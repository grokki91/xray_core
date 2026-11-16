// Пакет config — конфигурация Xray, производная от состояния (docs/architecture/components.md,
// config; ADR-0004). Одно состояние → побайтно один файл. Разделы: log (готовый раздел
// приносит вызывающий — от logging), dns (из состояния), inbounds (пресет и клиенты), outbounds,
// routing с запретом частных, петлевых и link-local адресов назначения (docs/security/policy.md
// §4). Проверку `xray run -test` выполняет вызывающий через core.Validate: менеджеры друг друга
// не импортируют.
package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/grokki91/xray_core/internal/config/preset"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/store"
)

// Path — файл конфигурации Xray (docs/architecture/data-model.md §1): root:xray, 0640.
const Path = "/usr/local/etc/xray/config.json"

// ErrState — состояние не позволяет построить конфигурацию.
var ErrState = errors.New("состояние не позволяет построить конфигурацию")

// Rendered — отрисованная конфигурация и её SHA-256 (hex): значение для applied.config_sha256.
type Rendered struct {
	Data   []byte
	SHA256 string
}

// Manager — отрисовка, запись и сверка конфигурации.
type Manager struct{ p platform.Platform }

// New создаёт менеджер поверх platform.
func New(p platform.Platform) *Manager { return &Manager{p: p} }

// Render строит конфигурацию из состояния. logSection — раздел log от logging
// (logging.Manager.XraySection). Профили с enabled=false в клиентов не попадают. В MVP входящий
// ровно один (docs/architecture/data-model.md §2).
func (m *Manager) Render(st store.State, logSection json.RawMessage) (Rendered, error) {
	if len(st.Inbounds) != 1 {
		return Rendered{}, fmt.Errorf("%w: входящих %d, нужен один", ErrState, len(st.Inbounds))
	}
	in := st.Inbounds[0]
	pr, err := preset.Get(in.Preset)
	if err != nil {
		return Rendered{}, fmt.Errorf("%w: %w", ErrState, err)
	}
	var ids []string
	for _, pf := range st.Profiles {
		if pf.Enabled {
			ids = append(ids, pf.ID)
		}
	}
	inbound, err := pr.Inbound(preset.Params{
		Port:        st.Server.Port,
		Target:      in.Reality.Target,
		ServerNames: in.Reality.ServerNames,
		PrivateKey:  in.Reality.PrivateKey,
		ShortIDs:    in.Reality.ShortIDs,
		ClientIDs:   ids,
		Options:     in.Params,
	})
	if err != nil {
		return Rendered{}, fmt.Errorf("%w: %w", ErrState, err)
	}
	if !json.Valid(logSection) {
		return Rendered{}, fmt.Errorf("%w: раздел log не JSON", ErrState)
	}
	doc := document{
		Log:      logSection,
		DNS:      dnsSection(st.DNS),
		Inbounds: []json.RawMessage{inbound},
		Outbounds: []outbound{
			{Tag: tagDirect, Protocol: "freedom"},
			{Tag: tagBlock, Protocol: "blackhole"},
		},
		Routing: routing{
			DomainStrategy: "IPOnDemand",
			Rules:          []rule{{Type: "field", IP: deniedCIDRs, OutboundTag: tagBlock}},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return Rendered{}, fmt.Errorf("конфигурация: %w", err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return Rendered{}, fmt.Errorf("конфигурация: %w", err)
	}
	out.WriteByte('\n')
	sum := sha256.Sum256(out.Bytes())
	return Rendered{Data: out.Bytes(), SHA256: hex.EncodeToString(sum[:])}, nil
}

// Write атомарно пишет конфигурацию в Path: root:xray, 0640. Группу берёт у пользователя xray:
// Users.Ensure создаст его, если базовая защита (security.EnsureBaseline) ещё не выполнялась.
func (m *Manager) Write(ctx context.Context, r Rendered) error {
	svc, err := m.p.Users().Ensure(ctx, platform.ServiceUser)
	if err != nil {
		return fmt.Errorf("конфигурация: %w", err)
	}
	owner := platform.Owner{UID: 0, GID: svc.GID}
	if err := m.p.FS().WriteFile(Path, r.Data, 0o640, owner); err != nil {
		return fmt.Errorf("конфигурация: запись: %w", err)
	}
	return nil
}

// Drift сообщает, отличается ли файл на диске от последнего применённого (st.Applied). Нет
// файла и нет применённой суммы — дрейфа нет; файл есть, а суммы нет, или суммы различаются —
// дрейф.
func (m *Manager) Drift(st store.State) (bool, error) {
	b, err := m.p.FS().ReadFile(Path)
	var got string
	switch {
	case errors.Is(err, platform.ErrNotFound):
	case err != nil:
		return false, fmt.Errorf("конфигурация: чтение: %w", err)
	default:
		sum := sha256.Sum256(b)
		got = hex.EncodeToString(sum[:])
	}
	return got != st.Applied.ConfigSHA256, nil
}

const (
	tagDirect = "direct"
	tagBlock  = "block"
)

// deniedCIDRs — адреса назначения, которые клиент VPN не должен достать через тоннель:
// частные, петлевые, link-local и «этот хост» (0.0.0.0 на Linux ведёт на сам сервер).
var deniedCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"::/128", "::1/128", "fc00::/7", "fe80::/10",
}

// Порядок полей — порядок в файле.
type document struct {
	Log       json.RawMessage   `json:"log"`
	DNS       *dns              `json:"dns,omitempty"`
	Inbounds  []json.RawMessage `json:"inbounds"`
	Outbounds []outbound        `json:"outbounds"`
	Routing   routing           `json:"routing"`
}

type dns struct {
	Servers       []string `json:"servers"`
	QueryStrategy string   `json:"queryStrategy,omitempty"`
}

// dnsSection — раздел dns из состояния; пока DoH не задан (до фазы 4), раздела нет.
func dnsSection(d store.DNS) *dns {
	if len(d.DoH) == 0 {
		return nil
	}
	return &dns{Servers: d.DoH, QueryStrategy: d.Strategy}
}

type outbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
}

type routing struct {
	DomainStrategy string `json:"domainStrategy"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	Type        string   `json:"type"`
	IP          []string `json:"ip"`
	OutboundTag string   `json:"outboundTag"`
}
