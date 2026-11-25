// Пакет config — конфигурация Xray, производная от состояния (docs/architecture/components.md,
// config; ADR-0004). Одно состояние → побайтно один файл. Разделы: log (готовый раздел
// приносит вызывающий — от logging), dns (из состояния), inbounds (пресет и клиенты), outbounds,
// исходящий freedom с запретом частных, петлевых и link-local адресов назначения и порта 25 в
// finalRules (docs/security/policy.md §4, ADR-0027, ADR-0038), blackhole для BitTorrent. Проверку `xray run -test` выполняет вызывающий через core.Validate: менеджеры друг друга
// не импортируют.
package config

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

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
	// Служебный клиент самопроверки — последним: он не профиль, но входит в clients сервера
	// (ADR-0032); пустой id — клиента ещё нет.
	if st.Selftest.ID != "" {
		ids = append(ids, st.Selftest.ID)
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
		// freedom — первым: первый исходящий получает всё, что не поймали правила routing.
		// Порт 25 любого адреса — тем же механизмом, что частные адреса: хостеры блокируют VPS за
		// рассылку почты (ADR-0038). BitTorrent — правилом protocol: finalRules не видят результат
		// определения протокола; blackhole — только для этого правила.
		Outbounds: []outbound{{
			Tag: tagDirect, Protocol: "freedom",
			Settings: freedomSettings{FinalRules: []finalRule{
				{Action: "block", Network: "tcp", Port: "25"},
				{Action: "block", IP: deniedCIDRs},
			}},
		}, {Tag: tagBlock, Protocol: "blackhole", Settings: struct{}{}}},
		Routing: &routing{Rules: []rule{{Protocol: []string{"bittorrent"}, OutboundTag: tagBlock}}},
	}
	// Встроенный DNS сам :53 не перехватывает: запросы клиентов внутри тоннеля к нему ведёт
	// исходящий dns и правило routing. DoH самого Xray (схема https://) идёт через freedom, и
	// его finalRules действуют на DoH-трафик (ADR-0027).
	if doc.DNS != nil {
		// Правила явные, не умолчание upstream: A и AAAA — встроенному DNS, остальное — REFUSED;
		// на исходный адрес запроса ничего не уходит.
		doc.Outbounds = append(doc.Outbounds, outbound{Tag: tagDNS, Protocol: "dns", Settings: dnsOutSettings{
			Rules: []dnsRule{{Action: "hijack", QType: "1,28"}, {Action: "return", RCode: 5}},
		}})
		doc.Routing.Rules = append(doc.Routing.Rules, rule{Port: "53", Network: "tcp,udp", OutboundTag: tagDNS})
	}
	return finish(doc)
}

// RenderClient строит конфигурацию клиента самопроверки из состояния — тот же источник, что у
// ссылки профиля (ADR-0032): входящий — HTTP на сокете Unix по пути socket (права 0600), исходящий —
// VLESS к серверу с этим пресетом. Адрес сервера — первый из порядка «домен, IPv4, IPv6», как у
// ссылки по умолчанию. Разборщика ссылок нет: параметры берутся из состояния.
func (m *Manager) RenderClient(st store.State, id, socket string) (Rendered, error) {
	if len(st.Inbounds) != 1 {
		return Rendered{}, fmt.Errorf("%w: входящих %d, нужен один", ErrState, len(st.Inbounds))
	}
	in := st.Inbounds[0]
	pr, err := preset.Get(in.Preset)
	if err != nil {
		return Rendered{}, fmt.Errorf("%w: %w", ErrState, err)
	}
	// Запятая в пути отделила бы суффикс прав: «путь,0600» — единственная форма.
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || strings.ContainsAny(socket, ",@\x00") {
		return Rendered{}, fmt.Errorf("%w: сокет клиента: нужен абсолютный очищенный путь", ErrState)
	}
	if len(in.Reality.ServerNames) == 0 || len(in.Reality.ShortIDs) == 0 {
		return Rendered{}, fmt.Errorf("%w: во входящем нет имён или shortId", ErrState)
	}
	host := cmp.Or(st.Server.Addresses.Domain, st.Server.Addresses.IPv4, st.Server.Addresses.IPv6)
	out, err := pr.Outbound(preset.ClientParams{
		Host: host, Port: st.Server.Port, ID: id, SNI: in.Reality.ServerNames[0],
		PublicKey: in.Reality.PublicKey, ShortID: in.Reality.ShortIDs[0], Options: in.Params,
	})
	if err != nil {
		return Rendered{}, fmt.Errorf("%w: %w", ErrState, err)
	}
	inbound, err := json.Marshal(httpInbound{Tag: "in-selftest", Listen: socket + ",0600", Protocol: "http", Settings: struct{}{}})
	if err != nil {
		return Rendered{}, fmt.Errorf("конфигурация клиента: %w", err)
	}
	return finish(clientDocument{
		Log:       json.RawMessage(`{"loglevel":"none"}`),
		Inbounds:  []json.RawMessage{inbound},
		Outbounds: []json.RawMessage{out},
	})
}

// finish — единый вид файла: отступ в два пробела и перевод строки в конце; SHA-256 — по нему.
func finish(doc any) (Rendered, error) {
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

type clientDocument struct {
	Log       json.RawMessage   `json:"log"`
	Inbounds  []json.RawMessage `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
}

// httpInbound — входящий клиента: слушает только сокет Unix, порта нет.
type httpInbound struct {
	Tag      string   `json:"tag"`
	Listen   string   `json:"listen"`
	Protocol string   `json:"protocol"`
	Settings struct{} `json:"settings"`
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
// частные, петлевые, link-local и «этот хост» (0.0.0.0 на Linux ведёт на сам сервер). Запрет —
// finalRules исходящего freedom (ADR-0027): правило проверяет адрес, на который действительно
// идёт соединение, после разрешения имени. Встроенный запрет частных адресов в freedom
// (docs/compatibility.md §2) не заменяет его: поведение upstream по умолчанию может измениться.
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
	Routing   *routing          `json:"routing,omitempty"`
}

const tagDNS = "dns-out"

type routing struct {
	Rules []rule `json:"rules"`
}

type rule struct {
	Protocol    []string `json:"protocol,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	OutboundTag string   `json:"outboundTag"`
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
	Settings any    `json:"settings"` // freedomSettings, dnsOutSettings или пустой объект blackhole
}

type dnsOutSettings struct {
	Rules []dnsRule `json:"rules"`
}

type dnsRule struct {
	Action string `json:"action"`
	QType  string `json:"qType,omitempty"`
	RCode  int    `json:"rCode,omitempty"`
}

type freedomSettings struct {
	FinalRules []finalRule `json:"finalRules"`
}

type finalRule struct {
	Action  string   `json:"action"`
	Network string   `json:"network,omitempty"`
	Port    string   `json:"port,omitempty"`
	IP      []string `json:"ip,omitempty"`
}

// CandidatePath — временный файл новой конфигурации для `xray run -test`: до атомарной записи в
// Path (ADR-0005, шаг 3–4). Секреты внутри — поэтому каталог транзакций и права 0600.
const CandidatePath = "/var/lib/xm/tx/config.candidate.json"

// Stage записывает кандидата и возвращает его путь для core.Validate. Убирает его Unstage.
func (m *Manager) Stage(r Rendered) (string, error) {
	if err := m.p.FS().WriteFile(CandidatePath, r.Data, 0o600, platform.Root()); err != nil {
		return "", fmt.Errorf("конфигурация: кандидат: %w", err)
	}
	return CandidatePath, nil
}

// Unstage удаляет кандидата; его отсутствие — не ошибка.
func (m *Manager) Unstage() error { return m.removeIfAny(CandidatePath) }

// Remove удаляет config.json: откат установки, которой не было (в снимке файла нет).
func (m *Manager) Remove() error { return m.removeIfAny(Path) }

func (m *Manager) removeIfAny(path string) error {
	if err := m.p.FS().Remove(path); err != nil && !errors.Is(err, platform.ErrNotFound) {
		return fmt.Errorf("конфигурация: удаление %s: %w", path, err)
	}
	return nil
}
