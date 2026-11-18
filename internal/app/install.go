package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/server"
	"github.com/grokki91/xray_core/internal/store"
	"github.com/grokki91/xray_core/internal/update"
)

// Пресет и порт REALITY-цели по умолчанию до фазы 4 (Q3: автоматический выбор цели).
const (
	presetID = "reality-xhttp"
	// DefaultPort — порт сервера, если владелец не назвал другой.
	DefaultPort = 443
	targetPort  = 443
)

// Сроки команд: app задаёт их сам, адаптеры контекст со сроком не создают.
const (
	installTimeout = 15 * time.Minute
	serviceTimeout = 2 * time.Minute
	statusTimeout  = 30 * time.Second
)

var (
	// ErrInput — неверные параметры команды. Код выхода 2.
	ErrInput = errors.New("неверные параметры")
	// ErrPreflight — предусловия не выполнены (подробности — PreflightError). Код выхода 3.
	ErrPreflight = errors.New("предусловия не выполнены")
	// ErrInstalled — xm уже установлен: повторная установка — фаза 4. Код выхода 3.
	ErrInstalled = errors.New("xm уже установлен")
	// ErrNotInstalled — команде нужна установка. Код выхода 3.
	ErrNotInstalled = errors.New("xm не установлен")
)

// PreflightError — все найденные невыполненные предусловия сразу.
type PreflightError struct{ Issues []server.Issue }

func (e *PreflightError) Error() string {
	msgs := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		msgs[i] = is.Message
	}
	return ErrPreflight.Error() + ": " + strings.Join(msgs, "; ")
}

// Is связывает ошибку с ErrPreflight.
func (e *PreflightError) Is(target error) bool { return target == ErrPreflight }

// Action — действие над службой.
type Action string

// Действия над службой xray.service.
const (
	Start   Action = "start"
	Stop    Action = "stop"
	Restart Action = "restart"
)

// InstallOptions — параметры `xm install` (в фазе 2 заданы явно; автоматический выбор — фаза 4).
type InstallOptions struct {
	SNI     string // имя REALITY: домен цели, например example.com
	Address string // адрес сервера для клиентов: IPv4, IPv6 или домен
	Port    int
}

// InstallResult — итог установки; секретов в нём нет. Ссылки первого профиля — ProfileShow.
type InstallResult struct {
	Xray    string `json:"xray"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Profile string `json:"profile"` // имя первого профиля
}

// Releases — источник релизов Xray; настоящий — update.GitHub.
type Releases interface {
	Latest(ctx context.Context) (update.Release, error)
	Fetch(ctx context.Context, r update.Release, a update.Arch) (update.Archive, error)
}

var (
	domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// checkInstall проверяет ввод по закрытому правилу до любого обращения к системе и сети
// (docs/security/policy.md §5) и раскладывает адрес по полям состояния.
func checkInstall(o InstallOptions) (sni string, addr store.Addresses, err error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInput}, a...)...)
	}
	sni = strings.ToLower(o.SNI)
	switch {
	case o.SNI == "":
		return "", addr, bad("нужен --sni: домен цели REALITY, например example.com")
	case o.Address == "":
		return "", addr, bad("нужен --address: адрес сервера для клиентов (IP или домен)")
	case o.Port < 1 || o.Port > 65535:
		return "", addr, bad("порт вне 1…65535")
	case len(sni) > 253 || !domainRe.MatchString(sni):
		return "", addr, bad("--sni: нужно доменное имя вида example.com")
	}
	if ip, perr := netip.ParseAddr(o.Address); perr == nil {
		switch {
		case ip.Zone() != "" || ip.Is4In6():
			return "", addr, bad("--address: адрес с зоной и IPv4-в-IPv6 не поддерживаются")
		case ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast():
			return "", addr, bad("--address: нужен адрес, по которому клиенты достанут сервер, а не служебный")
		case ip.Is4():
			addr.IPv4 = ip.String()
		default:
			addr.IPv6 = ip.String()
		}
		return sni, addr, nil
	}
	if d := strings.ToLower(o.Address); len(d) <= 253 && domainRe.MatchString(d) {
		addr.Domain = d
		return sni, addr, nil
	}
	return "", addr, bad("--address: нужен IPv4, IPv6 или домен")
}

// Install ставит Xray на чистую машину: предусловия → загрузка и проверка релиза → ядро →
// транзакция (базовая защита, состояние, конфигурация, юнит, запуск, контроль). Повторная
// установка и автоматический выбор параметров — фаза 4.
func (a *App) Install(ctx context.Context, o InstallOptions) (InstallResult, error) {
	sni, addr, err := checkInstall(o)
	if err != nil {
		return InstallResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()

	if _, issues := a.s.Server.Preflight(ctx); len(issues) > 0 {
		return InstallResult{}, &PreflightError{issues}
	}
	// Незавершённая транзакция откатывается до проверки: состояние, оставшееся от оборванной
	// установки, не должно выглядеть как готовая. Решающая проверка — в Apply, под блокировкой.
	if _, err := a.Recover(ctx); err != nil {
		return InstallResult{}, err
	}
	if _, ok, err := a.installed(); err != nil {
		return InstallResult{}, err
	} else if ok {
		return InstallResult{}, ErrInstalled
	}

	rel, err := a.s.Releases.Latest(ctx)
	if err != nil {
		return InstallResult{}, err
	}
	version, err := core.ParseVersion(rel.Version())
	if err != nil {
		return InstallResult{}, err
	}
	arch, err := a.s.Releases.Fetch(ctx, rel, update.ArchAMD64)
	if err != nil {
		return InstallResult{}, err
	}
	// Версия, выложенная прошлой установкой из того же архива, повторно принимается; другое
	// содержимое под тем же номером — ErrStaged.
	if err := a.s.Core.Stage(ctx, version, arch.Data); err != nil {
		return InstallResult{}, err
	}

	keys, err := a.s.Security.NewRealityKeys(ctx)
	if err != nil {
		return InstallResult{}, err
	}
	shortID, err := a.s.Security.NewShortID()
	if err != nil {
		return InstallResult{}, err
	}
	clientID, err := a.s.Security.NewClientID()
	if err != nil {
		return InstallResult{}, err
	}
	a.s.Redactor.Register("uuid", clientID)
	st := store.State{
		SchemaVersion: 1,
		Server:        store.Server{Addresses: addr, Port: o.Port},
		Inbounds: []store.Inbound{{
			Preset: presetID,
			Reality: store.Reality{
				Target: fmt.Sprintf("%s:%d", sni, targetPort), ServerNames: []string{sni},
				PrivateKey: keys.Private, PublicKey: keys.Public, ShortIDs: []string{shortID},
			},
			Params: map[string]string{},
		}},
		Profiles: []store.Profile{},
		Core:     store.Core{Version: string(version)},
	}
	// Первый профиль создаётся в той же транзакции: установка завершается рабочей ссылкой.
	st, first, err := a.s.Profile.Add(st, a.s.Profile.NextName(st), clientID, a.s.Now())
	if err != nil {
		return InstallResult{}, err
	}
	var spec server.UnitSpec
	for _, o := range a.s.Security.UnitHardening() {
		spec.Hardening = append(spec.Hardening, server.UnitOption{Key: o.Key, Value: o.Value})
	}
	if err := a.Apply(ctx, Change{Reason: "install", State: st, Unit: &spec, Core: version, Create: true}); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{Xray: string(version), Address: o.Address, Port: o.Port, Profile: first.Name}, nil
}

// installed читает состояние: есть ли установка.
func (a *App) installed() (store.State, bool, error) {
	st, had, err := a.loadPrev()
	return st, had, err
}

// Service выполняет start, stop или restart. Это не транзакция: состояние не меняется, провал
// контроля — ошибка, а не откат (ADR-0023). Незавершённая транзакция откатывается раньше.
func (a *App) Service(ctx context.Context, act Action) error {
	if act != Start && act != Stop && act != Restart {
		return fmt.Errorf("%w: действие %q", ErrInput, string(act))
	}
	ctx, cancel := context.WithTimeout(ctx, serviceTimeout)
	defer cancel()
	if err := a.needRoot(); err != nil {
		return err
	}
	unlock, err := a.s.Store.Lock(ctx)
	if err != nil {
		return fmt.Errorf("блокировка: %w", err)
	}
	defer unlock()
	if _, err := a.recover(ctx); err != nil {
		return err
	}
	st, ok, err := a.installed()
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotInstalled
	}
	svc := a.s.Server.Service()
	switch act {
	case Start:
		err = svc.Start(ctx)
	case Stop:
		err = svc.Stop(ctx)
	default:
		err = svc.Restart(ctx)
	}
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, a.s.ControlTimeout)
	defer cancel()
	if act == Stop {
		return svc.CheckStopped(cctx, st.Server.Port)
	}
	return svc.CheckRunning(cctx, st.Server.Port)
}

// Status — состояние установки. Не установлено — Installed=false, это не ошибка.
func (a *App) Status(ctx context.Context) (contract.Status, error) {
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	out := contract.Status{Versions: contract.Versions{XM: a.s.XM}}
	if err := a.needRoot(); err != nil {
		return out, err
	}
	st, ok, err := a.installed()
	if err != nil || !ok {
		return out, err
	}
	xray, err := a.s.Core.Current(ctx)
	if err != nil {
		return out, err
	}
	us, err := a.s.Server.Service().Status(ctx)
	if err != nil {
		return out, err
	}
	drift, err := a.s.Config.Drift(st)
	if err != nil {
		return out, err
	}
	a4 := st.Server.Addresses
	clients := []contract.ClientSupport{}
	for _, c := range a.s.Profile.Clients(st) {
		clients = append(clients, contract.ClientSupport{Name: c.Name, Works: c.Works, Condition: c.Condition, Reason: c.Reason})
	}
	return contract.Status{
		Installed: true,
		Service:   contract.ServiceState{Loaded: us.Loaded, Active: us.Active, Sub: us.Sub, Enabled: us.Enabled, Restarts: us.Restarts},
		Versions:  contract.Versions{XM: a.s.XM, Xray: string(xray)},
		Addresses: contract.ServerAddress{IPv4: a4.IPv4, IPv6: a4.IPv6, Domain: a4.Domain},
		Port:      st.Server.Port,
		Drift:     drift,
		Profiles:  len(st.Profiles),
		Clients:   clients,
	}, nil
}

// needRoot — состояние и systemd доступны только root.
func (a *App) needRoot() error {
	if issue, bad := a.s.Server.CheckRoot(); bad {
		return &PreflightError{[]server.Issue{issue}}
	}
	return nil
}
