package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/diag"
	"github.com/grokki91/xray_core/internal/dns"
	"github.com/grokki91/xray_core/internal/network"
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
	// ErrInstalled — xm уже установлен; транзакция установки отказывает под блокировкой, если
	// установку успела сделать параллельная команда. Код выхода 3.
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

// InstallOptions — параметры `xm install`; все необязательны (ADR-0035, ADR-0041): пустые SNI и
// Address определяются по сетевым фактам, нулевой Port — DefaultPort.
type InstallOptions struct {
	SNI     string // имя REALITY: домен цели, например example.com; пусто — выбор из закрытого списка
	Address string // внешний адрес сервера (IPv4, IPv6) или домен; пусто — определяется
	Port    int
}

// FirewallResult — что установка сделала с фаерволом и что известно о порте. Состояние — факт
// локального фаервола: фаервол хостера с сервера не виден (ADR-0036).
type FirewallResult struct {
	State  string `json:"state"`  // allowed, denied, unknown
	Source string `json:"source"` // ufw, iptables или пусто
	Note   string `json:"note"`
	Added  bool   `json:"added"` // правило UFW поставил xm в этой установке
	Open   string `json:"open"`  // команда, которую владелец выполняет сам; пусто — не нужна
}

// InstallResult — итог установки; секретов в нём нет. Ссылки профиля — ProfileShow.
type InstallResult struct {
	Xray     string          `json:"xray"`
	Address  string          `json:"address"` // первый из «домен, IPv4, IPv6»; остальные — в ссылках профиля
	Port     int             `json:"port"`
	Profile  string          `json:"profile"`  // имя первого профиля; пусто — профилей нет
	Existing bool            `json:"existing"` // установка уже была: ничего не изменено
	Firewall FirewallResult  `json:"firewall"`
	Health   contract.Health `json:"health"`
}

// Releases — источник релизов Xray; настоящий — update.GitHub.
type Releases interface {
	Latest(ctx context.Context) (update.Release, error)
	Fetch(ctx context.Context, r update.Release, a update.Arch) (update.Archive, error)
}

var (
	domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// installInput — проверенный ввод: адрес разложен на внешний IP для сетевых фактов и домен.
type installInput struct {
	sni     string
	ip      string // --address, если это IP: переопределение внешнего адреса
	domain  string // --address, если это домен
	port    int
	portSet bool // --port задан явно: сравнивается с установленным
}

// checkInstall проверяет ввод по закрытому правилу до любого обращения к системе и сети
// (docs/security/policy.md §5).
func checkInstall(o InstallOptions) (in installInput, err error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInput}, a...)...)
	}
	in.port, in.portSet = o.Port, o.Port != 0
	if in.port == 0 {
		in.port = DefaultPort
	}
	if in.port < 1 || in.port > 65535 {
		return in, bad("порт вне 1…65535")
	}
	if o.SNI != "" {
		in.sni = strings.ToLower(o.SNI)
		if len(in.sni) > 253 || !domainRe.MatchString(in.sni) {
			return in, bad("--sni: нужно доменное имя вида example.com")
		}
	}
	if o.Address == "" {
		return in, nil
	}
	if ip, perr := netip.ParseAddr(o.Address); perr == nil {
		switch {
		case ip.Zone() != "" || ip.Is4In6():
			return in, bad("--address: адрес с зоной и IPv4-в-IPv6 не поддерживаются")
		case ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast():
			return in, bad("--address: нужен адрес, по которому клиенты достанут сервер, а не служебный")
		}
		in.ip = ip.String()
		return in, nil
	}
	if d := strings.ToLower(o.Address); len(d) <= 253 && domainRe.MatchString(d) {
		in.domain = d
		return in, nil
	}
	return in, bad("--address: нужен IPv4, IPv6 или домен")
}

// Install ставит Xray на чистую машину: сетевые факты → цель REALITY → загрузка и проверка
// релиза → ядро → транзакция (базовая защита, состояние, конфигурация, юнит, правило UFW,
// запуск, контроль). Повторный запуск на установленной системе ничего не меняет и возвращает
// итог существующей установки.
func (a *App) Install(ctx context.Context, o InstallOptions) (InstallResult, error) {
	in, err := checkInstall(o)
	if err != nil {
		return InstallResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()

	if err := a.needRoot(); err != nil {
		return InstallResult{}, err
	}
	// Незавершённая транзакция откатывается до проверки: состояние, оставшееся от оборванной
	// установки, не должно выглядеть как готовая. Решающая проверка — в Apply, под блокировкой.
	if _, err := a.Recover(ctx); err != nil {
		return InstallResult{}, err
	}
	if st, ok, err := a.installed(); err != nil {
		return InstallResult{}, err
	} else if ok {
		return a.existing(ctx, st, in)
	}
	if _, issues := a.s.Server.Preflight(ctx); len(issues) > 0 {
		return InstallResult{}, &PreflightError{issues}
	}

	facts, err := a.s.Network.Facts(ctx, network.Request{Address: in.ip, Port: in.port})
	if err != nil {
		return InstallResult{}, fmt.Errorf("%w: %w", ErrInput, err)
	}
	addr := store.Addresses{Domain: in.domain}
	if facts.V4.Addr.IsValid() {
		addr.IPv4 = facts.V4.Addr.String()
	}
	if facts.V6.Addr.IsValid() {
		addr.IPv6 = facts.V6.Addr.String()
	}
	if addr == (store.Addresses{}) {
		return InstallResult{}, &PreflightError{[]server.Issue{{Code: "preflight.no_address",
			Message: "внешний адрес сервера не определён (IPv4: " + facts.V4.Note + "; IPv6: " + facts.V6.Note + "): задайте --address"}}}
	}
	free, holder, err := a.s.Network.PortFree(ctx, in.port)
	if err != nil {
		return InstallResult{}, err
	}
	if !free {
		who := "процесс не определён"
		if holder.Name != "" {
			who = fmt.Sprintf("процесс %q, pid %d", holder.Name, holder.PID)
		}
		return InstallResult{}, &PreflightError{[]server.Issue{{Code: "preflight.port_busy",
			Message: fmt.Sprintf("порт %d занят (%s): освободите его или задайте другой --port", in.port, who)}}}
	}
	target, err := a.s.Network.SelectTarget(ctx, in.sni)
	if err != nil {
		return InstallResult{}, err
	}
	sni := target.Host

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
		SchemaVersion: store.SchemaVersion,
		Server:        store.Server{Addresses: addr, Port: in.port},
		Inbounds: []store.Inbound{{
			Preset: presetID,
			Reality: store.Reality{
				Target: fmt.Sprintf("%s:%d", sni, targetPort), ServerNames: []string{sni},
				PrivateKey: keys.Private, PublicKey: keys.Public, ShortIDs: []string{shortID},
			},
			Params: map[string]string{},
		}},
		Profiles: []store.Profile{},
		DNS:      dns.Plan(dns.NetFacts{IPv4: addr.IPv4 != "", IPv6: addr.IPv6 != ""}),
		Core:     store.Core{Version: string(version)},
		// Правило UFW ставится только при активном UFW и порте, закрытом его политикой (ADR-0041).
		Firewall: store.Firewall{UFWRule: facts.Firewall.CanAllow},
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
	ch := Change{Reason: "install", State: st, Unit: &spec, Core: version, Create: true}
	if st.Firewall.UFWRule {
		ch.UFWPort = in.port
	}
	if err := a.Apply(ctx, ch); err != nil {
		return InstallResult{}, err
	}
	h, err := a.health(ctx, in.port)
	if err != nil {
		return InstallResult{}, err
	}
	return InstallResult{Xray: string(version), Address: firstAddress(addr), Port: in.port, Profile: first.Name,
		Firewall: firewallResult(facts.Firewall, in.port, st.Firewall.UFWRule), Health: h}, nil
}

// existing — повторный запуск на установленной системе: ничего не меняет. Параметры, которых в
// установке нет, — ошибка ввода: install не меняет установленное.
func (a *App) existing(ctx context.Context, st store.State, in installInput) (InstallResult, error) {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format+"; установленное install не меняет", append([]any{ErrInput}, args...)...)
	}
	ad := st.Server.Addresses
	switch {
	case in.sni != "" && !slices.Contains(st.Inbounds[0].Reality.ServerNames, in.sni):
		return InstallResult{}, bad("--sni отличается от установленного")
	case in.portSet && in.port != st.Server.Port:
		return InstallResult{}, bad("--port отличается от установленного")
	case in.ip != "" && in.ip != ad.IPv4 && in.ip != ad.IPv6:
		return InstallResult{}, bad("--address отличается от установленных адресов")
	case in.domain != "" && in.domain != ad.Domain:
		return InstallResult{}, bad("--address отличается от установленного домена")
	}
	xray, err := a.s.Core.Current(ctx)
	if err != nil {
		return InstallResult{}, err
	}
	h, err := a.health(ctx, st.Server.Port)
	if err != nil {
		return InstallResult{}, err
	}
	res := InstallResult{Xray: string(xray), Address: firstAddress(ad), Port: st.Server.Port, Existing: true, Health: h}
	if len(st.Profiles) > 0 {
		res.Profile = st.Profiles[0].Name
	}
	return res, nil
}

// firstAddress — первый из порядка «домен, IPv4, IPv6» (так же выбирается адрес QR).
func firstAddress(a store.Addresses) string {
	for _, v := range []string{a.Domain, a.IPv4, a.IPv6} {
		if v != "" {
			return v
		}
	}
	return ""
}

// firewallResult — факт о порте и, когда xm ничего не сделал, а порт может быть закрыт
// правилами iptables, команда, которую владелец выполняет сам (ADR-0036). Вывод о фаерволе
// хостера не делается: он с сервера не виден.
func firewallResult(f network.Firewall, port int, added bool) FirewallResult {
	r := FirewallResult{State: string(f.State), Source: f.Source, Note: f.Note, Added: added}
	if !added && f.State != network.FirewallAllowed && f.Source == "iptables" {
		r.Open = fmt.Sprintf("iptables -I INPUT -p tcp --dport %d -j ACCEPT; ip6tables -I INPUT -p tcp --dport %d -j ACCEPT", port, port)
	}
	return r
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
	h, err := a.health(ctx, st.Server.Port)
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
		Health:    h,
	}, nil
}

// unchecked — что вердикт ok не измеряет: набор control смотрит с самого сервера и без самопроверки (ADR-0024, ADR-0033).
const unchecked = "подключение клиента не проверялось: самопроверка выполняется только при изменении, доступность порта снаружи и из сети клиента не проверена"

// health — вердикт по набору control: вердикт, первопричина и действие; при ok — что не проверено.
func (a *App) health(ctx context.Context, port int) (contract.Health, error) {
	r, err := a.controlReport(ctx, port, false)
	if err != nil {
		return contract.Health{}, err
	}
	h := contract.Health{Verdict: string(r.Health)}
	if r.Health == diag.HealthOK {
		h.Unchecked = unchecked
		return h, nil
	}
	if f := r.Cause(); f != nil {
		h.Cause, h.Action = f.Title, strings.Join(f.Actions, "; ")
		return h, nil
	}
	// unknown: проверка набора не измерила — называем первую такую.
	for _, o := range r.Observations {
		if o.Status == diag.StatusSkip || o.Status == diag.StatusError {
			h.Cause = fmt.Sprintf("проверка %s не измерила: %s", o.Check, o.Reason)
			h.Action = "повторите xm status; если повторяется — xm restart"
			break
		}
	}
	return h, nil
}

// needRoot — состояние и systemd доступны только root.
func (a *App) needRoot() error {
	if issue, bad := a.s.Server.CheckRoot(); bad {
		return &PreflightError{[]server.Issue{issue}}
	}
	return nil
}
