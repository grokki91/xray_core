package diag

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// Families — семейства адресов (platform.Families): app называет тип, не импортируя platform.
type Families = platform.Families

// LocalDeps — измерения каталога точки наблюдения local (фаза 5): набор control и проверки
// категории xray, которых контролю транзакции не нужно.
type LocalDeps struct {
	ControlDeps
	// Version — версия установленного Xray; "" без ошибки — Xray не установлен.
	Version func(ctx context.Context) (string, error)
	// InRange — входит ли версия в проверенный диапазон этой версии xm (update.Verified).
	InRange func(version string) bool
	// Drift — отличается ли конфигурация на диске от отрисованной из состояния.
	Drift func(ctx context.Context) (bool, error)
	// Families — на каких семействах слушается порт.
	Families interface {
		ListeningFamilies(ctx context.Context, port int) (platform.Families, error)
	}
	// Served — семейства адресов сервера из состояния: на них клиенты подключаются.
	Served func(ctx context.Context) (Families, error)
	// Firewall — пропускает ли локальный фаервол порт: FirewallAllowed, FirewallDenied или
	// FirewallUnknown и откуда взято (ufw, iptables). Фаервол хостера с сервера не виден.
	Firewall func(ctx context.Context, port int) (state, source string, err error)
	// Egress — исходящие соединения и адреса интерфейсов.
	Egress interface {
		Addrs(ctx context.Context) ([]platform.IfAddr, error)
		Connect(ctx context.Context, addr netip.AddrPort) error
	}
}

// SetLocal — каталог MVP с самого сервера (docs/operations/diagnostics.md §4).
const SetLocal = "local"

// Идентификаторы проверок каталога сверх набора control.
const (
	CheckInstalled    = "xray.installed"
	CheckVersionRange = "xray.version.range"
	CheckRestarts     = "xray.service.restarts"
	CheckConfigDrift  = "xray.config.drift"
	CheckListenIPv4   = "reach.listen.ipv4"
	CheckListenIPv6   = "reach.listen.ipv6"
	CheckFirewall     = "reach.firewall"
	CheckEgressIPv4   = "ipv4.egress"
	CheckEgressIPv6   = "ipv6.egress"
)

// Состояния порта в локальном фаерволе (как network.FirewallState).
const (
	FirewallAllowed = "allowed"
	FirewallDenied  = "denied"
	FirewallUnknown = "unknown"
)

// Контрольные узлы исходящей связности (docs/dev/dependencies.md §5; 2026-11-27, ответ
// владельца): TCP 443 к первому узлу семейства, при неудаче — ко второму, другому оператору.
var egressNodes = map[bool][]netip.AddrPort{
	false: {netip.MustParseAddrPort("1.1.1.1:443"), netip.MustParseAddrPort("9.9.9.9:443")},
	true:  {netip.MustParseAddrPort("[2606:4700:4700::1111]:443"), netip.MustParseAddrPort("[2620:fe::fe]:443")},
}

// egressTimeout — срок одного соединения: два узла на семейство укладываются в бюджет прогона §5.
const egressTimeout = 5 * time.Second

// NewLocal собирает движок с наборами control (без самопроверки: она только в контроле
// изменения, ADR-0033) и local — весь каталог MVP.
func NewLocal(d LocalDeps) (*Engine, error) {
	if d.Selftest != nil {
		return nil, fmt.Errorf("%w: самопроверка не входит в каталог local", ErrRegistry)
	}
	if d.Service == nil || d.Net == nil || d.Port == nil || d.Validate == nil ||
		d.Version == nil || d.InRange == nil || d.Drift == nil ||
		d.Families == nil || d.Served == nil || d.Egress == nil || d.Firewall == nil {
		return nil, fmt.Errorf("%w: не все измерения каталога local заданы", ErrRegistry)
	}
	c := d.ControlDeps
	checks := []Check{installed{d}, versionRange{d}, serviceActive{c}, restarts{c}, listen{c}, listenFamily{d, false}, listenFamily{d, true}, firewall{d},
		configValid{c}, configDrift{d}, egress{d, false}, egress{d, true}}
	ids := make([]string, len(checks))
	for i, ch := range checks {
		ids[i] = ch.ID()
	}
	return New(checks, map[string][]string{
		SetControl: {CheckServiceActive, CheckListen, CheckConfigValid},
		SetLocal:   ids,
	}, nil)
}

type installed struct{ d LocalDeps }

func (installed) ID() string         { return CheckInstalled }
func (installed) Requires() []string { return nil }

func (c installed) Run(ctx context.Context) []Observation {
	v, err := c.d.Version(ctx)
	if err != nil {
		return errObs("xray.binary", "не удалось определить версию Xray")
	}
	return obs("xray.binary", v != "", v, "версия — по бинарнику на диске; исправность запуска этим не доказана")
}

func (installed) Fact(Observation) Finding {
	return Finding{Code: "xray.installed.missing", Title: "Xray не установлен", Impact: ImpactDown,
		Actions: []string{"xm update — поставить проверенную версию; xm restore <id> — вернуть снимок"}}
}

type versionRange struct{ d LocalDeps }

func (versionRange) ID() string         { return CheckVersionRange }
func (versionRange) Requires() []string { return []string{CheckInstalled} }

func (c versionRange) Run(ctx context.Context) []Observation {
	v, err := c.d.Version(ctx)
	if err != nil || v == "" {
		return errObs("xray.binary", "не удалось определить версию Xray")
	}
	return obs("xray.binary", c.d.InRange(v), v,
		"вне диапазона — не проверено этой версией xm, а не заведомо неисправно")
}

func (versionRange) Fact(Observation) Finding {
	return Finding{Code: "xray.version.unverified", Title: "версия Xray вне проверенного диапазона xm", Impact: ImpactDegraded,
		Actions: []string{"xm update --check; xm update — перейти на проверенную версию"}}
}

type restarts struct{ d ControlDeps }

func (restarts) ID() string         { return CheckRestarts }
func (restarts) Requires() []string { return []string{CheckServiceActive} }

func (c restarts) Run(ctx context.Context) []Observation {
	st, err := c.d.Service.Status(ctx)
	if err != nil {
		return errObs("xray.service", "не удалось получить состояние службы")
	}
	return obs("xray.service", st.Restarts == 0, st.Restarts,
		"NRestarts считает авто-перезапуски с последнего ручного запуска: идёт ли цикл сейчас, один снимок не различает")
}

func (restarts) Fact(Observation) Finding {
	return Finding{Code: "xray.service.restarted", Title: "служба xray перезапускалась после сбоев", Impact: ImpactDegraded,
		Actions: []string{"xm logs --since 1h — причина падений"}}
}

type configDrift struct{ d LocalDeps }

func (configDrift) ID() string         { return CheckConfigDrift }
func (configDrift) Requires() []string { return nil }

func (c configDrift) Run(ctx context.Context) []Observation {
	drift, err := c.d.Drift(ctx)
	if err != nil {
		return errObs("xray.config", "не удалось сравнить конфигурацию с состоянием")
	}
	return obs("xray.config", !drift, drift,
		"сравнивается файл на диске; конфигурация, загруженная в работающий процесс, не читается")
}

func (configDrift) Fact(Observation) Finding {
	return Finding{Code: "xray.config.drift", Title: "конфигурация Xray правлена вне xm", Impact: ImpactDegraded,
		Actions: []string{"правки вручную не сохраняются: внести их через xm; вернуть конфигурацию — xm restore <id>"}}
}

func family(v6 bool) string {
	if v6 {
		return "IPv6"
	}
	return "IPv4"
}

type listenFamily struct {
	d  LocalDeps
	v6 bool
}

func (c listenFamily) ID() string {
	if c.v6 {
		return CheckListenIPv6
	}
	return CheckListenIPv4
}
func (listenFamily) Requires() []string { return []string{CheckListen} }

func (c listenFamily) Run(ctx context.Context) []Observation {
	target := "server.port." + map[bool]string{false: "ipv4", true: "ipv6"}[c.v6]
	served, err := c.d.Served(ctx)
	if err != nil {
		return errObs(target, "адреса сервера из состояния недоступны")
	}
	if !c.v6 && !served.IPv4 || c.v6 && !served.IPv6 {
		return []Observation{{Target: target, Status: StatusSkip, Reason: "у сервера в состоянии нет адреса " + family(c.v6)}}
	}
	port, err := c.d.Port(ctx)
	if err != nil || port <= 0 || port > 65535 {
		return errObs(target, "порт сервера из состояния недоступен")
	}
	fam, err := c.d.Families.ListeningFamilies(ctx, port)
	if err != nil {
		return errObs(target, "не удалось прочитать таблицы сокетов")
	}
	on := fam.IPv4
	if c.v6 {
		on = fam.IPv6
	}
	return obs(target, on, on,
		"сокет на :: считается слушающим оба семейства: флаг IPV6_V6ONLY таблицы сокетов не показывают",
		"сервер готов принимать; доступность извне этим не доказана")
}

func (c listenFamily) Fact(Observation) Finding {
	return Finding{Code: c.ID() + ".closed", Title: "порт сервера не слушается на " + family(c.v6), Impact: ImpactDegraded,
		Actions: []string{"ss -ltn; journalctl -u xray -n 50"}}
}

type egress struct {
	d  LocalDeps
	v6 bool
}

func (c egress) ID() string {
	if c.v6 {
		return CheckEgressIPv6
	}
	return CheckEgressIPv4
}
func (egress) Requires() []string { return nil }

// usable — адрес семейства, с которого возможен выход наружу: не петля и не link-local; для
// IPv6 — глобальный, для IPv4 подходит и частный (за NAT).
func usable(a netip.Addr, v6 bool) bool {
	if a.Is4() == v6 || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	return !v6 || a.IsGlobalUnicast() && !a.IsPrivate()
}

func (c egress) Run(ctx context.Context) []Observation {
	target := "egress." + map[bool]string{false: "ipv4", true: "ipv6"}[c.v6]
	addrs, err := c.d.Egress.Addrs(ctx)
	if err != nil {
		return errObs(target, "не удалось прочитать адреса интерфейсов")
	}
	has := false
	for _, a := range addrs {
		has = has || usable(a.Addr, c.v6)
	}
	if !has {
		return []Observation{{Target: target, Status: StatusSkip, Reason: "на интерфейсах нет адреса " + family(c.v6)}}
	}
	for _, node := range egressNodes[c.v6] {
		cctx, cancel := context.WithTimeout(ctx, egressTimeout)
		err := c.d.Egress.Connect(cctx, node)
		cancel()
		if err == nil {
			return obs(target, true, node.String(), egressLimits...)
		}
	}
	return obs(target, false, nil, egressLimits...)
}

var egressLimits = []string{
	"TCP до контрольных узлов на порт 443: доступность других адресов и портов не доказана",
	"исходящая связность не доказывает входящую",
}

func (c egress) Fact(Observation) Finding {
	f := Finding{Code: c.ID() + ".unreachable", Title: "нет исходящих соединений по " + family(c.v6), Impact: ImpactDegraded,
		Actions: []string{"ip route; проверить фаервол исходящего трафика и сеть провайдера"}}
	if !c.v6 {
		f.Impact = ImpactDown // без IPv4 наружу клиенты не достанут большую часть адресов
	}
	return f
}

type firewall struct{ d LocalDeps }

func (firewall) ID() string         { return CheckFirewall }
func (firewall) Requires() []string { return nil }

func (c firewall) Run(ctx context.Context) []Observation {
	port, err := c.d.Port(ctx)
	if err != nil || port <= 0 || port > 65535 {
		return errObs("firewall", "порт сервера из состояния недоступен")
	}
	state, source, err := c.d.Firewall(ctx, port)
	if err != nil {
		return errObs("firewall", "не удалось прочитать фаервол")
	}
	switch state {
	case FirewallAllowed, FirewallDenied:
		return obs("firewall", state == FirewallAllowed, map[string]string{"state": state, "source": source},
			"только локальный фаервол сервера: фаервол хостера и сети клиента с сервера не видны")
	case FirewallUnknown:
		// Причина из network не идёт в отчёт: в ней бывает текст ошибки утилиты.
		return []Observation{{Target: "firewall", Status: StatusSkip, Reason: "по правилам " + source + " не определено, пропускают ли они порт"}}
	}
	return errObs("firewall", "неизвестное состояние фаервола")
}

func (firewall) Fact(Observation) Finding {
	return Finding{Code: "reach.firewall.denied", Title: "локальный фаервол запрещает порт сервера", Impact: ImpactDown,
		Actions: []string{"ufw status verbose; разрешить порт: ufw allow <порт>/tcp"}}
}
