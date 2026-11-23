// Package network — сетевые факты хоста: адреса, внешний адрес, занятость порта, состояние
// локального фаервола. Только читает: ничего в сети и фаерволе не меняет (ADR-0036).
package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/grokki91/xray_core/internal/platform"
)

// Узлы определения внешнего адреса — закрытый список (docs/dev/dependencies.md §5). Запрос по
// адресу: семейство однозначно, DNS не нужен.
const (
	traceV4 = "https://1.1.1.1/cdn-cgi/trace"
	traceV6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
	hostV4  = "1.1.1.1"
	hostV6  = "[2606:4700:4700::1111]"
	// maxTrace — предел ответа trace: десяток коротких строк.
	maxTrace = 4 << 10
)

// cgnat — разделяемое пространство провайдера (RFC 6598): не частное по net/netip, но и не публичное.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Источник внешнего адреса.
const (
	SourceInterface = "interface" // публичный адрес на интерфейсе
	SourceTrace     = "trace"     // ответ узла из закрытого списка (хост за NAT)
	SourceFlag      = "flag"      // задан владельцем (--address)
)

// Request — что нужно знать о хосте. Address — переопределение внешнего адреса (--address):
// непустой — запросов к внешним узлам нет. Port — порт для состояния фаервола.
type Request struct {
	Address string
	Port    int
}

// Addr — адрес интерфейса и признак публичности.
type Addr struct {
	Iface  string
	Addr   netip.Addr
	Public bool
}

// External — внешний адрес одного семейства. Нулевой Addr — не определён; Note — почему.
type External struct {
	Addr   netip.Addr
	Source string
	Note   string
}

// Facts — сетевые факты: IPv4 и IPv6 раздельно.
type Facts struct {
	Addrs    []Addr
	V4, V6   External
	Firewall Firewall
}

// Manager читает сетевые факты через platform.
type Manager struct{ p platform.Platform }

// New — менеджер поверх платформы.
func New(p platform.Platform) *Manager { return &Manager{p: p} }

// Facts собирает адреса интерфейсов, внешний адрес каждого семейства и состояние фаервола для
// r.Port. Внешний адрес: --address, иначе публичный адрес интерфейса, иначе ответ trace.
// Неудача trace — не ошибка, а «не определён» с причиной: хост без IPv6 — обычное дело.
func (m *Manager) Facts(ctx context.Context, r Request) (Facts, error) {
	if err := checkPort(r.Port); err != nil {
		return Facts{}, err
	}
	var override netip.Addr
	if r.Address != "" {
		a, err := netip.ParseAddr(r.Address)
		if err != nil || a.Zone() != "" || !public(a.Unmap()) {
			return Facts{}, fmt.Errorf("адрес %q: нужен публичный IPv4 или IPv6", r.Address)
		}
		override = a.Unmap()
	}
	raw, err := m.p.Net().Addrs(ctx)
	if err != nil {
		return Facts{}, fmt.Errorf("адреса интерфейсов: %w", err)
	}
	var f Facts
	for _, a := range raw {
		f.Addrs = append(f.Addrs, Addr{Iface: a.Iface, Addr: a.Addr, Public: public(a.Addr)})
	}
	f.V4 = m.external(ctx, f.Addrs, override, true)
	f.V6 = m.external(ctx, f.Addrs, override, false)
	fw, err := m.firewall(ctx, r.Port)
	if err != nil {
		return Facts{}, err
	}
	f.Firewall = fw
	return f, nil
}

func (m *Manager) external(ctx context.Context, addrs []Addr, override netip.Addr, v4 bool) External {
	if override.IsValid() {
		if override.Is4() == v4 {
			return External{Addr: override, Source: SourceFlag}
		}
		return External{Note: "задан --address другого семейства; внешние узлы не опрашивались"}
	}
	for _, a := range addrs {
		if a.Public && a.Addr.Is4() == v4 {
			return External{Addr: a.Addr, Source: SourceInterface}
		}
	}
	url, host := traceV6, hostV6
	if v4 {
		url, host = traceV4, hostV4
	}
	body, err := m.p.Net().Get(ctx, platform.Request{URL: url, Hosts: []string{host}, Max: maxTrace})
	if err != nil {
		return External{Note: fmt.Sprintf("узел %s не ответил: %v", host, err)}
	}
	a, err := traceIP(body)
	if err != nil || a.Is4() != v4 || !public(a) {
		return External{Note: fmt.Sprintf("узел %s вернул негодный адрес", host)}
	}
	return External{Addr: a, Source: SourceTrace}
}

// traceIP — поле ip ответа /cdn-cgi/trace (строки ключ=значение).
func traceIP(body []byte) (netip.Addr, error) {
	for line := range strings.Lines(string(body)) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			a, err := netip.ParseAddr(v)
			if err != nil {
				return netip.Addr{}, err
			}
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, errors.New("нет поля ip")
}

// public — адрес, по которому хост может быть доступен из интернета: глобальный одноадресный,
// не частный, не CGNAT; петлевые и link-local не глобальны.
func public(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

func checkPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("порт %d вне 1–65535", port)
	}
	return nil
}
