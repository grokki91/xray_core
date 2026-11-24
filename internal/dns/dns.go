// Package dns — раздел dns конфигурации Xray: DoH-серверы и стратегия семейств адресов по
// сетевым фактам (docs/architecture/components.md, dns). Системный резолвер не меняет.
package dns

import "github.com/grokki91/xray_core/internal/store"

// Серверы DoH — закрытый список (docs/dev/dependencies.md §5). Схема https:// — запрос идёт
// через маршрутизацию и исходящий freedom, поэтому его finalRules (ADR-0027) действуют и на
// DoH; https+local:// шёл бы системным dialer мимо маршрутизации.
var servers = []string{"https://1.1.1.1/dns-query", "https://dns.quad9.net/dns-query"}

// Значения queryStrategy Xray.
const (
	UseIP   = "UseIP"
	UseIPv4 = "UseIPv4"
	UseIPv6 = "UseIPv6"
)

// NetFacts — есть ли у сервера внешний адрес каждого семейства. Заполняет вызывающий из
// network.Facts: менеджеры друг друга не импортируют.
type NetFacts struct {
	IPv4, IPv6 bool
}

// Plan строит state.dns: с обоими семействами — UseIP, только IPv6 — UseIPv6, без внешнего
// IPv6 — UseIPv4.
func Plan(n NetFacts) store.DNS {
	strategy := UseIPv4
	switch {
	case n.IPv4 && n.IPv6:
		strategy = UseIP
	case n.IPv6:
		strategy = UseIPv6
	}
	return store.DNS{DoH: append([]string(nil), servers...), Strategy: strategy}
}
