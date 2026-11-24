package network

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// Candidates — закрытый список целей REALITY (ADR-0035; docs/compatibility.md,
// docs/dev/dependencies.md §5). Порядок решает выбор при равном времени рукопожатия. Функция,
// а не переменная: список не меняется во время работы.
func Candidates() []string {
	return []string{
		"www.microsoft.com", "www.apple.com", "www.cloudflare.com", "www.amazon.com", "www.samsung.com",
		"www.nvidia.com", "www.oracle.com", "www.mozilla.org", "www.intel.com",
	}
}

const (
	targetPort = 443
	// targetTimeout — срок одной проверки цели; selectTimeout — общий срок всех кандидатов
	// (проверяются параллельно).
	targetTimeout = 10 * time.Second
	selectTimeout = 15 * time.Second
)

// Критерии цели.
const (
	CheckTLS13    = "tls13"
	CheckH2       = "h2"
	CheckMLKEM    = "x25519mlkem768"
	CheckCert     = "certificate"
	CheckAddress  = "address"
	CheckRedirect = "redirect"
)

// Check — итог одного критерия; Reason — почему не прошёл.
type Check struct {
	Name   string
	OK     bool
	Reason string
}

// TargetReport — проверка цели: адрес соединения, время рукопожатия, критерии по порядку.
type TargetReport struct {
	Host      string
	Addr      netip.Addr
	Handshake time.Duration
	Checks    []Check
}

// OK — цель прошла все критерии.
func (r TargetReport) OK() bool {
	return len(r.Checks) > 0 && !slices.ContainsFunc(r.Checks, func(c Check) bool { return !c.OK })
}

// Failure — причины непрошедших критериев одной строкой.
func (r TargetReport) Failure() string {
	var out []string
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c.Name+": "+c.Reason)
		}
	}
	return strings.Join(out, "; ")
}

// dnsName — имя цели: не меньше двух меток, последняя — не число (IP-литерал не цель).
var dnsName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$`)

// ProbeTarget проверяет цель REALITY одним соединением к host:443 на первый публичный адрес
// имени; публичного нет — соединения нет, критерий address не прошёл. Ошибка — только негодное
// имя; провал соединения — отчёт, где каждый критерий не прошёл с этой причиной.
func (m *Manager) ProbeTarget(ctx context.Context, host string) (TargetReport, error) {
	host = strings.ToLower(host)
	if len(host) > 253 || !dnsName.MatchString(host) {
		return TargetReport{}, fmt.Errorf("цель %q: нужно имя домена", host)
	}
	c, cancel := context.WithTimeout(ctx, targetTimeout)
	defer cancel()
	info, err := m.p.Net().TLSProbe(c, platform.TLSRequest{Host: host, Port: targetPort, Allow: public})
	r := TargetReport{Host: host, Addr: info.Addr, Handshake: info.Handshake}
	if err != nil {
		why := "не проверено: " + err.Error()
		for _, n := range []string{CheckTLS13, CheckH2, CheckMLKEM, CheckCert, CheckAddress, CheckRedirect} {
			c := Check{Name: n, Reason: why}
			if n == CheckAddress && errors.Is(err, platform.ErrNotAllowed) {
				c.Reason = "адрес не публичный (частный, петлевой, link-local или CGNAT); соединения не было: " + err.Error()
			}
			r.Checks = append(r.Checks, c)
		}
		return r, nil
	}
	check := func(name string, ok bool, reason string) {
		if ok {
			reason = ""
		}
		r.Checks = append(r.Checks, Check{Name: name, OK: ok, Reason: reason})
	}
	check(CheckTLS13, info.Version == tls.VersionTLS13, "версия "+tls.VersionName(info.Version)+", нужна TLS 1.3")
	check(CheckH2, info.ALPN == "h2", fmt.Sprintf("ALPN %q, нужен h2", info.ALPN))
	check(CheckMLKEM, info.Curve == tls.X25519MLKEM768, fmt.Sprintf("группа %v, нужна X25519MLKEM768", info.Curve))
	certWhy := ""
	if info.CertErr != nil {
		certWhy = "сертификат не действителен для имени: " + info.CertErr.Error()
	}
	check(CheckCert, info.CertErr == nil, certWhy)
	// Платформа подключается только к адресу по public: проверка здесь — страховка контракта.
	check(CheckAddress, public(info.Addr), fmt.Sprintf("адрес %v не публичный", info.Addr))
	ok, why := redirectOK(host, info)
	check(CheckRedirect, ok, why)
	return r, nil
}

// redirectOK — критерий ADR-0040: ответ на HEAD / не 3xx или 3xx с Location на то же имя
// (относительный путь или https на host); нет ответа — «не проверено».
func redirectOK(host string, info platform.TLSInfo) (bool, string) {
	if info.HeadErr != nil || info.Status == 0 {
		return false, fmt.Sprintf("не проверено: нет ответа на HEAD /: %v", info.HeadErr)
	}
	if info.Status < 300 || info.Status > 399 {
		return true, ""
	}
	loc := info.Location
	// Браузеры читают «\» как «/»: «/\чужое.имя» — перенаправление на другое имя.
	if strings.Contains(loc, `\`) {
		return false, fmt.Sprintf("ответ %d: перенаправление на другое имя (%q)", info.Status, clip(loc))
	}
	// Относительный — только путь с одним ведущим «/».
	if strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") {
		return true, ""
	}
	u, err := url.Parse(loc)
	if err == nil && u.Scheme == "https" && strings.EqualFold(u.Hostname(), host) && (u.Port() == "" || u.Port() == "443") {
		return true, ""
	}
	return false, fmt.Sprintf("ответ %d: перенаправление на другое имя или не по https (%q)", info.Status, clip(loc))
}

// maxLocation — предел Location в причине: заголовок чужого узла.
const maxLocation = 256

// clip обрезает строку до maxLocation байт.
func clip(s string) string {
	if len(s) > maxLocation {
		return s[:maxLocation] + "…"
	}
	return s
}

// SelectTarget выбирает цель REALITY. sni непустое (--sni) — только оно, провал — ошибка.
// Иначе — проверка всех Candidates параллельно с общим сроком и выбор прошедшего с наименьшим
// временем рукопожатия, при равенстве — раньше по списку; ни один не прошёл — ошибка с
// причиной по каждому.
func (m *Manager) SelectTarget(ctx context.Context, sni string) (TargetReport, error) {
	if sni != "" {
		r, err := m.ProbeTarget(ctx, sni)
		if err != nil {
			return TargetReport{}, err
		}
		if !r.OK() {
			return TargetReport{}, fmt.Errorf("цель %s не годится: %s", r.Host, r.Failure())
		}
		return r, nil
	}
	c, cancel := context.WithTimeout(ctx, selectTimeout)
	defer cancel()
	list := Candidates()
	reports := make([]TargetReport, len(list))
	var wg sync.WaitGroup
	for i, h := range list {
		wg.Go(func() {
			// Имена списка заведомо годны: ошибки имени нет.
			reports[i], _ = m.ProbeTarget(c, h)
		})
	}
	wg.Wait()
	var passed []TargetReport
	var why []string
	for _, r := range reports {
		if r.OK() {
			passed = append(passed, r)
		} else {
			why = append(why, r.Host+": "+r.Failure())
		}
	}
	if len(passed) == 0 {
		return TargetReport{}, errors.New("ни одна цель REALITY не прошла проверку (" + strings.Join(why, "; ") +
			"); укажите свою: --sni <домен>")
	}
	// SortStableFunc сохраняет порядок списка при равном времени.
	slices.SortStableFunc(passed, func(a, b TargetReport) int { return cmp.Compare(a.Handshake, b.Handshake) })
	return passed[0], nil
}
