package network

import (
	"crypto/tls"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// good — сведения о годной цели; тест портит одно поле.
func good(ms int) platform.TLSInfo {
	return platform.TLSInfo{Version: tls.VersionTLS13, ALPN: "h2", Curve: tls.X25519MLKEM768,
		Addr: netip.MustParseAddr("203.0.113.10"), Handshake: time.Duration(ms) * time.Millisecond}
}

func TestProbeTargetPasses(t *testing.T) {
	f := fake(t)
	f.SetTLS("www.example.com", good(30), nil)
	r, err := New(f).ProbeTarget(ctx(t), "www.example.com")
	if err != nil || !r.OK() || r.Handshake != 30*time.Millisecond || len(r.Checks) != 5 {
		t.Fatalf("ProbeTarget = %+v, %v", r, err)
	}
	if c := f.Calls(); len(c) != 1 || c[0].Op != "tls" || c[0].Path != "www.example.com" {
		t.Fatalf("Calls = %+v: нужно одно соединение", c)
	}
}

func TestProbeTargetEachCriterion(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(*platform.TLSInfo)
	}{
		{CheckTLS13, func(i *platform.TLSInfo) { i.Version = tls.VersionTLS12 }},
		{CheckH2, func(i *platform.TLSInfo) { i.ALPN = "http/1.1" }},
		{CheckMLKEM, func(i *platform.TLSInfo) { i.Curve = tls.X25519 }},
		{CheckCert, func(i *platform.TLSInfo) { i.CertErr = errors.New("x509: certificate is valid for other.test") }},
		{CheckAddress, func(i *platform.TLSInfo) { i.Addr = netip.MustParseAddr("10.0.0.1") }},
		{CheckAddress, func(i *platform.TLSInfo) { i.Addr = netip.MustParseAddr("127.0.0.1") }},
		{CheckAddress, func(i *platform.TLSInfo) { i.Addr = netip.MustParseAddr("fe80::1") }},
		{CheckAddress, func(i *platform.TLSInfo) { i.Addr = netip.MustParseAddr("fd00::1") }},
	}
	for _, tc := range cases {
		info := good(10)
		tc.spoil(&info)
		f := fake(t)
		f.SetTLS("www.example.com", info, nil)
		r, err := New(f).ProbeTarget(ctx(t), "www.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if r.OK() {
			t.Fatalf("%s: отчёт годен: %+v", tc.name, r)
		}
		for _, c := range r.Checks {
			if (c.Name == tc.name) == c.OK || (!c.OK && c.Reason == "") {
				t.Errorf("%s: критерий %+v", tc.name, c)
			}
		}
	}
}

func TestProbeTargetHandshakeFails(t *testing.T) {
	f := fake(t)
	f.SetTLS("www.example.com", platform.TLSInfo{}, errors.New("tls: handshake failure"))
	r, err := New(f).ProbeTarget(ctx(t), "www.example.com")
	if err != nil || r.OK() || len(r.Checks) != 5 || !strings.Contains(r.Failure(), "handshake failure") {
		t.Fatalf("ProbeTarget = %+v, %v", r, err)
	}
}

func TestProbeTargetBadName(t *testing.T) {
	for _, h := range []string{"", "a b", "x.test:443", "-x.test", "192.0.2.4", "x..test", "localhost"} {
		if _, err := New(fake(t)).ProbeTarget(ctx(t), h); err == nil {
			t.Errorf("имя %q принято", h)
		}
	}
}

func TestSelectTargetFastestDeterministic(t *testing.T) {
	Candidates := Candidates()
	if len(Candidates) == 0 || len(Candidates) > 10 {
		t.Fatalf("кандидатов %d, нужно 1–10", len(Candidates))
	}
	f := fake(t)
	for i, h := range Candidates {
		f.SetTLS(h, good(100+i), nil)
	}
	bad := good(1)
	bad.ALPN = ""
	f.SetTLS(Candidates[0], bad, nil) // самый быстрый, но негоден
	f.SetTLS(Candidates[5], good(20), nil)
	f.SetTLS(Candidates[3], good(20), nil) // равенство — раньше по списку
	r, err := New(f).SelectTarget(ctx(t), "")
	if err != nil || r.Host != Candidates[3] {
		t.Fatalf("SelectTarget = %+v, %v", r, err)
	}
}

func TestSelectTargetNonePass(t *testing.T) {
	Candidates := Candidates()
	f := fake(t)
	for _, h := range Candidates {
		f.SetTLS(h, platform.TLSInfo{}, errors.New("i/o timeout"))
	}
	_, err := New(f).SelectTarget(ctx(t), "")
	if err == nil || !strings.Contains(err.Error(), "--sni") {
		t.Fatalf("ошибка = %v", err)
	}
	for _, h := range Candidates {
		if !strings.Contains(err.Error(), h+": ") {
			t.Errorf("в ошибке нет причины для %s", h)
		}
	}
}

func TestSelectTargetExplicit(t *testing.T) {
	f := fake(t)
	f.SetTLS("www.example.com", good(500), nil)
	r, err := New(f).SelectTarget(ctx(t), "www.example.com")
	if err != nil || r.Host != "www.example.com" {
		t.Fatalf("SelectTarget = %+v, %v", r, err)
	}
	for _, c := range f.Calls() {
		if c.Op == "tls" && c.Path != "www.example.com" {
			t.Fatalf("при --sni проверен кандидат %s", c.Path)
		}
	}
	bad := good(5)
	bad.Curve = tls.X25519
	f.SetTLS("www.example.com", bad, nil)
	if _, err := New(f).SelectTarget(ctx(t), "www.example.com"); err == nil || !strings.Contains(err.Error(), "X25519MLKEM768") {
		t.Fatalf("негодное --sni: %v", err)
	}
}
