package network

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func ifa(name, a string) platform.IfAddr {
	return platform.IfAddr{Iface: name, Addr: netip.MustParseAddr(a)}
}

func out(s string) func(platform.Command) (platform.Result, error) {
	return func(platform.Command) (platform.Result, error) { return platform.Result{Stdout: []byte(s)}, nil }
}

// fake — хост с выключенным UFW и пустым nftables, если тест не задал иное.
func fake(t *testing.T) *platform.Fake {
	f := platform.NewFake(t.TempDir(), time.Now())
	f.Handle(platform.UFW, out("Status: inactive\n"))
	f.Handle(platform.NFT, out(`{"nftables":[{"metainfo":{}}]}`))
	return f
}

func gets(f *platform.Fake) int {
	n := 0
	for _, c := range f.Calls() {
		if c.Op == "get" {
			n++
		}
	}
	return n
}

func TestFactsPublicOnInterfaceNoRequest(t *testing.T) {
	f := fake(t)
	f.SetAddrs([]platform.IfAddr{ifa("lo", "127.0.0.1"), ifa("lo", "::1"), ifa("eth0", "fe80::1"),
		ifa("eth0", "203.0.113.7"), ifa("eth0", "2001:db8::7")})
	got, err := New(f).Facts(ctx(t), Request{Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	// 2001:db8::/32 и 203.0.113.0/24 — документационные, но для net/netip глобальные: годятся как фиктивные публичные.
	if got.V4.Addr.String() != "203.0.113.7" || got.V4.Source != SourceInterface {
		t.Fatalf("V4 = %+v", got.V4)
	}
	if got.V6.Addr.String() != "2001:db8::7" || got.V6.Source != SourceInterface {
		t.Fatalf("V6 = %+v", got.V6)
	}
	for _, a := range got.Addrs {
		if a.Public != (a.Iface == "eth0" && !a.Addr.IsLinkLocalUnicast()) {
			t.Errorf("Public у %v = %v", a.Addr, a.Public)
		}
	}
	if gets(f) != 0 {
		t.Fatal("публичный адрес на интерфейсе, а внешний узел опрошен")
	}
}

func TestFactsBehindNATUsesTrace(t *testing.T) {
	f := fake(t)
	f.SetAddrs([]platform.IfAddr{ifa("eth0", "10.0.0.5"), ifa("eth0", "100.64.1.2"), ifa("eth0", "fd00::5")})
	f.Serve(traceV4, []byte("fl=1\nh=1.1.1.1\nip=198.51.100.9\nts=1\n"))
	got, err := New(f).Facts(ctx(t), Request{Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if got.V4.Addr.String() != "198.51.100.9" || got.V4.Source != SourceTrace {
		t.Fatalf("V4 = %+v", got.V4)
	}
	if got.V6.Addr.IsValid() || got.V6.Note == "" {
		t.Fatalf("V6 без ответа узла должен быть не определён с причиной: %+v", got.V6)
	}
	for _, a := range got.Addrs {
		if a.Public {
			t.Errorf("%v признан публичным", a.Addr)
		}
	}
}

func TestFactsTraceRejectsPrivateOrWrongFamily(t *testing.T) {
	f := fake(t)
	f.Serve(traceV4, []byte("ip=10.1.1.1\n"))
	f.Serve(traceV6, []byte("ip=198.51.100.9\n"))
	got, err := New(f).Facts(ctx(t), Request{Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if got.V4.Addr.IsValid() || got.V6.Addr.IsValid() {
		t.Fatalf("негодный ответ принят: %+v %+v", got.V4, got.V6)
	}
}

func TestFactsAddressOverride(t *testing.T) {
	f := fake(t)
	f.SetAddrs([]platform.IfAddr{ifa("eth0", "203.0.113.7")})
	got, err := New(f).Facts(ctx(t), Request{Port: 443, Address: "198.51.100.20"})
	if err != nil {
		t.Fatal(err)
	}
	if got.V4.Addr.String() != "198.51.100.20" || got.V4.Source != SourceFlag || got.V6.Addr.IsValid() {
		t.Fatalf("переопределение: %+v %+v", got.V4, got.V6)
	}
	if gets(f) != 0 {
		t.Fatal("с --address внешний узел опрошен")
	}
	for _, bad := range []string{"10.0.0.1", "example", "fe80::1%eth0"} {
		if _, err := New(f).Facts(ctx(t), Request{Port: 443, Address: bad}); err == nil {
			t.Errorf("адрес %q принят", bad)
		}
	}
}

func TestPortFree(t *testing.T) {
	f := fake(t)
	m := New(f)
	free, h, err := m.PortFree(ctx(t), 443)
	if err != nil || !free || h != (Holder{}) {
		t.Fatalf("свободный порт: %v %+v %v", free, h, err)
	}
	f.SetListening(443, true)
	f.Handle(platform.SS, out(`LISTEN 0 4096 *:443 *:* users:(("nginx",pid=1234,fd=6))`+"\n"))
	free, h, err = m.PortFree(ctx(t), 443)
	if err != nil || free || h != (Holder{Name: "nginx", PID: 1234}) {
		t.Fatalf("занятый порт: %v %+v %v", free, h, err)
	}
	f.Handle(platform.SS, out("LISTEN 0 4096 *:443 *:*\n"))
	free, h, err = m.PortFree(ctx(t), 443)
	if err != nil || free || h != (Holder{}) {
		t.Fatalf("занят, владелец не виден: %v %+v %v", free, h, err)
	}
	if _, _, err := m.PortFree(ctx(t), 0); err == nil {
		t.Fatal("порт 0 принят")
	}
}

func TestFirewallStates(t *testing.T) {
	const ufwHead = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n"
	cases := []struct {
		name, ufw, nft string
		want           FirewallState
		source         string
	}{
		{"ufw разрешает", ufwHead + "443/tcp                    ALLOW IN    Anywhere\n443/tcp (v6)               ALLOW IN    Anywhere (v6)\n", "", FirewallAllowed, "ufw"},
		{"ufw запрещает правилом", ufwHead + "443                        DENY IN     Anywhere\n", "", FirewallDenied, "ufw"},
		{"ufw без правила, политика deny", ufwHead, "", FirewallDenied, "ufw"},
		{"ufw с ограничением источника", ufwHead + "443/tcp                    ALLOW IN    192.0.2.0/24\n", "", FirewallUnknown, "ufw"},
		{"nft accept", "Status: inactive\n", `{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"accept"}}]}`, FirewallAllowed, "nftables"},
		{"nft drop", "Status: inactive\n", `{"nftables":[{"chain":{"family":"ip","table":"filter","name":"INPUT","hook":"input","policy":"drop"}},{"chain":{"hook":"output","policy":"accept"}}]}`, FirewallUnknown, "nftables"},
		{"nft не разобран", "Status: inactive\n", `oops`, FirewallUnknown, "nftables"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fake(t)
			f.Handle(platform.UFW, out(c.ufw))
			if c.nft != "" {
				f.Handle(platform.NFT, out(c.nft))
			}
			got, err := New(f).Facts(ctx(t), Request{Port: 443, Address: "198.51.100.20"})
			if err != nil {
				t.Fatal(err)
			}
			if got.Firewall.State != c.want || got.Firewall.Source != c.source {
				t.Fatalf("Firewall = %+v, want %s от %s", got.Firewall, c.want, c.source)
			}
			if c.want != FirewallAllowed && got.Firewall.Note == "" {
				t.Fatal("нет причины")
			}
			for _, call := range f.Calls() {
				if call.Op == "exec" && call.Path == "ufw" && (len(call.Args) != 2 || call.Args[0] != "status") {
					t.Fatalf("ufw вызван не только для чтения: %v", call.Args)
				}
			}
		})
	}
}

func TestFirewallNoTools(t *testing.T) {
	f := platform.NewFake(t.TempDir(), time.Now()) // ни ufw, ни nft не отвечают
	got, err := New(f).Facts(ctx(t), Request{Port: 443, Address: "198.51.100.20"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Firewall.State != FirewallUnknown {
		t.Fatalf("без утилит: %+v", got.Firewall)
	}
}

func TestTraceHasOwnDeadline(t *testing.T) {
	f := fake(t)
	f.Serve(traceV4, []byte("ip=198.51.100.9\n"))
	got, err := New(f).Facts(context.Background(), Request{Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if got.V4.Addr.String() != "198.51.100.9" {
		t.Fatalf("trace без срока вызывающего не выполнен: %+v", got.V4)
	}
}

func TestFirewallUFWTimeoutIsUnknown(t *testing.T) {
	f := fake(t)
	f.Handle(platform.UFW, func(platform.Command) (platform.Result, error) { return platform.Result{}, context.DeadlineExceeded })
	got, err := New(f).Facts(ctx(t), Request{Port: 443, Address: "198.51.100.20"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Firewall.State != FirewallUnknown || got.Firewall.Source != "ufw" {
		t.Fatalf("срок ufw: %+v", got.Firewall)
	}
}

func TestPortHolderNameSanitized(t *testing.T) {
	f := fake(t)
	f.SetListening(443, true)
	for _, name := range []string{"evil\nline", "a b", "x'y\x1b[31m"} {
		f.Handle(platform.SS, out(`LISTEN 0 4096 *:443 *:* users:(("`+name+`",pid=1,fd=6))`))
		_, h, err := New(f).PortFree(ctx(t), 443)
		if err != nil || h != (Holder{}) {
			t.Errorf("имя %q: %+v %v", name, h, err)
		}
	}
}

func TestFirewallUFWFailureNoted(t *testing.T) {
	f := fake(t)
	f.Handle(platform.UFW, func(platform.Command) (platform.Result, error) { return platform.Result{ExitCode: 1}, nil })
	got, err := New(f).Facts(ctx(t), Request{Port: 443, Address: "198.51.100.20"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Firewall.Source != "nftables" || !strings.Contains(got.Firewall.Note, "ufw не прочитан") {
		t.Fatalf("сбой ufw не назван: %+v", got.Firewall)
	}
}
