package network

import (
	"context"
	"net/netip"
	"os"
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

// fake — хост с выключенным UFW и пустой INPUT с политикой ACCEPT, если тест не задал иное.
func fake(t *testing.T) *platform.Fake {
	f := platform.NewFake(t.TempDir(), time.Now())
	f.Handle(platform.UFW, out("Status: inactive\n"))
	f.Handle(platform.IPTables, out("-P INPUT ACCEPT\n"))
	f.Handle(platform.IP6Tables, out("-P INPUT ACCEPT\n"))
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
		name, ufw, ipt4, ipt6 string
		want                  FirewallState
		source                string
	}{
		{"ufw разрешает", ufwHead + "443/tcp                    ALLOW IN    Anywhere\n443/tcp (v6)               ALLOW IN    Anywhere (v6)\n", "", "", FirewallAllowed, "ufw"},
		{"ufw запрещает правилом", ufwHead + "443                        DENY IN     Anywhere\n", "", "", FirewallDenied, "ufw"},
		{"ufw без правила, политика deny", ufwHead, "", "", FirewallDenied, "ufw"},
		{"ufw с ограничением источника", ufwHead + "443/tcp                    ALLOW IN    192.0.2.0/24\n", "", "", FirewallUnknown, "ufw"},
		{"iptables accept, правила без запрета", "Status: inactive\n", "-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n", "-P INPUT ACCEPT\n", FirewallAllowed, "iptables"},
		{"iptables политика DROP", "Status: inactive\n", "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n", "-P INPUT ACCEPT\n", FirewallUnknown, "iptables"},
		{"ip6tables правило REJECT", "Status: inactive\n", "-P INPUT ACCEPT\n", "-P INPUT ACCEPT\n-A INPUT -s 2001:db8::/32 -j REJECT --reject-with icmp6-port-unreachable\n", FirewallUnknown, "iptables"},
		{"iptables правило DROP", "Status: inactive\n", "-P INPUT ACCEPT\n-A INPUT -p tcp -j DROP\n", "-P INPUT ACCEPT\n", FirewallUnknown, "iptables"},
		{"iptables переход в цепочку f2b", "Status: inactive\n", "-P INPUT ACCEPT\n-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n", "-P INPUT ACCEPT\n", FirewallUnknown, "iptables"},
		{"iptables переход -g", "Status: inactive\n", "-P INPUT ACCEPT\n-A INPUT -g extra\n", "-P INPUT ACCEPT\n", FirewallUnknown, "iptables"},
		{"iptables LOG и RETURN", "Status: inactive\n", "-P INPUT ACCEPT\n-A INPUT -j LOG --log-prefix x\n-A INPUT -j RETURN\n", "-P INPUT ACCEPT\n", FirewallAllowed, "iptables"},
		{"iptables незнакомый формат", "Status: inactive\n", "Chain INPUT (policy ACCEPT)\n", "-P INPUT ACCEPT\n", FirewallUnknown, "iptables"},
		{"iptables лишняя цепочка", "Status: inactive\n", "-P INPUT ACCEPT\n-N extra\n", "-P INPUT ACCEPT\n", FirewallUnknown, "iptables"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fake(t)
			f.Handle(platform.UFW, out(c.ufw))
			if c.ipt4 != "" {
				f.Handle(platform.IPTables, out(c.ipt4))
				f.Handle(platform.IP6Tables, out(c.ipt6))
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
	f := platform.NewFake(t.TempDir(), time.Now()) // ни ufw, ни iptables не отвечают
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
	if got.Firewall.Source != "iptables" || !strings.Contains(got.Firewall.Note, "ufw не прочитан") {
		t.Fatalf("сбой ufw не назван: %+v", got.Firewall)
	}
}

func TestFirewallIPTablesFailures(t *testing.T) {
	cases := map[string]func(platform.Command) (platform.Result, error){
		"срок":   func(platform.Command) (platform.Result, error) { return platform.Result{}, context.DeadlineExceeded },
		"код":    func(platform.Command) (platform.Result, error) { return platform.Result{ExitCode: 3}, nil },
		"ошибка": func(platform.Command) (platform.Result, error) { return platform.Result{}, os.ErrNotExist },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			f := fake(t)
			f.Handle(platform.IP6Tables, h)
			got, err := New(f).Facts(ctx(t), Request{Port: 443, Address: "198.51.100.20"})
			if err != nil {
				t.Fatal(err)
			}
			if got.Firewall.State != FirewallUnknown || !strings.Contains(got.Firewall.Note, "ip6tables не прочитан") {
				t.Fatalf("сбой ip6tables: %+v", got.Firewall)
			}
		})
	}
}

func TestFirewallIPTablesReadOnly(t *testing.T) {
	f := fake(t)
	if _, err := New(f).Facts(ctx(t), Request{Port: 443, Address: "198.51.100.20"}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range f.Calls() {
		if c.Op == "exec" && (c.Path == platform.IPTables || c.Path == platform.IP6Tables) {
			n++
			if len(c.Args) != 2 || c.Args[0] != "-S" || c.Args[1] != "INPUT" {
				t.Fatalf("%s вызван не для чтения: %v", c.Path, c.Args)
			}
		}
	}
	if n != 2 {
		t.Fatalf("вызовов iptables/ip6tables: %d", n)
	}
}

// CanAllow — только когда порт закрыт политикой UFW по умолчанию: явный deny правилом, чужой
// фаервол и открытый порт правило «allow» не получают (ADR-0041).
func TestFirewallCanAllow(t *testing.T) {
	const head = "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo Action From\n-- ------ ----\n22/tcp ALLOW IN Anywhere\n"
	cases := []struct {
		name, ufw string
		want      bool
	}{
		{"политика deny, правила нет", head, true},
		{"явный deny", head + "443 DENY IN Anywhere\n", false},
		{"уже разрешён", head + "443/tcp ALLOW IN Anywhere\n", false},
		{"ufw выключен", "Status: inactive\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fake(t)
			f.Handle(platform.UFW, out(tc.ufw))
			got, err := New(f).Facts(ctx(t), Request{Address: "203.0.113.7", Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			if got.Firewall.CanAllow != tc.want {
				t.Fatalf("CanAllow = %v, нужно %v (%+v)", got.Firewall.CanAllow, tc.want, got.Firewall)
			}
		})
	}
}

func TestAllowAndRevokePort(t *testing.T) {
	f := fake(t)
	f.Handle(platform.UFW, out("Rule added\n"))
	m := New(f)
	if err := m.AllowPort(ctx(t), 443); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokePort(ctx(t), 443); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range f.Calls() {
		if c.Op == "exec" && c.Path == platform.UFW {
			got = append(got, strings.Join(c.Args, " "))
		}
	}
	if strings.Join(got, "|") != "allow 443/tcp|delete allow 443/tcp" {
		t.Fatalf("вызовы ufw: %q", got)
	}
	if err := m.AllowPort(ctx(t), 0); err == nil {
		t.Fatal("порт 0 принят")
	}
	f.Handle(platform.UFW, func(platform.Command) (platform.Result, error) { return platform.Result{ExitCode: 1}, nil })
	if err := m.AllowPort(ctx(t), 443); err == nil {
		t.Fatal("код выхода 1 принят")
	}
}
