package diag

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/grokki91/xray_core/internal/platform"
)

type localCase struct {
	controlCase
	version func(context.Context) (string, error)
	inRange bool
	drift   func(context.Context) (bool, error)
	fam     platform.Families
	served  platform.Families
	egress  *fakeEgress
	fw      string
	fwErr   error
	usage   platform.DiskUsage
	mem     [2]int64 // доступно и всего, КиБ
	oomN    int
	synced  bool
}

type famNet struct{ f platform.Families }

func (n famNet) ListeningFamilies(context.Context, int) (platform.Families, error) { return n.f, nil }

type fakeEgress struct {
	addrs []platform.IfAddr
	ok    map[netip.AddrPort]bool
	tried []netip.AddrPort
}

func (e *fakeEgress) Addrs(context.Context) ([]platform.IfAddr, error) { return e.addrs, nil }
func (e *fakeEgress) Connect(_ context.Context, a netip.AddrPort) error {
	e.tried = append(e.tried, a)
	if e.ok[a] {
		return nil
	}
	return errors.New("timeout")
}

func allUp() *fakeEgress {
	ok := map[netip.AddrPort]bool{}
	for _, n := range append(egressNodes[false], egressNodes[true]...) {
		ok[n] = true
	}
	return &fakeEgress{ok: ok, addrs: []platform.IfAddr{
		{Addr: netip.MustParseAddr("10.0.0.5")}, {Addr: netip.MustParseAddr("2001:db8::5")},
	}}
}

func healthyLocal() localCase {
	c := healthy()
	c.selftest = nil
	return localCase{
		controlCase: c,
		version:     func(context.Context) (string, error) { return "26.11.9", nil },
		inRange:     true,
		drift:       func(context.Context) (bool, error) { return false, nil },
		fam:         platform.Families{IPv4: true, IPv6: true},
		served:      platform.Families{IPv4: true, IPv6: true},
		egress:      allUp(),
		fw:          FirewallAllowed,
		usage:       platform.DiskUsage{Avail: 10 << 30, Total: 20 << 30},
		mem:         [2]int64{1 << 20, 2 << 20},
		synced:      true,
	}
}

func (c localCase) run(t *testing.T) Report {
	t.Helper()
	e, err := NewLocal(LocalDeps{
		ControlDeps: ControlDeps{Service: c.svc, Net: c.net, Port: c.port, Validate: c.validate},
		HostDeps: HostDeps{
			Disk:        func(context.Context, string) (platform.DiskUsage, error) { return c.usage, nil },
			Memory:      func(context.Context) (int64, int64, error) { return c.mem[0], c.mem[1], nil },
			OOMKills:    func(context.Context) (int, error) { return c.oomN, nil },
			ClockSynced: func(context.Context) (bool, error) { return c.synced, nil },
		},
		Version:  c.version,
		InRange:  func(string) bool { return c.inRange },
		Drift:    c.drift,
		Families: famNet{c.fam},
		Served:   func(context.Context) (platform.Families, error) { return c.served, nil },
		Egress:   c.egress,
		Firewall: func(context.Context, int) (string, string, error) {
			return c.fw, "ufw", c.fwErr
		},
	})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	r, err := e.Run(context.Background(), SetLocal)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

func TestLocalHealthy(t *testing.T) {
	r := healthyLocal().run(t)
	if r.Health != HealthOK || r.Summary.OK != 17 {
		t.Fatalf("health %s, summary %+v", r.Health, r.Summary)
	}
}

func TestLocalCatalog(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mod    func(*localCase)
		check  string
		want   Status
		health Health
	}{
		{"нет Xray", func(c *localCase) { c.version = func(context.Context) (string, error) { return "", nil } }, CheckInstalled, StatusFail, HealthDown},
		{"версия не измерена", func(c *localCase) { c.version = func(context.Context) (string, error) { return "", errors.New("x") } }, CheckVersionRange, StatusSkip, HealthOK},
		{"вне диапазона", func(c *localCase) { c.inRange = false }, CheckVersionRange, StatusFail, HealthDegraded},
		{"перезапуски", func(c *localCase) { c.svc.st.Restarts = 3 }, CheckRestarts, StatusFail, HealthDegraded},
		{"служба стоит", func(c *localCase) { c.svc.st.Active = "inactive" }, CheckRestarts, StatusSkip, HealthDown},
		{"дрейф", func(c *localCase) { c.drift = func(context.Context) (bool, error) { return true, nil } }, CheckConfigDrift, StatusFail, HealthDegraded},
		{"порт не на IPv6", func(c *localCase) { c.fam.IPv6 = false }, CheckListenIPv6, StatusFail, HealthDegraded},
		{"порт не на IPv4", func(c *localCase) { c.fam.IPv4 = false }, CheckListenIPv4, StatusFail, HealthDegraded},
		{"у сервера нет IPv6", func(c *localCase) { c.served.IPv6, c.fam.IPv6 = false, false }, CheckListenIPv6, StatusSkip, HealthOK},
		{"порт закрыт", func(c *localCase) { c.net.on = false }, CheckListenIPv4, StatusSkip, HealthDown},
		{"нет IPv4 наружу", func(c *localCase) { c.egress.ok = map[netip.AddrPort]bool{} }, CheckEgressIPv4, StatusFail, HealthDown},
		{"нет IPv6 наружу", func(c *localCase) {
			delete(c.egress.ok, egressNodes[true][0])
			delete(c.egress.ok, egressNodes[true][1])
		}, CheckEgressIPv6, StatusFail, HealthDegraded},
		{"нет адреса IPv6", func(c *localCase) {
			c.egress.addrs = []platform.IfAddr{{Addr: netip.MustParseAddr("10.0.0.5")}, {Addr: netip.MustParseAddr("fe80::1")}}
		}, CheckEgressIPv6, StatusSkip, HealthOK},
		{"второй узел IPv4", func(c *localCase) { delete(c.egress.ok, egressNodes[false][0]) }, CheckEgressIPv4, StatusOK, HealthOK},
		{"фаервол запрещает", func(c *localCase) { c.fw = FirewallDenied }, CheckFirewall, StatusFail, HealthDown},
		{"фаервол не определён", func(c *localCase) { c.fw = FirewallUnknown }, CheckFirewall, StatusSkip, HealthOK},
		{"фаервол не прочитан", func(c *localCase) { c.fwErr = errors.New("x") }, CheckFirewall, StatusError, HealthOK},
		{"диск < 10 %", func(c *localCase) { c.usage = platform.DiskUsage{Avail: 1 << 30, Total: 20 << 30} }, CheckDisk, StatusFail, HealthDegraded},
		{"диск < 500 МБ", func(c *localCase) { c.usage = platform.DiskUsage{Avail: 400 << 20, Total: 1 << 30} }, CheckDisk, StatusFail, HealthDegraded},
		{"диск ровно 10 %", func(c *localCase) { c.usage = platform.DiskUsage{Avail: 2 << 30, Total: 20 << 30} }, CheckDisk, StatusOK, HealthOK},
		{"память < 10 %", func(c *localCase) { c.mem = [2]int64{100, 2000} }, CheckMemory, StatusFail, HealthDegraded},
		{"OOM", func(c *localCase) { c.oomN = 1 }, CheckOOM, StatusFail, HealthDegraded},
		{"часы", func(c *localCase) { c.synced = false }, CheckClock, StatusFail, HealthDegraded},
		{"дрейф не измерен", func(c *localCase) { c.drift = func(context.Context) (bool, error) { return false, errors.New("x") } }, CheckConfigDrift, StatusError, HealthOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := healthyLocal()
			c.svc.st = platform.UnitStatus{Loaded: true, Active: "active", Sub: "running"}
			tc.mod(&c)
			r := c.run(t)
			if got := status(r, tc.check); got != tc.want {
				t.Fatalf("%s: %s, want %s", tc.check, got, tc.want)
			}
			if r.Health != tc.health {
				t.Fatalf("health %s, want %s", r.Health, tc.health)
			}
		})
	}
}

func TestLocalRejectsSelftest(t *testing.T) {
	c := healthy()
	_, err := NewLocal(LocalDeps{
		ControlDeps: ControlDeps{Service: c.svc, Net: c.net, Port: c.port, Validate: c.validate, Selftest: c.selftest},
		Version:     func(context.Context) (string, error) { return "", nil },
		InRange:     func(string) bool { return true },
		Drift:       func(context.Context) (bool, error) { return false, nil },
	})
	if !errors.Is(err, ErrRegistry) {
		t.Fatalf("err %v", err)
	}
}

// Второй узел — только при неудаче первого: к узлам без серий соединений (§5).
func TestEgressSecondNodeOnlyOnFailure(t *testing.T) {
	c := healthyLocal()
	c.run(t)
	if len(c.egress.tried) != 2 || c.egress.tried[0] != egressNodes[false][0] || c.egress.tried[1] != egressNodes[true][0] {
		t.Fatalf("узлы при успехе: %v", c.egress.tried)
	}
	c = healthyLocal()
	delete(c.egress.ok, egressNodes[false][0])
	c.run(t)
	if len(c.egress.tried) != 3 || c.egress.tried[1] != egressNodes[false][1] {
		t.Fatalf("узлы при неудаче первого: %v", c.egress.tried)
	}
}
