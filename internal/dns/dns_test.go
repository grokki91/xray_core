package dns

import (
	"slices"
	"testing"
)

func TestPlanStrategyByFamilies(t *testing.T) {
	want := []string{"https://1.1.1.1/dns-query", "https://dns.quad9.net/dns-query"}
	for _, c := range []struct {
		n    NetFacts
		want string
	}{
		{NetFacts{IPv4: true}, UseIPv4},
		{NetFacts{IPv4: true, IPv6: true}, UseIP},
		{NetFacts{IPv6: true}, UseIPv6},
	} {
		got := Plan(c.n)
		if got.Strategy != c.want {
			t.Errorf("%+v: стратегия %q, нужна %q", c.n, got.Strategy, c.want)
		}
		if !slices.Equal(got.DoH, want) {
			t.Errorf("%+v: серверы %v", c.n, got.DoH)
		}
	}
}

func TestPlanDoesNotShareList(t *testing.T) {
	a := Plan(NetFacts{IPv4: true})
	a.DoH[0] = "x"
	if Plan(NetFacts{IPv4: true}).DoH[0] == "x" {
		t.Fatal("Plan отдаёт общий срез")
	}
}
