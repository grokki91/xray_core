package platform

import (
	"context"
	"strings"
	"testing"
	"time"
)

const route4Head = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

func TestScanDefault4(t *testing.T) {
	for name, tc := range map[string]struct {
		rows string
		want bool
	}{
		"маршрут по умолчанию": {"eth0\t00000000\t017100CB\t0003\t0\t0\t100\t00000000\t0\t0\t0\n", true},
		"только сеть":          {"eth0\t007100CB\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n", false},
		"не поднят":            {"eth0\t00000000\t017100CB\t0002\t0\t0\t100\t00000000\t0\t0\t0\n", false},
		"отказ":                {"eth0\t00000000\t00000000\t0201\t0\t0\t100\t00000000\t0\t0\t0\n", false},
		"пусто":                {"", false},
	} {
		got, err := scanDefault4(strings.NewReader(route4Head + tc.rows))
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v; нужно %v", name, got, err, tc.want)
		}
	}
	if _, err := scanDefault4(strings.NewReader(route4Head + "eth0\t00000000\t017100CB\tZZZZ\t0\t0\t100\t00000000\t0\t0\t0\n")); err == nil {
		t.Error("нечисловые флаги — нужна ошибка")
	}
	if _, err := scanDefault4(strings.NewReader(route4Head + "eth0 00000000\n")); err == nil {
		t.Error("короткая строка — нужна ошибка")
	}
}

func TestScanDefault6(t *testing.T) {
	z := strings.Repeat("0", 32)
	gw := "20010db8000000000000000000000001"
	for name, tc := range map[string]struct {
		rows string
		want bool
	}{
		// Ядро без маршрута IPv6 держит ::/0 через lo с RTF_REJECT — это не маршрут.
		"отказ через lo":       {z + " 00 " + z + " 00 " + z + " ffffffff 00000001 00000000 00200200       lo\n", false},
		"маршрут по умолчанию": {z + " 00 " + z + " 00 " + gw + " 00000400 00000001 00000000 00450003     eth0\n", true},
		"только сеть":          {"20010db8000000000000000000000000 40 " + z + " 00 " + z + " 00000100 00000001 00000000 00000001     eth0\n", false},
		"пусто":                {"", false},
	} {
		got, err := scanDefault6(strings.NewReader(tc.rows))
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v; нужно %v", name, got, err, tc.want)
		}
	}
	if _, err := scanDefault6(strings.NewReader(z + " 00 " + z + " 00 " + gw + " 00000400 00000001 00000000 ZZZZ eth0\n")); err == nil {
		t.Error("нечисловые флаги IPv6 — нужна ошибка")
	}
	if _, err := scanDefault6(strings.NewReader(z + " 00\n")); err == nil {
		t.Error("короткая строка — нужна ошибка")
	}
}

func TestDefaultRoutes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := New().Net().DefaultRoutes(ctx); err != nil {
		t.Errorf("Real.DefaultRoutes: %v", err)
	}
	f := NewFake(t.TempDir(), time.Unix(0, 0))
	f.SetDefaultRoutes(Families{IPv4: true})
	if got, err := f.Net().DefaultRoutes(ctx); err != nil || got != (Families{IPv4: true}) {
		t.Errorf("Fake.DefaultRoutes = %+v, %v", got, err)
	}
}
