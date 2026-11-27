package platform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestScanFamilies(t *testing.T) {
	head := "  sl  local_address rem_address   st\n"
	for _, tc := range []struct {
		name string
		row  string
		v6   bool
		want Families
	}{
		{"tcp", "   0: 00000000:01BB 00000000:0000 0A 0:0\n", false, Families{IPv4: true}},
		{"tcp6 ::", "   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0:0\n", true, Families{IPv4: true, IPv6: true}},
		{"tcp6 ::1", "   0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 0:0\n", true, Families{IPv6: true}},
		{"tcp6 v4-mapped", "   0: 0000000000000000FFFF00000100007F:01BB 00000000000000000000000000000000:0000 0A 0:0\n", true, Families{IPv4: true}},
		{"чужой порт", "   0: 00000000:1F90 00000000:0000 0A 0:0\n", false, Families{}},
		{"не LISTEN", "   0: 00000000:01BB 0100007F:C350 01 0:0\n", false, Families{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanFamilies(strings.NewReader(head+tc.row), 443, tc.v6)
			if err != nil || got != tc.want {
				t.Fatalf("%+v %v, want %+v", got, err, tc.want)
			}
		})
	}
	if _, err := scanFamilies(strings.NewReader(head+"   0: 0000:01BB 0:0 0A\n"), 443, true); err == nil {
		t.Fatal("короткий адрес tcp6 принят")
	}
}

func listenOn(t *testing.T, network, addr string) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skip("нет адреса для теста:", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func TestListeningFamiliesReal(t *testing.T) {
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n := New().Net()
	_, p4 := listenOn(t, "tcp4", "127.0.0.1:0")
	if f, err := n.ListeningFamilies(c, p4); err != nil || f != (Families{IPv4: true}) {
		t.Fatalf("127.0.0.1: %+v %v", f, err)
	}
	_, pany := listenOn(t, "tcp", ":0") // Go: двойной сокет на ::
	if f, err := n.ListeningFamilies(c, pany); err != nil || !f.IPv4 {
		t.Fatalf("любой адрес: %+v %v", f, err)
	}
	if _, err := n.ListeningFamilies(c, 0); err == nil {
		t.Fatal("порт 0 принят")
	}
}

func TestConnect(t *testing.T) {
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n := New().Net()
	ln, port := listenOn(t, "tcp4", "127.0.0.1:0")
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	if err := n.Connect(c, addr); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	ln.Close()
	if err := n.Connect(c, addr); err == nil {
		t.Fatal("соединение с закрытым портом прошло")
	}
	if err := n.Connect(context.Background(), addr); err == nil {
		t.Fatal("соединение без срока принято")
	}
	for _, bad := range []netip.AddrPort{{}, netip.MustParseAddrPort("0.0.0.0:443"), netip.MustParseAddrPort("[::ffff:1.1.1.1]:443"), netip.MustParseAddrPort("1.1.1.1:0"), netip.MustParseAddrPort("[fe80::1%eth0]:443")} {
		if err := n.Connect(c, bad); !errors.Is(err, ErrURL) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
}

func TestFakeFamiliesAndConnect(t *testing.T) {
	f := NewFake(t.TempDir(), time.Time{})
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f.SetFamilies(443, Families{IPv6: true})
	if got, _ := f.Net().ListeningFamilies(c, 443); got != (Families{IPv6: true}) {
		t.Fatalf("SetFamilies: %+v", got)
	}
	a := netip.MustParseAddrPort("1.1.1.1:443")
	if err := f.Net().Connect(c, a); err == nil {
		t.Fatal("не заданный узел соединился")
	}
	f.SetConnect(a, nil)
	if err := f.Net().Connect(c, a); err != nil {
		t.Fatalf("SetConnect: %v", err)
	}
}
