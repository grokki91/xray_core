package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// netCase — реализация сети и адрес её «своего» узла, на котором заданы ответы:
// /ok — тело, /hop — перенаправление на /ok, /out — перенаправление на чужой узел,
// /loop — перенаправление на себя, /chainN — цепочка из N перенаправлений до /ok.
type netCase struct {
	name string
	net  Net
	base string // https://узел
	host string
}

const foreign = "https://foreign.test/ok"

var netBody = []byte("архив")

func netCases(t *testing.T) []netCase {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/chain%d", &n); err == nil {
			to := "/ok"
			if n > 1 {
				to = fmt.Sprintf("/chain%d", n-1)
			}
			http.Redirect(w, r, to, http.StatusFound)
			return
		}
		switch r.URL.Path {
		case "/ok":
			w.Write(netBody)
		case "/hop":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/out":
			http.Redirect(w, r, foreign, http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	real := newReal(nil, srv.Client().Transport)

	fake := newFake(t.TempDir(), time.Time{}, nil)
	const fb = "https://own.test"
	fake.Serve(fb+"/ok", netBody)
	fake.Redirect(fb+"/hop", fb+"/ok")
	fake.Redirect(fb+"/out", foreign)
	fake.Redirect(fb+"/loop", fb+"/loop")
	fake.Serve(foreign, []byte("чужое"))
	for n := 1; n <= maxRedirects+1; n++ {
		to := fb + "/ok"
		if n > 1 {
			to = fmt.Sprintf("%s/chain%d", fb, n-1)
		}
		fake.Redirect(fmt.Sprintf("%s/chain%d", fb, n), to)
	}

	return []netCase{
		{"real", real.Net(), srv.URL, strings.TrimPrefix(srv.URL, "https://")},
		{"fake", fake.Net(), fb, "own.test"},
	}
}

// Обе реализации одинаково применяют правила адреса, перенаправлений и предела.
func TestNetAgree(t *testing.T) {
	for _, c := range netCases(t) {
		t.Run(c.name, func(t *testing.T) {
			ctx := deadline(t, 5*time.Second)
			req := func(path string) Request {
				return Request{URL: c.base + path, Hosts: []string{c.host}, Max: 1 << 10}
			}
			for _, path := range []string{"/ok", "/hop", fmt.Sprintf("/chain%d", maxRedirects)} {
				got, err := c.net.Get(ctx, req(path))
				if err != nil || !bytes.Equal(got, netBody) {
					t.Errorf("%s: %q, %v", path, got, err)
				}
			}
			if _, err := c.net.Get(ctx, req("/out")); !errors.Is(err, ErrURL) {
				t.Errorf("перенаправление на чужой узел: %v, нужен ErrURL", err)
			}
			if _, err := c.net.Get(ctx, req(fmt.Sprintf("/chain%d", maxRedirects+1))); err == nil {
				t.Errorf("цепочка из %d перенаправлений принята", maxRedirects+1)
			}
			if _, err := c.net.Get(ctx, req("/loop")); err == nil {
				t.Error("бесконечное перенаправление принято")
			}
			if _, err := c.net.Get(ctx, req("/missing")); err == nil {
				t.Error("ответ 404 принят")
			}
			small := req("/ok")
			small.Max = int64(len(netBody)) - 1
			if _, err := c.net.Get(ctx, small); !errors.Is(err, ErrTooLarge) {
				t.Error("тело сверх предела принято")
			}
			if _, err := c.net.Get(context.Background(), req("/ok")); !errors.Is(err, ErrDeadline) {
				t.Errorf("без срока: %v, нужен ErrDeadline", err)
			}
			bad := []string{
				"http://" + c.host + "/ok",
				foreign,
				"https://user@" + c.host + "/ok",
				"https://" + c.host + ":1/ok",
				"//" + c.host + "/ok",
			}
			for _, u := range bad {
				r := req("")
				r.URL = u
				if _, err := c.net.Get(ctx, r); !errors.Is(err, ErrURL) {
					t.Errorf("%s: %v, нужен ErrURL", u, err)
				}
			}
		})
	}
}

func TestListeningReal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("нет петли для теста:", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	on, err := New().Net().Listening(c, port)
	if err != nil || !on {
		t.Fatalf("слушаемый порт %d: %v %v", port, on, err)
	}
	ln.Close()
	on, err = New().Net().Listening(c, port)
	if err != nil || on {
		t.Fatalf("закрытый порт %d: %v %v", port, on, err)
	}
	if _, err := New().Net().Listening(c, 0); err == nil {
		t.Fatal("порт 0 принят")
	}
}

func TestScanListeningOnlyListenState(t *testing.T) {
	table := "  sl  local_address rem_address   st\n" +
		"   0: 00000000:01BB 00000000:0000 0A 0:0\n" + // 443 LISTEN
		"   1: 0100007F:1F90 0100007F:C350 01 0:0\n" // 8080 ESTABLISHED
	for port, want := range map[int]bool{443: true, 8080: false, 80: false} {
		got, err := scanListening(strings.NewReader(strings.ReplaceAll(table, "\\\n", "\n")), port)
		if err != nil || got != want {
			t.Errorf("порт %d: %v %v, ждали %v", port, got, err, want)
		}
	}
}

func TestFakeListeningAndSleep(t *testing.T) {
	f := NewFake(t.TempDir(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if on, _ := f.Net().Listening(c, 443); on {
		t.Fatal("по умолчанию порт не слушается")
	}
	f.SetListening(443, true)
	if on, _ := f.Net().Listening(c, 443); !on {
		t.Fatal("SetListening не подействовал")
	}
	if err := f.Clock().Sleep(c, 3*time.Second); err != nil || !f.Clock().Now().Equal(time.Date(2026, 1, 1, 0, 0, 3, 0, time.UTC)) {
		t.Fatalf("Sleep: %v %v", err, f.Clock().Now())
	}
}
