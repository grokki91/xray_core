package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// netCase — реализация сети и адрес её «своего» узла, на котором заданы ответы:
// /ok — тело, /hop — перенаправление на /ok, /out — перенаправление на чужой узел,
// /loop — перенаправление на себя, /chainN — цепочка из N перенаправлений до /ok;
// у настоящей: /auth — заголовок Authorization запроса, /authhop — перенаправление на /auth.
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
		case "/auth":
			w.Write([]byte(r.Header.Get("Authorization")))
		case "/authhop":
			http.Redirect(w, r, "/auth", http.StatusFound)
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
		got, err := scanListening(strings.NewReader(table), port)
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

// Токен уходит заголовком Bearer только в первый запрос: в перенаправление, даже на тот же узел,
// — нет. Подделка отмечает, был ли токен у загрузки.
func TestNetToken(t *testing.T) {
	cases := netCases(t)
	c := cases[0]
	ctx := deadline(t, 5*time.Second)
	get := func(path, token string) string {
		t.Helper()
		got, err := c.net.Get(ctx, Request{URL: c.base + path, Hosts: []string{c.host}, Max: 1 << 10, Token: token})
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return string(got)
	}
	if got := get("/auth", "tok_1"); got != "Bearer tok_1" {
		t.Errorf("первый запрос: заголовок %q", got)
	}
	if got := get("/authhop", "tok_1"); got != "" {
		t.Errorf("перенаправление: заголовок %q, нужен пустой", got)
	}
	if got := get("/auth", ""); got != "" {
		t.Errorf("без токена: заголовок %q", got)
	}

	fake := newFake(t.TempDir(), time.Time{}, nil)
	fake.Serve("https://own.test/ok", netBody)
	for _, token := range []string{"tok_1", ""} {
		if _, err := fake.Net().Get(ctx, Request{URL: "https://own.test/ok", Hosts: []string{"own.test"}, Max: 1 << 10, Token: token}); err != nil {
			t.Fatal(err)
		}
	}
	calls := fake.Calls()
	if len(calls) != 2 || !calls[0].Auth || calls[1].Auth {
		t.Errorf("подделка: %+v", calls)
	}
}

// connectProxy — HTTP-прокси на сокете Unix: туннелирует CONNECT и считает их.
func connectProxy(t *testing.T) (socket string, connects *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("", "xm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket = dir + "/p.sock"
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	connects = new(atomic.Int32)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "только CONNECT", http.StatusMethodNotAllowed)
			return
		}
		connects.Add(1)
		dst, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		src, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			dst.Close()
			return
		}
		go func() { io.Copy(dst, src); dst.Close() }()
		io.Copy(src, dst)
		src.Close()
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return socket, connects
}

// Proxy ведёт запрос через HTTP-прокси на сокете Unix (окружение не действует), а ожидаемый код
// ответа — не только 200: цель самопроверки отвечает 204 без тела.
func TestNetProxyAndStatus(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1") // окружение с Proxy не действует
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte("тело"))
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "https://")
	real := newReal(nil, srv.Client().Transport).Net()
	socket, connects := connectProxy(t)
	ctx := deadline(t, 5*time.Second)
	get := func(path string, status int, proxy string) ([]byte, error) {
		return real.Get(ctx, Request{URL: srv.URL + path, Hosts: []string{host}, Max: 1 << 10, Proxy: proxy, Status: status})
	}

	if got, err := get("/204", 204, socket); err != nil || len(got) != 0 {
		t.Errorf("204 при ожидании 204: %q, %v", got, err)
	}
	if connects.Load() != 1 {
		t.Errorf("запрос не прошёл через прокси: CONNECT %d", connects.Load())
	}
	if got, err := get("/ok", 0, socket); err != nil || string(got) != "тело" {
		t.Errorf("код по умолчанию 200: %q, %v", got, err)
	}
	if _, err := get("/204", 0, socket); err == nil {
		t.Error("204 принят при ожидании 200")
	}
	if _, err := get("/ok", 204, socket); err == nil {
		t.Error("200 принят при ожидании 204")
	}
	if _, err := get("/ok", 0, "p.sock"); !errors.Is(err, ErrPath) {
		t.Errorf("относительный сокет: %v, нужно ErrPath", err)
	}
	if _, err := get("/ok", 0, "/run/xm/../x.sock"); !errors.Is(err, ErrPath) {
		t.Errorf("неочищенный сокет: %v, нужно ErrPath", err)
	}
	if _, err := get("/ok", 0, filepath.Dir(socket)+"/нет.sock"); err == nil {
		t.Error("сокета нет, а запрос прошёл")
	}

	// Подделка: те же предусловия, код ответа и запись Proxy в вызове.
	fake := newFake(t.TempDir(), time.Time{}, nil)
	fake.ServeStatus("https://own.test/204", 204, nil)
	fake.Serve("https://own.test/ok", netBody)
	fg := func(path string, status int, proxy string) ([]byte, error) {
		return fake.Net().Get(ctx, Request{URL: "https://own.test" + path, Hosts: []string{"own.test"}, Max: 1 << 10, Proxy: proxy, Status: status})
	}
	if got, err := fg("/204", 204, "/run/xm/selftest.sock"); err != nil || len(got) != 0 {
		t.Errorf("подделка 204: %q, %v", got, err)
	}
	if _, err := fg("/ok", 204, "/run/xm/selftest.sock"); err == nil {
		t.Error("подделка: 200 принят при ожидании 204")
	}
	if _, err := fg("/204", 0, "/run/xm/selftest.sock"); err == nil {
		t.Error("подделка: 204 принят при ожидании 200")
	}
	if _, err := fg("/ok", 0, "p.sock"); !errors.Is(err, ErrPath) {
		t.Errorf("подделка, относительный сокет: %v, нужно ErrPath", err)
	}
	if calls := fake.Calls(); len(calls) == 0 || calls[0].Proxy != "/run/xm/selftest.sock" {
		t.Errorf("Proxy не записан в вызове: %+v", calls)
	}
}
