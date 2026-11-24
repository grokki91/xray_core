package platform

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func allowAll(netip.Addr) bool { return true }

// resolve — подставной резолвер: имя → адреса; IP-литерал — сам себя; иначе ошибка.
func resolve(m map[string][]string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{a}, nil
		}
		var out []netip.Addr
		for _, a := range m[host] {
			out = append(out, netip.MustParseAddr(a))
		}
		if out == nil {
			return nil, errors.New("имя не разрешено: " + host)
		}
		return out, nil
	}
}

func global(a netip.Addr) bool { return a.IsGlobalUnicast() && !a.IsPrivate() }

// Адрес не по Allow — ErrNotAllowed до соединения: сервер не видит ни одного подключения.
func TestTLSProbeNotAllowedNoDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	fake := newFake(t.TempDir(), time.Time{}, nil)
	fake.SetTLS("127.0.0.1", TLSInfo{Addr: netip.MustParseAddr("127.0.0.1")}, nil)
	fake.SetTLS("private.test", TLSInfo{Addr: netip.MustParseAddr("10.0.0.1")}, nil)
	realImpl := newReal(nil, http.DefaultTransport)
	realImpl.net.lookup = resolve(map[string][]string{"private.test": {"10.0.0.1", "127.0.0.1", "::1"}})
	real := realImpl.Net()
	for _, c := range []struct {
		name string
		n    Net
		host string
	}{{"real", real, "127.0.0.1"}, {"real", real, "private.test"}, {"fake", fake.Net(), "127.0.0.1"}, {"fake", fake.Net(), "private.test"}} {
		_, err := c.n.TLSProbe(deadline(t, 5*time.Second), TLSRequest{Host: c.host, Port: port, Allow: global})
		if !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s %s: %v, нужен ErrNotAllowed", c.name, c.host, err)
		}
	}
	for _, call := range fake.Calls() {
		if call.Op == "dial" {
			t.Errorf("подделка соединилась: %+v", call)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("настоящая реализация соединилась %d раз", n)
	}
}

// Сертификат доверен, но выдан на другое имя — CertErr.
func TestTLSProbeRealWrongName(t *testing.T) {
	port, roots := tlsServer(t)
	real := newReal(nil, http.DefaultTransport)
	real.net.roots = roots
	// Сертификат httptest — на example.com и 127.0.0.1; wrong.test ведёт на тот же сервер, но в сертификате его нет.
	real.net.lookup = resolve(map[string][]string{"wrong.test": {"127.0.0.1"}})
	got, err := real.Net().TLSProbe(deadline(t, 5*time.Second), TLSRequest{Host: "wrong.test", Port: port, Allow: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if got.CertErr == nil {
		t.Fatalf("сертификат на чужое имя принят: %+v", got)
	}
}

// tlsServer — локальный TLS-сервер с самоподписанным сертификатом на 127.0.0.1, ALPN h2.
func tlsServer(t *testing.T) (port int, roots *x509.CertPool) {
	port, roots, _ = tlsServerWith(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	return port, roots
}

// tlsServerWith — то же с обработчиком; conns — число принятых соединений.
func tlsServerWith(t *testing.T, h http.Handler) (port int, roots *x509.CertPool, conns *atomic.Int32) {
	srv := httptest.NewUnstartedServer(h)
	conns = new(atomic.Int32)
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ = strconv.Atoi(p)
	roots = x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return port, roots, conns
}

// Обе реализации отдают одинаковые сведения о рукопожатии и одинаково отвергают ввод.
func TestTLSProbeAgree(t *testing.T) {
	port, roots := tlsServer(t)
	real := newReal(nil, http.DefaultTransport)
	real.net.roots = roots
	fake := newFake(t.TempDir(), time.Time{}, nil)
	want := TLSInfo{Version: tls.VersionTLS13, ALPN: "h2", Curve: tls.X25519MLKEM768, Addr: netip.MustParseAddr("127.0.0.1"), Status: http.StatusOK}
	fake.SetTLS("127.0.0.1", want, nil)
	for name, n := range map[string]Net{"real": real.Net(), "fake": fake.Net()} {
		t.Run(name, func(t *testing.T) {
			ctx := deadline(t, 5*time.Second)
			got, err := n.TLSProbe(ctx, TLSRequest{Host: "127.0.0.1", Port: port, Allow: allowAll})
			if err != nil {
				t.Fatal(err)
			}
			if got.Version != want.Version || got.ALPN != want.ALPN || got.Curve != want.Curve || got.Addr != want.Addr || got.CertErr != nil ||
				got.Status != want.Status || got.HeadErr != nil {
				t.Fatalf("TLSProbe = %+v", got)
			}
			if _, err := n.TLSProbe(context.Background(), TLSRequest{Host: "127.0.0.1", Port: port, Allow: allowAll}); !errors.Is(err, ErrDeadline) {
				t.Errorf("без срока: %v, нужен ErrDeadline", err)
			}
			for _, r := range []TLSRequest{{Host: "a b", Port: 443, Allow: allowAll}, {Host: "", Port: 443, Allow: allowAll}, {Host: "x.test:1", Port: 443, Allow: allowAll}, {Host: "x.test", Port: 0, Allow: allowAll}, {Host: "x.test", Port: 443}} {
				if _, err := n.TLSProbe(ctx, r); !errors.Is(err, ErrURL) {
					t.Errorf("%+v: %v, нужен ErrURL", r, err)
				}
			}
		})
	}
}

// Сертификат не из пула доверия — сведения о рукопожатии есть, ошибка проверки в CertErr.
func TestTLSProbeRealUntrusted(t *testing.T) {
	port, _ := tlsServer(t)
	real := newReal(nil, http.DefaultTransport)
	real.net.roots = x509.NewCertPool()
	got, err := real.Net().TLSProbe(deadline(t, 5*time.Second), TLSRequest{Host: "127.0.0.1", Port: port, Allow: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if got.CertErr == nil || got.Version != tls.VersionTLS13 || got.Handshake <= 0 {
		t.Fatalf("TLSProbe = %+v", got)
	}
}

func TestFakeTLSUnknownHost(t *testing.T) {
	f := newFake(t.TempDir(), time.Time{}, nil)
	if _, err := f.Net().TLSProbe(deadline(t, time.Second), TLSRequest{Host: "x.test", Port: 443, Allow: allowAll}); err == nil {
		t.Fatal("неизвестный узел подделки: соединение без ошибки")
	}
	if c := f.Calls(); len(c) != 1 || c[0].Op != "tls" {
		t.Fatalf("Calls = %+v", c)
	}
}

// HEAD / по тому же соединению: код и Location первого ответа, без перехода.
func TestTLSProbeRealHead(t *testing.T) {
	for _, c := range []struct {
		status   int
		location string
	}{{200, ""}, {301, "https://127.0.0.1/a"}, {301, "https://other.test/"}, {301, "http://127.0.0.1/"}} {
		var method, host string
		port, roots, conns := tlsServerWith(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method, host = r.Method+" "+r.URL.Path+" "+r.Proto, r.Host
			if _, ok := r.Header["User-Agent"]; ok {
				method = "User-Agent: " + r.UserAgent()
			}
			if c.location != "" {
				w.Header().Set("Location", c.location)
			}
			w.WriteHeader(c.status)
		}))
		real := newReal(nil, http.DefaultTransport)
		real.net.roots = roots
		got, err := real.Net().TLSProbe(deadline(t, 5*time.Second), TLSRequest{Host: "127.0.0.1", Port: port, Allow: allowAll})
		if err != nil || got.HeadErr != nil || got.Status != c.status || got.Location != c.location {
			t.Fatalf("%d %s: %+v, %v", c.status, c.location, got, err)
		}
		if method != "HEAD / HTTP/2.0" || host != "127.0.0.1" {
			t.Fatalf("запрос %q, Host %q", method, host)
		}
		if n := conns.Load(); n != 1 {
			t.Fatalf("%d %s: сервер принял %d соединений, нужно одно", c.status, c.location, n)
		}
	}
}
