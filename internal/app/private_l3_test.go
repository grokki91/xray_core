//go:build l3

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/platform/xraytest"
	"github.com/grokki91/xray_core/internal/security"
	"github.com/grokki91/xray_core/internal/store"
)

// L3, задача A1 (ADR-0027): клиент VPN не достаёт службы самого сервера. Сервер Xray из
// состояния ↔ клиент Xray из состояния ↔ локальный слушатель на всех адресах машины. Запрос
// через тоннель к 127.0.0.1, к имени localhost и к частному адресу машины до слушателя не
// доходит, как и к 0.0.0.0 и ::1. Контроль: тот же сервер с правилом allow для петли перед запретом пропускает запрос —
// значит, тоннель работает и отказ дают finalRules. Без нашего правила тест не падает: freedom
// блокирует частные адреса и сам (docs/compatibility.md §2); что правило отрисовано, доказывает
// L2 TestRenderBlocksPrivateDestinations.
func TestL3PrivateDestinationsBlocked(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("архив Xray-linux-64 — только для хоста amd64")
	}
	for _, v := range xraytest.Versions() {
		t.Run(v, func(t *testing.T) {
			st := newEgressStand(t, v)
			r, svcPort, serve, run := st.cfg, st.svcPort, st.serve, st.run
			if !run(allowLoopback(t, r), net.JoinHostPort("127.0.0.1", svcPort)) {
				t.Fatal("контроль: с allow для петли запрос не дошёл — тоннель не работает")
			}
			// 0.0.0.0 на Linux ведёт на сам хост; ::1 — петля IPv6, если её слушает слушатель.
			targets := []string{
				net.JoinHostPort("127.0.0.1", svcPort), net.JoinHostPort("localhost", svcPort),
				net.JoinHostPort("0.0.0.0", svcPort),
			}
			if serve(net.JoinHostPort("::1", svcPort)) {
				targets = append(targets, net.JoinHostPort("::1", svcPort))
			} else {
				t.Log("петля IPv6 недоступна: случай ::1 не измерен")
			}
			if ip := privateAddr(); ip != "" && serve(net.JoinHostPort(ip, svcPort)) {
				targets = append(targets, net.JoinHostPort(ip, svcPort))
			} else {
				t.Log("у машины нет частного IPv4: случай частного адреса не измерен")
			}
			for _, target := range targets {
				if run(r, target) {
					t.Errorf("запрос через тоннель к %s дошёл до службы сервера", target)
				}
			}
		})
	}
}

// egressStand — стенд L3 запретов исходящего трафика: сервер Xray из состояния ↔ клиент Xray из
// состояния ↔ HTTP-слушатель на петле. run запускает сервер с конфигурацией cfg и клиента,
// отправляет запрос к target через тоннель и возвращает, дошло ли соединение до слушателя.
type egressStand struct {
	cfg     []byte                 // отрисованная конфигурация сервера
	svcPort string                 // порт слушателя на 127.0.0.1
	serve   func(addr string) bool // ещё один адрес того же слушателя
	run     func(cfg []byte, target string) bool
}

func newEgressStand(t *testing.T, v string) egressStand {
	t.Helper()
	get := func(ctx context.Context, url string, hosts []string) ([]byte, error) {
		return platform.New().Net().Get(ctx, platform.Request{URL: url, Hosts: hosts, Max: platform.MaxFileSize})
	}
	root := t.TempDir()
	if err := os.MkdirAll(root+"/usr/local/lib", 0o755); err != nil {
		t.Fatal(err)
	}
	f := platform.NewFake(root, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	f.RunUnderRoot("xray")
	cm := core.New(f)
	rc, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	t.Cleanup(cancel)
	if err := cm.Stage(rc, core.Version(v), xraytest.Archive(t, get, v)); err != nil {
		t.Fatal(err)
	}
	if err := cm.Activate(rc, core.Version(v)); err != nil {
		t.Fatal(err)
	}
	sec := security.New(f)
	keys, err := sec.NewRealityKeys(rc)
	if err != nil {
		t.Fatal(err)
	}

	// Служба самого сервера — на петле IPv4, а также на ::1 и частном адресе машины, если они
	// есть; не на всех адресах, чтобы не открывать порт наружу. Считает принятые соединения.
	var hits atomic.Int32
	svc := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				hits.Add(1)
			}
		}}
	t.Cleanup(func() { svc.Close() })
	serve := func(addr string) bool {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		go svc.Serve(ln)
		return true
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go svc.Serve(ln)
	svcPort := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	realityTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	realityTarget.EnableHTTP2 = true
	realityTarget.StartTLS()
	t.Cleanup(realityTarget.Close)

	srvPort := freeTCPPort(t)
	st := stateOf("phone")
	st.Inbounds[0].Reality.Target = realityTarget.Listener.Addr().String()
	st.Server = store.Server{Port: srvPort, Addresses: store.Addresses{IPv4: "127.0.0.1"}}
	st.Inbounds[0].Reality.PrivateKey, st.Inbounds[0].Reality.PublicKey = keys.Private, keys.Public

	cfgm := config.New(f)
	r, err := cfgm.Render(st, json.RawMessage(`{"loglevel":"none"}`))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "xm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := dir + "/client.sock"
	cr, err := cfgm.RenderClient(st, st.Profiles[0].ID, sock)
	if err != nil {
		t.Fatal(err)
	}
	client := func() *http.Client {
		// Прокси нужен ради абсолютного адреса в строке запроса: соединение всё равно идёт в
		// сокет клиента.
		proxy, _ := url.Parse("http://proxy.invalid")
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		}}
	}

	// run запускает сервер с конфигурацией cfg и клиента, отправляет запрос к target через
	// тоннель и возвращает, дошло ли соединение до слушателя.
	run := func(cfg []byte, target string) bool {
		t.Helper()
		srv, err := f.Start(rc, platform.Command{Program: "xray", Version: v, Args: []string{"run", "-c", "stdin:"}, Stdin: cfg})
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Stop()
		waitListening(t, rc, srvPort)
		os.Remove(sock)
		cl, err := cm.StartClient(rc, cr.Data)
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Stop()
		waitSocket(t, sock)
		before := hits.Load()
		resp, err := client().Get("http://" + target + "/")
		if err == nil {
			resp.Body.Close()
		}
		return hits.Load() > before
	}
	return egressStand{cfg: r.Data, svcPort: svcPort, serve: serve, run: run}
}

// allowLoopback вставляет перед запретом правило allow для 127.0.0.1 — только для контроля.
func allowLoopback(t *testing.T, cfg []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(cfg, &doc); err != nil {
		t.Fatal(err)
	}
	s := doc["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)
	s["finalRules"] = append([]any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}, s["finalRules"].([]any)...)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(out, cfg) {
		t.Fatal("контрольная конфигурация не изменилась")
	}
	return out
}

// privateAddr — частный IPv4 интерфейса машины или пустая строка.
func privateAddr() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
			return n.IP.String()
		}
	}
	return ""
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitListening(t *testing.T, ctx context.Context, port int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if on, _ := platform.New().Net().Listening(ctx, port); on {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(fmt.Sprintf("сервер Xray не начал слушать порт %d", port))
}

func waitSocket(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("клиент Xray не создал сокет")
}
