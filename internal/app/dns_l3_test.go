//go:build l3

package app

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/dns"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/platform/xraytest"
	"github.com/grokki91/xray_core/internal/security"
	"github.com/grokki91/xray_core/internal/store"
)

// L3: DNS-запрос клиента через тоннель к адресу назначения на порту DNS попадает во встроенный
// DNS, а не на этот адрес. Слушатель DNS на петле считает соединения: ни запрос A, ни TXT до него
// не доходят; A получает ответ встроенного DNS, TXT — REFUSED (rCode 5). Ответ A берётся из
// dns.hosts, добавленного в тестовую конфигурацию: так тест не зависит от доступности DoH.
// Порт 53 недоступен — слушатель на свободном порту, и в тестовой конфигурации меняется только
// порт правила routing: проверяется то же правило и тот же исходящий dns. Что отрисованы именно
// эти правила, доказывает L2 TestRenderDNSFromState (эталон).
func TestL3ClientDNSHijacked(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("архив Xray-linux-64 — только для хоста amd64")
	}
	get := func(ctx context.Context, url string, hosts []string) ([]byte, error) {
		return platform.New().Net().Get(ctx, platform.Request{URL: url, Hosts: hosts, Max: platform.MaxFileSize})
	}
	// Слушатель на месте «чужого» DNS-сервера: принял соединение — запрос утёк мимо встроенного DNS.
	var hits atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:53")
	if err != nil {
		t.Logf("порт 53 недоступен (%v): слушатель и правило routing — на свободном порту", err)
		if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	dnsPort := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	for _, v := range xraytest.Versions() {
		t.Run(v, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(root+"/usr/local/lib", 0o755); err != nil {
				t.Fatal(err)
			}
			f := platform.NewFake(root, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			f.RunUnderRoot("xray")
			cm := core.New(f)
			rc, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
			defer cancel()
			if err := cm.Stage(rc, core.Version(v), xraytest.Archive(t, get, v)); err != nil {
				t.Fatal(err)
			}
			if err := cm.Activate(rc, core.Version(v)); err != nil {
				t.Fatal(err)
			}
			keys, err := security.New(f).NewRealityKeys(rc)
			if err != nil {
				t.Fatal(err)
			}
			realityTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			realityTarget.EnableHTTP2 = true
			realityTarget.StartTLS()
			t.Cleanup(realityTarget.Close)

			srvPort := freeTCPPort(t)
			st := stateOf("phone")
			st.Inbounds[0].Reality.Target = realityTarget.Listener.Addr().String()
			st.Server = store.Server{Port: srvPort, Addresses: store.Addresses{IPv4: "127.0.0.1"}}
			st.Inbounds[0].Reality.PrivateKey, st.Inbounds[0].Reality.PublicKey = keys.Private, keys.Public
			st.DNS = dns.Plan(dns.NetFacts{IPv4: true})

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

			srv, err := f.Start(rc, platform.Command{Program: "xray", Version: v, Args: []string{"run", "-c", "stdin:"}, Stdin: testDNSConfig(t, r.Data, dnsPort)})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Stop()
			waitListening(t, rc, srvPort)
			cl, err := cm.StartClient(rc, cr.Data)
			if err != nil {
				t.Fatal(err)
			}
			defer cl.Stop()
			waitSocket(t, sock)

			target := net.JoinHostPort("127.0.0.1", dnsPort)
			a := queryViaTunnel(t, sock, target, 1)
			if rcode(a) != 0 || !strings.Contains(string(a), string([]byte{192, 0, 2, 1})) {
				t.Errorf("A: нет ответа встроенного DNS (rCode %d)", rcode(a))
			}
			if txt := queryViaTunnel(t, sock, target, 16); rcode(txt) != 5 {
				t.Errorf("TXT: rCode %d, нужен 5 (REFUSED)", rcode(txt))
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("до слушателя %s дошло соединений: %d", target, n)
			}
		})
	}
}

// testDNSConfig добавляет dns.hosts для имени теста и, если слушатель не на 53, переносит
// порт правила routing на его порт. Остальное — как отрисовал config.
func testDNSConfig(t *testing.T, cfg []byte, port string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(cfg, &doc); err != nil {
		t.Fatal(err)
	}
	doc["dns"].(map[string]any)["hosts"] = map[string]any{"xm.test": "192.0.2.1"}
	rule := doc["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["port"] != "53" {
		t.Fatalf("правило routing: порт %v, нужен 53", rule["port"])
	}
	rule["port"] = port
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// queryViaTunnel отправляет запрос DNS по TCP (RFC 1035 §4.2.2) к target через HTTP CONNECT
// клиента Xray и возвращает ответ.
func queryViaTunnel(t *testing.T, sock, target string, qtype uint16) []byte {
	t.Helper()
	c, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 2, 'x', 'm', 4, 't', 'e', 's', 't', 0}
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = append(q, 0, 1)
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := c.Write(append(msg, q...)); err != nil {
		t.Fatal(err)
	}
	var n uint16
	if err := binary.Read(br, binary.BigEndian, &n); err != nil {
		t.Fatalf("ответ DNS (тип %d): %v", qtype, err)
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(br, out); err != nil || n < 12 {
		t.Fatalf("ответ DNS (тип %d): %v", qtype, err)
	}
	return out
}

func rcode(m []byte) int { return int(m[3] & 0x0f) }
