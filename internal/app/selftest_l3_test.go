//go:build l3

package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/diag"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/platform/xraytest"
	"github.com/grokki91/xray_core/internal/profile"
	"github.com/grokki91/xray_core/internal/security"
	"github.com/grokki91/xray_core/internal/store"
)

// l3Host — платформа проверки на настоящих файлах, сети и часах: сокет клиента лежит во
// временном каталоге, а не под корнем подделки.
type l3Host struct{ p *platform.Real }

func (h l3Host) FS() platform.FS       { return h.p.FS() }
func (h l3Host) Net() platform.Net     { return h.p.Net() }
func (h l3Host) Clock() platform.Clock { return h.p.Clock() }

type activeService struct{}

func (activeService) Status(context.Context) (platform.UnitStatus, error) {
	return platform.UnitStatus{Loaded: true, Active: "active", Sub: "running"}, nil
}

// L3 (ADR-0032): сервер Xray из состояния ↔ клиент Xray из состояния ↔ тестовый адрес, на
// настоящем Xray каждой границы диапазона (сверка ссылки с клиентом — link_client_test.go);
// удалённый профиль перестаёт подключаться; клиент, убитый до уборки сокета, не мешает
// следующему запуску. Тестовый адрес недоступен с машины — тест пропускается: он такой же
// «не измерено», как у самой проверки.
func TestL3SelftestEndToEnd(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("архив Xray-linux-64 — только для хоста amd64")
	}
	get := func(ctx context.Context, url string, hosts []string) ([]byte, error) {
		return platform.New().Net().Get(ctx, platform.Request{URL: url, Hosts: hosts, Max: platform.MaxFileSize})
	}
	for _, v := range xraytest.Versions() {
		t.Run(v, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(root+"/usr/local/lib", 0o755); err != nil {
				t.Fatal(err)
			}
			f := platform.NewFake(root, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			f.RunUnderRoot("xray")
			cm := core.New(f)
			rc, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
			defer cancel()
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
			selftestID, err := sec.NewClientID()
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			freePort := ln.Addr().(*net.TCPAddr).Port
			ln.Close()

			// Цель REALITY — локальный TLS 1.3 сервер: сервер Xray обращается к цели при каждом
			// подключении, и стенд не должен зависеть от внешнего сайта.
			realityTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			realityTarget.EnableHTTP2 = true
			realityTarget.StartTLS()
			t.Cleanup(realityTarget.Close)

			st := stateOf("phone")
			st.Inbounds[0].Reality.Target = realityTarget.Listener.Addr().String()
			st.Server = store.Server{Port: freePort, Addresses: store.Addresses{IPv4: "127.0.0.1"}}
			st.Inbounds[0].Reality.PrivateKey, st.Inbounds[0].Reality.PublicKey = keys.Private, keys.Public
			st.Selftest.ID = selftestID

			dir, err := os.MkdirTemp("", "xm")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			sock := dir + "/selftest.sock"

			cfgm := config.New(f)
			var srv platform.Process
			startServer := func(st store.State) {
				t.Helper()
				if srv != nil {
					srv.Stop()
				}
				r, err := cfgm.Render(st, json.RawMessage(`{"loglevel":"none"}`))
				if err != nil {
					t.Fatal(err)
				}
				if srv, err = f.Start(rc, platform.Command{Program: "xray", Version: v, Args: []string{"run", "-c", "stdin:"}, Stdin: r.Data}); err != nil {
					t.Fatal(err)
				}
				real := platform.New()
				for i := 0; ; i++ {
					if on, _ := real.Net().Listening(rc, freePort); on {
						return
					}
					select {
					case <-srv.Done():
						t.Fatal("сервер Xray завершился при запуске")
					default:
					}
					if i > 100 {
						t.Fatal("сервер Xray не начал слушать порт")
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			startServer(st)
			t.Cleanup(func() { srv.Stop() })

			// check — проверка reach.selftest движка diag клиентом с идентификатором id.
			check := func(st store.State, id string) diag.Observation {
				t.Helper()
				e, err := diag.NewControl(diag.ControlDeps{
					Service: activeService{}, Net: platform.New().Net(),
					Port:     func(context.Context) (int, error) { return freePort, nil },
					Validate: func(context.Context) (bool, error) { return true, nil },
					Selftest: diag.SelftestDeps{Host: l3Host{platform.New()}, Socket: sock, Start: func(ctx context.Context) (diag.Process, error) {
						r, err := cfgm.RenderClient(st, id, sock)
						if err != nil {
							return nil, err
						}
						p, err := cm.StartClient(ctx, r.Data)
						if err != nil {
							return nil, err
						}
						return p, nil
					}},
				})
				if err != nil {
					t.Fatal(err)
				}
				cc, cancel := context.WithTimeout(rc, time.Minute)
				defer cancel()
				rep, err := e.Run(cc, diag.SetControl)
				if err != nil {
					t.Fatal(err)
				}
				for _, o := range rep.Observations {
					if o.Check == diag.CheckSelftest {
						return o
					}
				}
				t.Fatal("в отчёте нет reach.selftest")
				return diag.Observation{}
			}

			o := check(st, selftestID)
			if o.Status == diag.StatusSkip {
				t.Skipf("самопроверка не измерена на этой машине: %s", o.Reason)
			}
			if o.Status != diag.StatusOK {
				t.Fatalf("служебный клиент: %+v", o)
			}
			if _, err := os.Lstat(sock); !os.IsNotExist(err) {
				t.Errorf("сокет клиента остался после проверки: %v", err)
			}
			// Повторный запуск после убитого клиента: прежний сокет и .lock не мешают.
			if o := check(st, selftestID); o.Status != diag.StatusOK {
				t.Fatalf("повторная самопроверка: %+v", o)
			}

			// Клиент с данными профиля подключается; после удаления профиля — нет.
			if o := check(st, st.Profiles[0].ID); o.Status != diag.StatusOK {
				t.Fatalf("клиент профиля: %+v", o)
			}
			gone, err := profile.New().Remove(st, "phone")
			if err != nil {
				t.Fatal(err)
			}
			startServer(gone)
			if o := check(gone, st.Profiles[0].ID); o.Status != diag.StatusFail {
				t.Fatalf("удалённый профиль подключился: %+v", o)
			}
			if o := check(gone, selftestID); o.Status != diag.StatusOK {
				t.Fatalf("служебный клиент после удаления профиля: %+v", o)
			}
		})
	}
}
