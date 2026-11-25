package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/store"
)

const (
	fakeKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	logPart  = `{"access":"none","loglevel":"warning"}`
	idPhone  = "00000000-0000-4000-8000-000000000001"
	idLaptop = "00000000-0000-4000-8000-000000000002"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	return c
}

// state — состояние с фиктивными данными (docs/security/secrets.md §4).
func state() store.State {
	return store.State{
		SchemaVersion: store.SchemaVersion,
		Server:        store.Server{Port: 443},
		Inbounds: []store.Inbound{{
			Preset: "reality-xhttp",
			Reality: store.Reality{
				Target: "example.com:443", ServerNames: []string{"example.com"},
				PrivateKey: fakeKey, PublicKey: fakeKey, ShortIDs: []string{"0123456789abcdef"},
			},
			Params: map[string]string{"path": "/example"},
		}},
		Profiles: []store.Profile{
			{Name: "phone", ID: idPhone, Enabled: true},
			{Name: "laptop", ID: idLaptop, Enabled: false},
		},
	}
}

func render(t *testing.T, st store.State) Rendered {
	t.Helper()
	r, err := New(nil).Render(st, json.RawMessage(logPart))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRenderIsDeterministic(t *testing.T) {
	a, b := render(t, state()), render(t, state())
	if !bytes.Equal(a.Data, b.Data) || a.SHA256 != b.SHA256 {
		t.Fatal("одно состояние дало разные файлы")
	}
}

func TestRenderMatchesGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/config.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := render(t, state()).Data; !bytes.Equal(got, want) {
		t.Fatalf("конфигурация расходится с эталоном:\n%s", got)
	}
}

func TestRenderOnlyEnabledProfiles(t *testing.T) {
	out := string(render(t, state()).Data)
	if !strings.Contains(out, idPhone) || strings.Contains(out, idLaptop) {
		t.Fatalf("клиенты в конфигурации не совпали с включёнными профилями:\n%s", out)
	}
}

func TestRenderNoProfilesIsValidDocument(t *testing.T) {
	st := state()
	st.Profiles = nil
	var doc struct {
		Inbounds []struct {
			Settings struct {
				Clients []json.RawMessage `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(render(t, st).Data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Inbounds[0].Settings.Clients == nil || len(doc.Inbounds[0].Settings.Clients) != 0 {
		t.Fatal("без профилей нужен пустой список clients, не null")
	}
}

func TestRenderBlocksPrivateDestinations(t *testing.T) {
	// ADR-0027: запрет — finalRules исходящего freedom; freedom — первым, он получает всё, что не
	// поймали правила маршрутизации.
	var doc struct {
		Outbounds []struct {
			Tag, Protocol string
			Settings      struct {
				FinalRules []struct {
					Action string
					IP     []string
				}
			}
		}
	}
	if err := json.Unmarshal(render(t, state()).Data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Outbounds) == 0 || doc.Outbounds[0].Protocol != "freedom" {
		t.Fatalf("outbounds: %+v", doc.Outbounds)
	}
	have := map[string]bool{}
	for _, r := range doc.Outbounds[0].Settings.FinalRules {
		if r.Action == "block" {
			for _, c := range r.IP {
				have[c] = true
			}
		}
	}
	for _, c := range []string{"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "::/128", "::1/128", "fc00::/7", "fe80::/10"} {
		if !have[c] {
			t.Errorf("в запрете нет %s", c)
		}
	}
}

// ADR-0038, A8: порт 25 любого адреса — finalRules freedom тем же механизмом, что частные адреса;
// BitTorrent — правилом protocol в blackhole, для чего у входящего sniffing только для
// маршрутизации: адрес назначения не подменяется.
func TestRenderRestrictsClientEgress(t *testing.T) {
	var doc struct {
		Inbounds []struct {
			Sniffing *struct {
				Enabled, RouteOnly, MetadataOnly bool
			}
		}
		Outbounds []struct {
			Tag, Protocol string
			Settings      struct {
				FinalRules []struct {
					Action, Network, Port string
					IP                    []string
				}
			}
		}
		Routing *struct {
			Rules []struct {
				Protocol    []string
				OutboundTag string
			}
		}
	}
	if err := json.Unmarshal(render(t, state()).Data, &doc); err != nil {
		t.Fatal(err)
	}
	port25 := false
	for _, r := range doc.Outbounds[0].Settings.FinalRules {
		if r.Action == "block" && r.Port == "25" && r.Network == "tcp" && len(r.IP) == 0 {
			port25 = true
		}
	}
	if !port25 {
		t.Errorf("в finalRules нет запрета tcp:25: %+v", doc.Outbounds[0].Settings.FinalRules)
	}
	if sn := doc.Inbounds[0].Sniffing; sn == nil || !sn.Enabled || !sn.RouteOnly || sn.MetadataOnly {
		t.Errorf("sniffing: %+v", sn)
	}
	blackhole := map[string]bool{}
	for _, o := range doc.Outbounds {
		if o.Protocol == "blackhole" {
			blackhole[o.Tag] = true
		}
	}
	torrent := false
	if doc.Routing != nil {
		for _, r := range doc.Routing.Rules {
			if len(r.Protocol) == 1 && r.Protocol[0] == "bittorrent" && blackhole[r.OutboundTag] {
				torrent = true
			}
		}
	}
	if !torrent {
		t.Errorf("нет правила bittorrent → blackhole: %+v", doc.Routing)
	}
}

func TestRenderDNSFromState(t *testing.T) {
	if strings.Contains(string(render(t, state()).Data), `"dns"`) {
		t.Fatal("раздел dns есть при пустом состоянии")
	}
	for _, s := range []string{`"port": "53"`, `"protocol": "dns"`} {
		if strings.Contains(string(render(t, state()).Data), s) {
			t.Fatalf("%s есть без раздела dns", s)
		}
	}
	want, err := os.ReadFile("testdata/config-dns.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := render(t, dnsState()).Data; !bytes.Equal(got, want) {
		t.Fatalf("конфигурация с dns расходится с эталоном:\n%s", got)
	}
}

// dnsState — состояние с разделом dns, как его строит dns.Plan.
func dnsState() store.State {
	st := state()
	st.DNS = store.DNS{DoH: []string{"https://1.1.1.1/dns-query", "https://dns.quad9.net/dns-query"}, Strategy: "UseIPv4"}
	return st
}

func TestRenderRejectsBadState(t *testing.T) {
	cases := map[string]func(*store.State){
		"нет входящих":       func(s *store.State) { s.Inbounds = nil },
		"два входящих":       func(s *store.State) { s.Inbounds = append(s.Inbounds, s.Inbounds[0]) },
		"неизвестный пресет": func(s *store.State) { s.Inbounds[0].Preset = "nope" },
		"плохой порт":        func(s *store.State) { s.Server.Port = 0 },
		"плохой ключ":        func(s *store.State) { s.Inbounds[0].Reality.PrivateKey = "short" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			st := state()
			mut(&st)
			_, err := New(nil).Render(st, json.RawMessage(logPart))
			if err == nil {
				t.Fatal("принято")
			}
			if !errorsIs(err, ErrState) {
				t.Fatalf("ошибка не ErrState: %v", err)
			}
			if strings.Contains(err.Error(), fakeKey) || strings.Contains(err.Error(), "short") {
				t.Fatalf("в ошибке значение секрета: %v", err)
			}
		})
	}
	if _, err := New(nil).Render(state(), json.RawMessage(`{`)); err == nil {
		t.Fatal("раздел log не JSON принят")
	}
}

func fake(t *testing.T) *platform.Fake {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(root+"/usr/local/etc/xray", 0o750); err != nil {
		t.Fatal(err)
	}
	return platform.NewFake(root, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
}

func TestWriteSetsManifestPerms(t *testing.T) {
	f := fake(t)
	m := New(f)
	r := render(t, state())
	if err := m.Write(ctx(t), r); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(f.Path(Path))
	if err != nil || !bytes.Equal(got, r.Data) {
		t.Fatalf("содержимое: %v", err)
	}
	fi, _ := os.Stat(f.Path(Path))
	svc, _ := f.Users().Ensure(ctx(t), platform.ServiceUser)
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("права %v, нужны 0640", fi.Mode().Perm())
	}
	if o, ok := f.Owner(Path); !ok || o != (platform.Owner{GID: svc.GID}) {
		t.Errorf("владелец %v, нужен root:xray", o)
	}
}

func TestDrift(t *testing.T) {
	f := fake(t)
	m := New(f)
	st := state()
	if d, err := m.Drift(st); err != nil || d {
		t.Fatalf("нет файла и нет суммы: дрейф %v, %v", d, err)
	}
	r := render(t, st)
	if err := m.Write(ctx(t), r); err != nil {
		t.Fatal(err)
	}
	if d, _ := m.Drift(st); !d {
		t.Fatal("файл есть, суммы нет — нужен дрейф")
	}
	st.Applied.ConfigSHA256 = r.SHA256
	if d, err := m.Drift(st); err != nil || d {
		t.Fatalf("файл как применён: дрейф %v, %v", d, err)
	}
	if err := os.WriteFile(f.Path(Path), []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if d, _ := m.Drift(st); !d {
		t.Fatal("ручная правка не замечена")
	}
	if err := os.Remove(f.Path(Path)); err != nil {
		t.Fatal(err)
	}
	if d, _ := m.Drift(st); !d {
		t.Fatal("файл удалён, сумма есть — нужен дрейф")
	}
}

func TestStageUnstageRemove(t *testing.T) {
	f := platform.NewFake(t.TempDir(), time.Time{})
	for _, d := range []string{"/var", "/var/lib", "/var/lib/xm", "/var/lib/xm/tx", "/usr", "/usr/local", "/usr/local/etc", "/usr/local/etc/xray"} {
		if err := f.FS().Mkdir(d, 0o700, platform.Root()); err != nil {
			t.Fatal(err)
		}
	}
	m := New(f)
	p, err := m.Stage(Rendered{Data: []byte("{}")})
	if err != nil || p != CandidatePath {
		t.Fatalf("%q %v", p, err)
	}
	if info, err := os.Stat(f.Path(p)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("права кандидата: %v %v", info, err)
	}
	if err := m.Unstage(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.FS().ReadFile(p); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("кандидат не удалён: %v", err)
	}
	if err := m.Unstage(); err != nil {
		t.Fatalf("повторное удаление: %v", err)
	}
	if err := m.Remove(); err != nil {
		t.Fatalf("Remove без файла: %v", err)
	}
}

const idSelftest = "00000000-0000-4000-8000-0000000000aa"

// Служебный клиент — в клиентах сервера, даже когда профилей нет; пустой id — клиента нет.
func TestRenderIncludesSelftestClient(t *testing.T) {
	st := state()
	st.Selftest.ID = idSelftest
	out := string(render(t, st).Data)
	if !strings.Contains(out, idSelftest) || !strings.Contains(out, idPhone) {
		t.Fatalf("служебный клиент и профиль должны быть в clients:\n%s", out)
	}
	st.Profiles = nil
	if !strings.Contains(string(render(t, st).Data), idSelftest) {
		t.Fatal("без профилей служебного клиента нет")
	}
}

func clientState() store.State {
	st := state()
	st.Server.Addresses = store.Addresses{IPv4: "203.0.113.10", IPv6: "2001:db8::10"}
	st.Selftest.ID = idSelftest
	return st
}

func TestRenderClientMatchesGolden(t *testing.T) {
	r, err := New(nil).RenderClient(clientState(), idSelftest, "/run/xm/selftest.sock")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/client.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Data, want) {
		t.Fatalf("клиент расходится с эталоном:\n%s", r.Data)
	}
	again, _ := New(nil).RenderClient(clientState(), idSelftest, "/run/xm/selftest.sock")
	if again.SHA256 != r.SHA256 {
		t.Fatal("одно состояние дало разные файлы")
	}
}

// Адрес сервера — первый из порядка «домен, IPv4, IPv6», как у ссылки по умолчанию.
func TestRenderClientAddressOrder(t *testing.T) {
	st := clientState()
	st.Server.Addresses = store.Addresses{IPv6: "2001:db8::10"}
	r, err := New(nil).RenderClient(st, idSelftest, "/run/xm/selftest.sock")
	if err != nil || !strings.Contains(string(r.Data), `"address": "2001:db8::10"`) {
		t.Fatalf("только IPv6: %v\n%s", err, r.Data)
	}
	st.Server.Addresses = store.Addresses{IPv4: "203.0.113.10", Domain: "vpn.example.com"}
	r, err = New(nil).RenderClient(st, idSelftest, "/run/xm/selftest.sock")
	if err != nil || !strings.Contains(string(r.Data), `"address": "vpn.example.com"`) {
		t.Fatalf("домен первый: %v\n%s", err, r.Data)
	}
}

func TestRenderClientRejects(t *testing.T) {
	for name, c := range map[string]struct {
		mut      func(*store.State)
		id, sock string
	}{
		"id пуст":         {func(*store.State) {}, "", "/run/xm/s.sock"},
		"id не UUID":      {func(*store.State) {}, "x", "/run/xm/s.sock"},
		"сокет относит.":  {func(*store.State) {}, idSelftest, "s.sock"},
		"сокет не очищ.":  {func(*store.State) {}, idSelftest, "/run/xm/../s.sock"},
		"сокет с запятой": {func(*store.State) {}, idSelftest, "/run/xm/s.sock,0777"},
		"нет адреса":      {func(s *store.State) { s.Server.Addresses = store.Addresses{} }, idSelftest, "/run/xm/s.sock"},
		"нет входящего":   {func(s *store.State) { s.Inbounds = nil }, idSelftest, "/run/xm/s.sock"},
	} {
		st := clientState()
		c.mut(&st)
		if _, err := New(nil).RenderClient(st, c.id, c.sock); !errorsIs(err, ErrState) {
			t.Errorf("%s: %v, нужна ErrState", name, err)
		}
	}
}
