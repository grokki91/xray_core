package profile

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/store"
)

// shareState — состояние с профилем phone и тремя адресами; значения фиктивные.
func shareState() store.State {
	return store.State{
		SchemaVersion: store.SchemaVersion,
		Server: store.Server{
			Addresses: store.Addresses{IPv4: "192.0.2.10", IPv6: "2001:db8::10", Domain: "vpn.example.com"},
			Port:      8443,
		},
		Inbounds: []store.Inbound{{
			Preset: "reality-xhttp",
			Reality: store.Reality{
				ServerNames: []string{"www.example.com"}, PublicKey: strings.Repeat("A", 43),
				ShortIDs: []string{"0123456789abcdef"},
			},
			Params: map[string]string{"path": "/x"},
		}},
		Profiles: []store.Profile{{Name: "phone", ID: id(1), Enabled: true}},
		Core:     store.Core{Version: "26.11.9"},
	}
}

// Ссылка на каждый адрес сервера в порядке «домен, IPv4, IPv6»; QR — для первого; параметры
// ссылки берутся из состояния.
func TestShareLinksAndQR(t *testing.T) {
	sh, err := New().Share(shareState(), "phone", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var addrs []string
	for _, l := range sh.Links {
		addrs = append(addrs, l.Address)
	}
	if strings.Join(addrs, " ") != "vpn.example.com 192.0.2.10 2001:db8::10" {
		t.Fatalf("адреса %v", addrs)
	}
	u, err := url.Parse(sh.Links[2].URI)
	if err != nil || u.Host != "[2001:db8::10]:8443" || u.User.Username() != id(1) {
		t.Fatalf("ссылка IPv6: %q, %v", sh.Links[2].URI, err)
	}
	q := u.Query()
	if q.Get("sni") != "www.example.com" || q.Get("sid") != "0123456789abcdef" || q.Get("path") != "/x" || u.Fragment != "phone" {
		t.Fatalf("параметры: %q", sh.Links[2].URI)
	}
	if sh.QRAddress != "vpn.example.com" || sh.QR == "" {
		t.Fatalf("QR для %q", sh.QRAddress)
	}
}

func TestShareQRAddress(t *testing.T) {
	m := New()
	a, err := m.Share(shareState(), "phone", "", "192.0.2.10")
	if err != nil || a.QRAddress != "192.0.2.10" {
		t.Fatalf("QR для %q: %v", a.QRAddress, err)
	}
	b, _ := m.Share(shareState(), "phone", "", "")
	if a.QR == b.QR {
		t.Fatal("QR не зависит от адреса")
	}
	if _, err := m.Share(shareState(), "phone", "", "198.51.100.1"); !errors.Is(err, ErrInput) {
		t.Fatalf("чужой адрес: %v", err)
	}
}

// Клиенты, которые не подключатся, названы с причиной из таблицы; это не ошибка.
func TestShareUnfit(t *testing.T) {
	sh, err := New().Share(shareState(), "phone", "", "")
	if err != nil || len(sh.Unfit) != 2 {
		t.Fatalf("несовместимые: %+v %v", sh.Unfit, err)
	}
	for _, u := range sh.Unfit {
		if !strings.Contains(u.Reason, "X25519MLKEM768") {
			t.Errorf("%s: причина %q", u.Client, u.Reason)
		}
	}
}

// Явный клиент: совместимый — ссылки есть; несовместимый — ошибка с причиной без ссылок;
// неизвестный — ошибка ввода.
func TestShareClient(t *testing.T) {
	m := New()
	if sh, err := m.Share(shareState(), "phone", "hiddify-5", ""); err != nil || len(sh.Links) != 3 {
		t.Fatalf("hiddify-5: %v", err)
	}
	sh, err := m.Share(shareState(), "phone", "sing-box", "")
	if !errors.Is(err, ErrIncompatible) || !strings.Contains(err.Error(), "X25519MLKEM768") {
		t.Fatalf("sing-box: %v", err)
	}
	if len(sh.Links) != 0 || sh.QR != "" {
		t.Fatal("при отказе ссылок нет")
	}
	if _, err := m.Share(shareState(), "phone", "nope", ""); !errors.Is(err, ErrUnknownClient) {
		t.Fatalf("неизвестный клиент: %v", err)
	}
}

func TestShareNotFoundAndInput(t *testing.T) {
	m := New()
	if _, err := m.Share(shareState(), "tablet", "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет профиля: %v", err)
	}
	if _, err := m.Share(shareState(), "Bad Name", "", ""); !errors.Is(err, ErrInput) {
		t.Fatalf("имя: %v", err)
	}
	st := shareState()
	st.Inbounds = nil
	if _, err := m.Share(st, "phone", "", ""); err == nil {
		t.Fatal("без входящего ссылку не построить")
	}
}

// Ошибки не содержат идентификатор клиента и ключ.
func TestShareErrorsHaveNoSecrets(t *testing.T) {
	st := shareState()
	st.Inbounds[0].Reality.PublicKey = "битый"
	_, err := New().Share(st, "phone", "", "")
	if err == nil || strings.Contains(err.Error(), id(1)) || strings.Contains(err.Error(), "битый") {
		t.Fatalf("ошибка %v", err)
	}
}

func TestNextName(t *testing.T) {
	st := shareState()
	if n := New().NextName(st); n != "profile-1" {
		t.Fatalf("имя %q", n)
	}
	st.Profiles = append(st.Profiles, store.Profile{Name: "profile-1", ID: id(2)}, store.Profile{Name: "profile-2", ID: id(3)})
	if n := New().NextName(st); n != "profile-3" {
		t.Fatalf("имя %q", n)
	}
	if !ValidName(New().NextName(st)) {
		t.Fatal("имя не по правилу")
	}
}

func TestClients(t *testing.T) {
	cs := New().Clients(shareState())
	if len(cs) != 5 {
		t.Fatalf("клиентов %d", len(cs))
	}
	st := shareState()
	st.Core.Version = "26.1.1"
	if got := New().Clients(st); len(got) != 0 {
		t.Fatalf("для старого ядра таблица молчит: %+v", got)
	}
}
