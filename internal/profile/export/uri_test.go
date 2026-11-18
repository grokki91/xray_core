package export

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/store"
)

// Фиктивные данные — docs/security/secrets.md §4.
const (
	testID  = "00000000-0000-4000-8000-000000000001"
	testSID = "0123456789abcdef"
)

var testPBK = strings.Repeat("A", 43)

func testProfile() store.Profile { return store.Profile{Name: "alice", ID: testID, Enabled: true} }

func testEndpoint(host string) Endpoint {
	return Endpoint{
		Host: host, Port: 443, Preset: "reality-xhttp",
		SNI: "www.example.com", PublicKey: testPBK, ShortID: testSID, Path: "/",
	}
}

func TestURIFormat(t *testing.T) {
	if got := (URI{}).Format(); got != "uri" {
		t.Fatalf("Format() = %q, нужен uri", got)
	}
}

// Эталоны: порядок параметров фиксирован, вывод побайтно детерминирован.
func TestURIGolden(t *testing.T) {
	q := "?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk=" + testPBK +
		"&sid=" + testSID + "&type=xhttp&path=%2F&mode=auto#alice"
	cases := []struct{ name, host, want string }{
		{"ipv4", "192.0.2.10", "vless://" + testID + "@192.0.2.10:443" + q},
		{"ipv6", "2001:db8::10", "vless://" + testID + "@[2001:db8::10]:443" + q},
		{"domain", "vpn.example.com", "vless://" + testID + "@vpn.example.com:443" + q},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := (URI{}).Export(testProfile(), testEndpoint(c.host))
			if err != nil {
				t.Fatalf("Export: %v", err)
			}
			if a.Format != "uri" || a.Text != c.want {
				t.Fatalf("артефакт:\n got %q %q\nwant %q %q", a.Format, a.Text, "uri", c.want)
			}
		})
	}
}

// Ссылка разбирается net/url и даёт те же параметры, что пришли на вход.
func TestURIRoundTrip(t *testing.T) {
	e := testEndpoint("2001:db8::10")
	e.Port = 8443
	e.Path = "/a.b_c~d/e-f"
	p := testProfile()
	p.Name = "bob_2-x"
	a, err := (URI{}).Export(p, e)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	u, err := url.Parse(a.Text)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if u.Scheme != "vless" || u.User.Username() != testID || u.Hostname() != e.Host || u.Port() != "8443" || u.Fragment != p.Name {
		t.Fatalf("разбор: scheme %q user %q host %q port %q fragment %q", u.Scheme, u.User.Username(), u.Hostname(), u.Port(), u.Fragment)
	}
	want := map[string]string{
		"encryption": "none", "security": "reality", "sni": e.SNI, "fp": "chrome",
		"pbk": e.PublicKey, "sid": e.ShortID, "type": "xhttp", "path": e.Path, "mode": "auto",
	}
	got := u.Query()
	if len(got) != len(want) {
		t.Fatalf("параметры %v, нужны ровно %v", got, want)
	}
	for k, v := range want {
		if vs := got[k]; len(vs) != 1 || vs[0] != v {
			t.Errorf("%s = %q, нужно %q", k, vs, v)
		}
	}
	if _, ok := got["flow"]; ok {
		t.Error("flow для XHTTP не пишется")
	}
}

// Имя кодируется %-последовательностями без «+»: ни одно значение не ломает ссылку.
func TestURINameEncoding(t *testing.T) {
	p := testProfile()
	p.Name = "a b+c#d?&é"
	a, err := (URI{}).Export(p, testEndpoint("192.0.2.10"))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	frag := a.Text[strings.IndexByte(a.Text, '#')+1:]
	if frag != "a%20b%2Bc%23d%3F%26%C3%A9" {
		t.Fatalf("метка %q", frag)
	}
	u, err := url.Parse(a.Text)
	if err != nil || u.Fragment != p.Name {
		t.Fatalf("разбор метки: %q, %v", u.Fragment, err)
	}
}

func TestURIRejects(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*store.Profile, *Endpoint)
		want error
	}{
		{"пресет", func(_ *store.Profile, e *Endpoint) { e.Preset = "reality-vision" }, ErrPreset},
		{"пресет пустой", func(_ *store.Profile, e *Endpoint) { e.Preset = "" }, ErrPreset},
		{"адрес пустой", func(_ *store.Profile, e *Endpoint) { e.Host = "" }, ErrInput},
		{"адрес со скобками", func(_ *store.Profile, e *Endpoint) { e.Host = "[2001:db8::10]" }, ErrInput},
		{"IPv6 с зоной", func(_ *store.Profile, e *Endpoint) { e.Host = "fe80::1%eth0" }, ErrInput},
		{"адрес с портом", func(_ *store.Profile, e *Endpoint) { e.Host = "192.0.2.10:443" }, ErrInput},
		{"адрес с пробелом", func(_ *store.Profile, e *Endpoint) { e.Host = "vpn example.com" }, ErrInput},
		{"адрес с @", func(_ *store.Profile, e *Endpoint) { e.Host = "a@example.com" }, ErrInput},
		{"домен с дефисом в начале метки", func(_ *store.Profile, e *Endpoint) { e.Host = "-a.example.com" }, ErrInput},
		{"цифровой домен", func(_ *store.Profile, e *Endpoint) { e.Host = "999.0.2.10" }, ErrInput},
		{"порт 0", func(_ *store.Profile, e *Endpoint) { e.Port = 0 }, ErrInput},
		{"порт 65536", func(_ *store.Profile, e *Endpoint) { e.Port = 65536 }, ErrInput},
		{"pbk пустой", func(_ *store.Profile, e *Endpoint) { e.PublicKey = "" }, ErrInput},
		{"pbk короткий", func(_ *store.Profile, e *Endpoint) { e.PublicKey = strings.Repeat("A", 42) }, ErrInput},
		{"pbk не base64url", func(_ *store.Profile, e *Endpoint) { e.PublicKey = strings.Repeat("A", 42) + "+" }, ErrInput},
		{"sid пустой", func(_ *store.Profile, e *Endpoint) { e.ShortID = "" }, ErrInput},
		{"sid нечётный", func(_ *store.Profile, e *Endpoint) { e.ShortID = "abc" }, ErrInput},
		{"sid длинный", func(_ *store.Profile, e *Endpoint) { e.ShortID = testSID + "00" }, ErrInput},
		{"sni пустой", func(_ *store.Profile, e *Endpoint) { e.SNI = "" }, ErrInput},
		{"sni адрес", func(_ *store.Profile, e *Endpoint) { e.SNI = "192.0.2.10" }, ErrInput},
		{"sni с пробелом", func(_ *store.Profile, e *Endpoint) { e.SNI = "www example.com" }, ErrInput},
		{"path пустой", func(_ *store.Profile, e *Endpoint) { e.Path = "" }, ErrInput},
		{"path без /", func(_ *store.Profile, e *Endpoint) { e.Path = "a" }, ErrInput},
		{"path с запросом", func(_ *store.Profile, e *Endpoint) { e.Path = "/a?b" }, ErrInput},
		{"имя пустое", func(p *store.Profile, _ *Endpoint) { p.Name = "" }, ErrInput},
		{"идентификатор не UUID", func(p *store.Profile, _ *Endpoint) { p.ID = "00000000-0000-4000-8000-00000000000" }, ErrInput},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, e := testProfile(), testEndpoint("192.0.2.10")
			c.mod(&p, &e)
			a, err := (URI{}).Export(p, e)
			if !errors.Is(err, c.want) {
				t.Fatalf("ошибка %v, нужна %v", err, c.want)
			}
			if a != (Artifact{}) {
				t.Fatalf("при отказе артефакт пуст, получен %q", a.Format)
			}
			// Ни одно входное значение — исходное или изменённое — не попадает в ошибку
			// (secrets.md §3). Значения короче трёх знаков совпали бы со словами сообщения.
			for _, s := range []string{testID, testPBK, testSID, "192.0.2.10", "www.example.com",
				p.ID, p.Name, e.Host, e.SNI, e.PublicKey, e.ShortID, e.Path} {
				if len(s) >= 3 && strings.Contains(err.Error(), s) {
					t.Fatalf("в ошибке входное значение (длина %d)", len(s))
				}
			}
		})
	}
}

// Отказ на учётных данных не раскрывает их ни при каком значении.
func TestURIErrorsHaveNoSecrets(t *testing.T) {
	p, e := testProfile(), testEndpoint("192.0.2.10")
	p.ID = testID + "x"
	e.PublicKey = testPBK + "B"
	for _, mod := range []func(){func() {}, func() { p.ID = testID }} {
		mod()
		_, err := (URI{}).Export(p, e)
		if err == nil {
			t.Fatal("нужен отказ")
		}
		if strings.Contains(err.Error(), testID) || strings.Contains(err.Error(), testPBK) {
			t.Fatal("в ошибке значение секрета")
		}
	}
}
