package preset

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func params() Params {
	return Params{
		Port: 443, Target: "example.com:443", ServerNames: []string{"example.com"},
		PrivateKey: key, ShortIDs: []string{"0123456789abcdef"},
		ClientIDs: []string{"00000000-0000-4000-8000-000000000001"},
	}
}

func TestGet(t *testing.T) {
	p, err := Get("reality-xhttp")
	if err != nil || p.ID() != "reality-xhttp" {
		t.Fatalf("%v, %v", p, err)
	}
	if r := p.Requires(); r.Port != 443 || !r.NeedsTarget || r.MinXray == "" {
		t.Fatalf("Requires: %+v", r)
	}
	if _, err := Get("nope"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("неизвестный пресет: %v", err)
	}
	if ids := IDs(); len(ids) != 1 || ids[0] != "reality-xhttp" {
		t.Fatalf("IDs: %v", ids)
	}
}

func TestInboundFields(t *testing.T) {
	p, _ := Get("reality-xhttp")
	raw, err := p.Inbound(params())
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Protocol string
		Port     int
		Settings struct {
			Decryption string
			Clients    []struct{ ID, Flow string }
		}
		StreamSettings struct {
			Network, Security string
			XHTTPSettings     struct{ Path, Mode string }
			RealitySettings   struct {
				Target      string
				ServerNames []string
				PrivateKey  string
				ShortIDs    []string
			}
		}
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	s := in.StreamSettings
	if in.Protocol != "vless" || in.Port != 443 || in.Settings.Decryption != "none" ||
		len(in.Settings.Clients) != 1 || in.Settings.Clients[0].Flow != "" ||
		s.Network != "xhttp" || s.Security != "reality" || s.XHTTPSettings.Mode != "auto" || s.XHTTPSettings.Path != "/" ||
		s.RealitySettings.Target != "example.com:443" || s.RealitySettings.PrivateKey != key {
		t.Fatalf("поля: %s", raw)
	}
}

func TestInboundRejects(t *testing.T) {
	cases := map[string]func(*Params){
		"порт 0":           func(p *Params) { p.Port = 0 },
		"порт 70000":       func(p *Params) { p.Port = 70000 },
		"цель без порта":   func(p *Params) { p.Target = "example.com" },
		"цель со схемой":   func(p *Params) { p.Target = "https://example.com:443" },
		"порт цели":        func(p *Params) { p.Target = "example.com:99999" },
		"нет SNI":          func(p *Params) { p.ServerNames = nil },
		"плохой SNI":       func(p *Params) { p.ServerNames = []string{"a b"} },
		"короткий ключ":    func(p *Params) { p.PrivateKey = "AAAA" },
		"нет shortId":      func(p *Params) { p.ShortIDs = nil },
		"нечётный shortId": func(p *Params) { p.ShortIDs = []string{"abc"} },
		"длинный shortId":  func(p *Params) { p.ShortIDs = []string{"0123456789abcdef00"} },
		"не UUID":          func(p *Params) { p.ClientIDs = []string{"x"} },
		"path без /":       func(p *Params) { p.Options = map[string]string{"path": "x"} },
		"path с запросом":  func(p *Params) { p.Options = map[string]string{"path": "/a?b=1"} },
		"чужая опция":      func(p *Params) { p.Options = map[string]string{"mode": "packet-up"} },
	}
	p, _ := Get("reality-xhttp")
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			in := params()
			mut(&in)
			_, err := p.Inbound(in)
			if err == nil {
				t.Fatal("принято")
			}
			if strings.Contains(err.Error(), key) {
				t.Fatalf("в ошибке секрет: %v", err)
			}
		})
	}
}

func clientParams() ClientParams {
	return ClientParams{
		Host: "203.0.113.10", Port: 443, ID: "00000000-0000-4000-8000-000000000001",
		SNI: "example.com", PublicKey: key, ShortID: "0123456789abcdef",
		Options: map[string]string{"path": "/example"},
	}
}

// Исходящий клиента берёт те же значения, что ссылка: fp chrome, flow пустой, mode auto.
func TestOutboundFields(t *testing.T) {
	p, _ := Get("reality-xhttp")
	raw, err := p.Outbound(clientParams())
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		Protocol string
		Settings struct {
			Vnext []struct {
				Address string
				Port    int
				Users   []struct{ ID, Encryption, Flow string }
			}
		}
		StreamSettings struct {
			Network, Security string
			RealitySettings   struct{ ServerName, Fingerprint, PublicKey, ShortId string }
			XhttpSettings     struct{ Path, Mode string }
		}
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	v, s := o.Settings.Vnext, o.StreamSettings
	if o.Protocol != "vless" || len(v) != 1 || v[0].Address != "203.0.113.10" || v[0].Port != 443 ||
		len(v[0].Users) != 1 || v[0].Users[0].ID != clientParams().ID || v[0].Users[0].Encryption != "none" || v[0].Users[0].Flow != "" {
		t.Errorf("vless: %+v", o)
	}
	if s.Network != "xhttp" || s.Security != "reality" || s.RealitySettings.ServerName != "example.com" ||
		s.RealitySettings.Fingerprint != "chrome" || s.RealitySettings.PublicKey != key || s.RealitySettings.ShortId != "0123456789abcdef" ||
		s.XhttpSettings.Path != "/example" || s.XhttpSettings.Mode != "auto" {
		t.Errorf("stream: %+v", s)
	}
}

func TestOutboundRejects(t *testing.T) {
	p, _ := Get("reality-xhttp")
	for name, mut := range map[string]func(*ClientParams){
		"id":        func(c *ClientParams) { c.ID = "x" },
		"публичный": func(c *ClientParams) { c.PublicKey = "x" },
		"sni":       func(c *ClientParams) { c.SNI = "a b" },
		"shortId":   func(c *ClientParams) { c.ShortID = "zz" },
		"адрес":     func(c *ClientParams) { c.Host = "" },
		"порт":      func(c *ClientParams) { c.Port = 0 },
		"опция":     func(c *ClientParams) { c.Options = map[string]string{"x": "y"} },
		"путь":      func(c *ClientParams) { c.Options = map[string]string{"path": "a?b"} },
	} {
		c := clientParams()
		mut(&c)
		if _, err := p.Outbound(c); err == nil {
			t.Errorf("%s: принят", name)
		} else if strings.Contains(err.Error(), key) {
			t.Errorf("%s: значение в ошибке", name)
		}
	}
}
