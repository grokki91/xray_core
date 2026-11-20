package app

import (
	"encoding/json"
	"net/url"
	"strconv"
	"testing"

	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/profile"
	"github.com/grokki91/xray_core/internal/store"
)

// Ссылка профиля и клиент самопроверки строятся из одного состояния и несут одни и те же
// значения (ADR-0032): разборщика ссылок в боевом коде нет, поэтому сверка — здесь. Адрес
// IPv6 в ссылке в скобках, у клиента — без.
func TestLinkAndClientCarrySameParameters(t *testing.T) {
	for name, addrs := range map[string]store.Addresses{
		"IPv4":  {IPv4: "203.0.113.10"},
		"IPv6":  {IPv6: "2001:db8::10"},
		"домен": {Domain: "vpn.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			st := stateOf("phone")
			st.Server.Addresses = addrs
			share, err := profile.New().Share(st, "phone", "", "")
			if err != nil {
				t.Fatal(err)
			}
			link, err := url.Parse(share.Links[0].URI)
			if err != nil {
				t.Fatal(err)
			}
			r, err := config.New(nil).RenderClient(st, st.Profiles[0].ID, "/run/xm/selftest.sock")
			if err != nil {
				t.Fatal(err)
			}
			var cl struct {
				Outbounds []struct {
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
			}
			if err := json.Unmarshal(r.Data, &cl); err != nil {
				t.Fatal(err)
			}
			ob, q := cl.Outbounds[0], link.Query()
			vn, rs := ob.Settings.Vnext[0], ob.StreamSettings.RealitySettings
			for k, p := range map[string][2]string{
				"id":         {link.User.Username(), vn.Users[0].ID},
				"host":       {link.Hostname(), vn.Address},
				"port":       {link.Port(), strconv.Itoa(vn.Port)},
				"encryption": {q.Get("encryption"), vn.Users[0].Encryption},
				"security":   {q.Get("security"), ob.StreamSettings.Security},
				"type":       {q.Get("type"), ob.StreamSettings.Network},
				"sni":        {q.Get("sni"), rs.ServerName},
				"fp":         {q.Get("fp"), rs.Fingerprint},
				"pbk":        {q.Get("pbk"), rs.PublicKey},
				"sid":        {q.Get("sid"), rs.ShortId},
				"path":       {q.Get("path"), ob.StreamSettings.XhttpSettings.Path},
				"mode":       {q.Get("mode"), ob.StreamSettings.XhttpSettings.Mode},
			} {
				if p[0] == "" || p[0] != p[1] {
					t.Errorf("%s: в ссылке %q, у клиента %q", k, p[0], p[1])
				}
			}
			if q.Get("flow") != "" || vn.Users[0].Flow != "" {
				t.Errorf("flow: в ссылке %q, у клиента %q; у XHTTP он пуст", q.Get("flow"), vn.Users[0].Flow)
			}
		})
	}
}
