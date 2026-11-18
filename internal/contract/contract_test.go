package contract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var at = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Эталон схемы меняется только осознанно: расхождение вывода с ним — провал.
func TestGolden(t *testing.T) {
	cases := map[string]Envelope{
		"version": New("0.1.0", at, Version{XM: "0.1.0"}),
		"status": New("0.1.0", at, Status{
			Installed: true,
			Service:   ServiceState{Loaded: true, Active: "active", Sub: "running", Enabled: true},
			Versions:  Versions{XM: "0.1.0", Xray: "26.11.9"},
			Addresses: ServerAddress{IPv4: "203.0.113.10"},
			Port:      443,
			Profiles:  2,
			Clients: []ClientSupport{
				{Name: "v2rayN", Works: true, Condition: "ядро Xray клиента не старше v25.7.26"},
				{Name: "Hiddify 4.x", Reason: "вырезает X25519MLKEM768"},
			},
			Health: Health{Verdict: HealthDown, Cause: "порт сервера не слушается", Action: "ss -ltn; journalctl -u xray -n 50"},
		}),
		"profiles": New("0.1.0", at, Profiles{Profiles: []ProfileItem{
			{Name: "phone", Created: 1767225600, Enabled: true},
			{Name: "laptop", Created: 1767229200},
		}}),
		"profile": New("0.1.0", at, Profile{
			ProfileItem: ProfileItem{Name: "phone", Created: 1767225600, Enabled: true},
			Links: []ProfileLink{
				{Address: "vpn.example.com", URI: "vless://00000000-0000-4000-8000-000000000001@vpn.example.com:443?encryption=none#phone"},
			},
			QRAddress: "vpn.example.com",
			Unfit:     []UnfitClient{{Client: "Hiddify 4.x", Reason: "вырезает X25519MLKEM768"}},
		}),
		"error": NewError("0.1.0", at, Error{
			Code:    "cli.unknown_command",
			Message: "неизвестная команда «frobnicate»",
			Hint:    "список команд: xm help",
		}),
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if env.Schema.Name != name {
				t.Fatalf("schema.name %q, нужен %q", env.Schema.Name, name)
			}
			var got bytes.Buffer
			if err := Encode(&got, env); err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("вывод расходится с эталоном testdata/%s.json:\n%s", name, got.Bytes())
			}
		})
	}
}

// Потребитель прежней версии игнорирует неизвестные поля: добавление поля (minor+1) его не ломает.
func TestOldConsumerIgnoresNewFields(t *testing.T) {
	doc := `{"schema":{"name":"version","major":1,"minor":7},"xm":{"version":"0.1.0"},"time":1,` +
		`"future":true,"data":{"xm":"0.1.0","xray":"26.11.9"}}`
	var got struct {
		Schema Schema  `json:"schema"`
		Data   Version `json:"data"`
	}
	if err := json.Unmarshal([]byte(doc), &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema.Major != 1 || got.Data.XM != "0.1.0" {
		t.Fatalf("разобрано неверно: %+v", got)
	}
}
