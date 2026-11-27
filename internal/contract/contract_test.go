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
			Health:    Health{Verdict: "ok", Unchecked: "доступность порта снаружи и самопроверка не проверены"},
			Clients: []ClientSupport{
				{Name: "v2rayN", Works: true, Condition: "ядро Xray клиента не старше v25.7.26"},
				{Name: "Hiddify 4.x", Reason: "вырезает X25519MLKEM768"},
			},
			Update: Available{Version: "26.11.9", Checked: "2026-01-01T00:00:00Z"},
		}),
		"update": New("0.1.0", at, Update{
			Current: "26.10.21", Target: "26.11.9", Latest: "26.12.1",
			Range: Range{Min: "26.10.21", Max: "26.11.9"}, InRange: true, Updated: true,
			Checked: "2026-01-01T00:00:00Z", Unchecked: "сторонние клиентские ядра не проверялись",
		}),
		"backups": New("0.1.0", at, Backups{Backups: []BackupItem{
			{ID: "20260101T000000Z-manual", Created: 1767225600, Kind: "manual", XM: "0.1.0", Xray: "26.11.9", Valid: true},
			{ID: "20260101T010000Z-profile-add", Created: 1767229200, Kind: "auto"},
		}}),
		"diag-report": New("0.1.0", at, DiagReport{
			ID: "20260101T000000Z", Vantage: DiagVantage{Kind: "local", ID: "server"},
			Env: DiagEnv{XM: "0.1.0", Xray: "26.11.9", OS: "ubuntu-24.04"}, Health: "down",
			Observations: []DiagObservation{
				{Check: "xray.service.active", Status: "fail", Value: "inactive", Limits: []string{"состояние юнита, не работа протокола"}},
				{Check: "reach.listen", Status: "skip", Reason: "не прошла зависимость xray.service.active"},
			},
			Findings: []DiagFinding{{Code: "xray.service.inactive", Class: "fact", Title: "Служба Xray не активна",
				Evidence: []string{"xray.service.active"}, Actions: []string{"xm start"}, Impact: "down"}},
			Summary: DiagSummary{Fail: 1, Skip: 1},
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
