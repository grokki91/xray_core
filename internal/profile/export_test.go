package profile

import (
	"errors"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/profile/compat"
	"github.com/grokki91/xray_core/internal/profile/export"
	"github.com/grokki91/xray_core/internal/store"
)

func testEndpoint() export.Endpoint {
	return export.Endpoint{
		Host: "192.0.2.10", Port: 443, Preset: "reality-xhttp", SNI: "www.example.com",
		PublicKey: strings.Repeat("A", 43), ShortID: "0123456789abcdef", Path: "/",
	}
}

// Экспорт идёт только под совместимый клиент; несовместимый — ошибка с причиной из таблицы,
// а не «приблизительная» ссылка; имя профиля проверяется до экспортёра.
func TestExport(t *testing.T) {
	m := New()
	p := store.Profile{Name: "phone", ID: id(1), Enabled: true}

	a, err := m.Export(p, testEndpoint(), "v2rayn", export.URI{})
	if err != nil || !strings.HasPrefix(a.Text, "vless://") || a.Format != "uri" {
		t.Fatalf("совместимый клиент: %q, %v", a.Format, err)
	}

	for _, c := range []struct {
		client string
		want   error
		reason string
	}{
		{"hiddify-4", compat.ErrIncompatible, "X25519MLKEM768"},
		{"sing-box", compat.ErrIncompatible, "XHTTP"},
		{"unknown", compat.ErrUnknown, ""},
	} {
		a, err := m.Export(p, testEndpoint(), c.client, export.URI{})
		if !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: ошибка %v, нужна %v с %q", c.client, err, c.want, c.reason)
		}
		if a != (export.Artifact{}) {
			t.Errorf("%s: при отказе артефакт не пуст", c.client)
		}
	}

	bad := p
	bad.Name = "Phone#1"
	if _, err := m.Export(bad, testEndpoint(), "v2rayn", export.URI{}); !errors.Is(err, ErrInput) {
		t.Fatalf("имя не по правилу: %v", err)
	}
}
