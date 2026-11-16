//go:build l3

package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/platform/xraytest"
	"github.com/grokki91/xray_core/internal/security"
)

// L3: эталонная конфигурация проходит `xray run -test` настоящего Xray обеих границ
// проверенного диапазона; контроль — испорченный протокол входящего отвергается (код 23).
func TestL3ReferenceConfigPassesXray(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("архив Xray-linux-64 — только для хоста amd64")
	}
	get := func(ctx context.Context, url string, hosts []string) ([]byte, error) {
		return platform.New().Net().Get(ctx, platform.Request{URL: url, Hosts: hosts, Max: platform.MaxFileSize})
	}
	for _, v := range xraytest.Versions() {
		t.Run(v, func(t *testing.T) {
			root := t.TempDir()
			f := platform.NewFake(root, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			for _, d := range []string{"/usr", "/usr/local", "/usr/local/lib", "/usr/local/etc", "/var", "/var/lib", "/run", "/etc"} {
				if err := f.FS().Mkdir(d, 0o755, platform.Root()); err != nil {
					t.Fatal(err)
				}
			}
			f.RunUnderRoot("xray")
			if err := security.New(f).EnsureBaseline(ctx(t)); err != nil {
				t.Fatal(err)
			}
			cm := core.New(f)
			if err := cm.Stage(ctx(t), core.Version(v), xraytest.Archive(t, get, v)); err != nil {
				t.Fatal(err)
			}
			m := New(f)
			r, err := m.Render(state(), json.RawMessage(logPart))
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Write(ctx(t), r); err != nil {
				t.Fatal(err)
			}
			if err := cm.Validate(ctx(t), core.Version(v), Path); err != nil {
				t.Fatalf("Xray %s отверг эталон: %v", v, err)
			}
			bad := bytes.Replace(r.Data, []byte(`"vless"`), []byte(`"nope"`), 1)
			if err := m.Write(ctx(t), Rendered{Data: bad}); err != nil {
				t.Fatal(err)
			}
			if err := cm.Validate(ctx(t), core.Version(v), Path); !errors.Is(err, core.ErrConfig) {
				t.Fatalf("испорченная конфигурация: %v, нужна core.ErrConfig", err)
			}
		})
	}
}
