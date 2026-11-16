//go:build l3

package core

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/platform/xraytest"
)

// L3: настоящий Xray каждой границы проверенного диапазона проходит Stage, Activate и Validate.
func TestL3RealXray(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("архив Xray-linux-64 — только для хоста amd64")
	}
	get := func(ctx context.Context, url string, hosts []string) ([]byte, error) {
		return platform.New().Net().Get(ctx, platform.Request{URL: url, Hosts: hosts, Max: platform.MaxFileSize})
	}
	for _, v := range xraytest.Versions() {
		t.Run(v, func(t *testing.T) {
			archive := xraytest.Archive(t, get, v)
			root := t.TempDir()
			for _, d := range []string{"/usr/local/lib", "/etc/xm"} {
				if err := os.MkdirAll(root+d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			f := platform.NewFake(root, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			f.RunUnderRoot("xray")
			m := New(f)
			ver := Version(v)
			if err := m.Stage(ctx(t), ver, archive); err != nil {
				t.Fatalf("Stage: %v", err)
			}
			if err := m.Activate(ctx(t), ver); err != nil {
				t.Fatalf("Activate: %v", err)
			}
			if cur, err := m.Current(ctx(t)); err != nil || cur != ver {
				t.Fatalf("Current: %q, %v", cur, err)
			}
			for _, tc := range []struct {
				name, config string
				want         error
			}{
				{"ok", `{"inbounds":[{"listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}}]}`, nil},
				{"bad", `{"inbounds":[{"port":10085,"protocol":"no-such-protocol"}]}`, ErrConfig},
			} {
				path := "/etc/xm/" + tc.name + ".json"
				if err := os.WriteFile(root+path, []byte(tc.config), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := m.Validate(ctx(t), ver, path); !errors.Is(err, tc.want) {
					t.Errorf("Validate %s: %v, нужно %v", tc.name, err, tc.want)
				}
			}
		})
	}
}
