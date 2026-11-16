//go:build l3

package security

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/platform/xraytest"
)

// L3: настоящий Xray каждой границы диапазона выводит из нашего закрытого ключа наш открытый.
func TestL3KeysMatchXray(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("архив Xray-linux-64 — только для хоста amd64")
	}
	get := func(ctx context.Context, url string, hosts []string) ([]byte, error) {
		return platform.New().Net().Get(ctx, platform.Request{URL: url, Hosts: hosts, Max: platform.MaxFileSize})
	}
	for _, v := range xraytest.Versions() {
		t.Run(v, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range []string{"/usr/local/lib", "/etc/xm"} {
				if err := os.MkdirAll(root+d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			f := platform.NewFake(root, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			f.RunUnderRoot("xray")
			if err := core.New(f).Stage(ctx(t), core.Version(v), xraytest.Archive(t, get, v)); err != nil {
				t.Fatal(err)
			}
			keys, err := New(f).NewRealityKeys(ctx(t))
			if err != nil {
				t.Fatal(err)
			}
			res, err := f.Exec(ctx(t), platform.Command{Program: "xray", Version: v, Args: []string{"x25519", "-i", keys.Private}})
			if err != nil || res.ExitCode != 0 {
				t.Fatalf("x25519: %v, код %d", err, res.ExitCode)
			}
			if !bytes.Contains(res.Stdout, []byte(keys.Public)) {
				t.Fatalf("Xray не вывел наш открытый ключ")
			}
		})
	}
}
