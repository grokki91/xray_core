package security

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"io/fs"
	"maps"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

// fakeHost — подделка с родителями каталогов манифеста, как на чистой Ubuntu.
func fakeHost(t *testing.T) *platform.Fake {
	f := platform.NewFake(t.TempDir(), time.Time{})
	for _, d := range []string{"/usr", "/usr/local", "/usr/local/lib", "/usr/local/etc", "/var", "/var/lib", "/run", "/etc"} {
		if err := f.FS().Mkdir(d, 0o755, platform.Root()); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestRealityKeysMatchAndDiffer(t *testing.T) {
	m := New(nil)
	a, err := m.NewRealityKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.RawURLEncoding.DecodeString(a.Private)
	if err != nil || len(priv) != 32 {
		t.Fatalf("закрытый ключ: %v, %d байт", err, len(priv))
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()); got != a.Public {
		t.Fatalf("открытый ключ не из закрытого: %q", got)
	}
	b, _ := m.NewRealityKeys(t.Context())
	if a == b {
		t.Fatal("две пары совпали")
	}
}

func TestClientIDIsUUIDv4(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	m := New(nil)
	a, _ := m.NewClientID()
	b, _ := m.NewClientID()
	if !re.MatchString(a) || a == b {
		t.Fatalf("%q, %q", a, b)
	}
}

func TestShortID(t *testing.T) {
	m := New(nil)
	a, _ := m.NewShortID()
	b, _ := m.NewShortID()
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(a) || a == b {
		t.Fatalf("%q, %q", a, b)
	}
}

func TestEnsureBaselineFollowsManifest(t *testing.T) {
	f := fakeHost(t)
	m := New(f)
	if err := m.EnsureBaseline(ctx(t)); err != nil {
		t.Fatal(err)
	}
	svc, _ := f.Users().Ensure(ctx(t), ServiceUser)
	want := map[string]struct {
		perm fs.FileMode
		own  platform.Owner
	}{
		"/usr/local/lib/xm":   {0o755, platform.Root()},
		platform.CoreDir:      {0o755, platform.Root()},
		"/etc/xm":             {0o700, platform.Root()},
		"/usr/local/etc/xray": {0o750, platform.Owner{GID: svc.GID}},
		"/var/lib/xm":         {0o700, platform.Root()},
		"/var/lib/xm/backups": {0o700, platform.Root()},
		"/var/lib/xm/tx":      {0o700, platform.Root()},
		"/var/lib/xm/diag":    {0o700, platform.Root()},
		"/var/lib/xm/monitor": {0o700, platform.Root()},
		"/var/lib/xm/cache":   {0o700, platform.Root()},
		"/run/xm":             {0o700, platform.Root()},
	}
	for path, w := range want {
		fi, err := os.Stat(f.Path(path))
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != w.perm {
			t.Errorf("%s: %v, %v", path, fi, err)
		}
		if o, ok := f.Owner(path); !ok || o != w.own {
			t.Errorf("%s: владелец %v, нужен %v", path, o, w.own)
		}
	}
	if err := m.EnsureBaseline(ctx(t)); err != nil {
		t.Fatalf("повтор: %v", err)
	}
}

func TestEnsureBaselineRejectsWrongPerms(t *testing.T) {
	f := fakeHost(t)
	if err := f.FS().Mkdir("/etc/xm", 0o755, platform.Root()); err != nil {
		t.Fatal(err)
	}
	if err := New(f).EnsureBaseline(ctx(t)); err == nil {
		t.Fatal("каталог с правами 0755 принят")
	}
}

func TestEnsureBaselineRejectsWrongOwner(t *testing.T) {
	f := fakeHost(t)
	if err := f.FS().Mkdir("/etc/xm", 0o700, platform.Owner{UID: 1000, GID: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := New(f).EnsureBaseline(ctx(t)); err == nil {
		t.Fatal("каталог с чужим владельцем принят")
	}
}

func TestUnitHardeningMatchesPolicy(t *testing.T) {
	// Таблица — docs/security/policy.md §3; ослабление директивы должно ронять тест.
	want := map[string]string{
		"NoNewPrivileges": "true", "ProtectSystem": "strict", "ProtectHome": "true", "PrivateTmp": "true",
		"PrivateDevices": "true", "ProtectKernelTunables": "true", "ProtectKernelModules": "true",
		"ProtectControlGroups": "true", "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
		"RestrictNamespaces": "true", "LockPersonality": "true", "MemoryDenyWriteExecute": "true",
		"SystemCallArchitectures": "native", "CapabilityBoundingSet": "CAP_NET_BIND_SERVICE",
		"AmbientCapabilities": "CAP_NET_BIND_SERVICE",
	}
	got := map[string]string{}
	for _, o := range New(nil).UnitHardening() {
		if _, dup := got[o.Key]; dup {
			t.Errorf("директива %s повторена", o.Key)
		}
		got[o.Key] = o.Value
	}
	if !maps.Equal(got, want) {
		t.Errorf("директивы: %v, нужны %v", got, want)
	}
}
