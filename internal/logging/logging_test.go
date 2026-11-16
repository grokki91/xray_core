package logging

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/redact"
	"github.com/grokki91/xray_core/internal/redact/redacttest"
)

func newManager(t *testing.T, level slog.Level) (*Manager, *platform.Fake, *redact.Redactor) {
	f := platform.NewFake(t.TempDir(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	r := redact.New()
	return New(f, r, level), f, r
}

// Канареечный тест: ни одно значение секрета не доходит до journald — ни в сообщении, ни в
// атрибутах, ни в группах, ни в WithAttrs; точные значения и шаблоны.
func TestLoggerNeverWritesCanaries(t *testing.T) {
	c := redacttest.New(t)
	m, f, r := newManager(t, slog.LevelDebug)
	r.Register(redact.UUID, c.UUID)
	r.Register(redact.Key, c.PrivateKey)
	r.Register(redact.ShortID, c.ShortID)
	r.Register(redact.Domain, c.Domain)
	r.Register(redact.Path, c.Path)

	l := m.Logger().With("owner", c.Domain).WithGroup("cfg")
	l.Info("install "+c.UUID, "key", c.PrivateKey, "short", c.ShortID, "path", c.Path)
	l.Error("connect failed", "addr", c.IPv4+":443", "v6", c.IPv6, "pub", c.PublicKey)
	l.Debug("link", "uri", "vless://"+c.UUID+"@"+c.IPv4+":443?pbk="+c.PublicKey)

	var out []string
	for _, e := range f.Journaled() {
		out = append(out, e.Message)
	}
	if len(out) != 3 {
		t.Fatalf("записей %d, нужно 3", len(out))
	}
	redacttest.AssertClean(t, c, map[string]string{"journal": strings.Join(out, "\n")})
}

func TestLoggerLevelsAndPriorities(t *testing.T) {
	m, f, _ := newManager(t, slog.LevelInfo)
	l := m.Logger()
	l.Debug("skipped")
	l.Info("i")
	l.Warn("w")
	l.Error("e")
	got := f.Journaled()
	want := []platform.Priority{platform.PriInfo, platform.PriWarning, platform.PriErr}
	if len(got) != len(want) {
		t.Fatalf("записей %d, нужно %d: %+v", len(got), len(want), got)
	}
	for i, p := range want {
		if got[i].Priority != p {
			t.Errorf("запись %d: приоритет %d, нужно %d", i, got[i].Priority, p)
		}
	}
}

func TestLoggerFormat(t *testing.T) {
	m, f, _ := newManager(t, slog.LevelInfo)
	m.Logger().With("a", 1, "s", "x y").WithGroup("g").Info("hello", "k", "two words", "n", 2)
	got := f.Journaled()[0].Message
	if want := `hello a=1 s="x y" g.k="two words" g.n=2`; got != want {
		t.Errorf("формат %q, нужно %q", got, want)
	}
}

func TestXrayLogSection(t *testing.T) {
	m, _, _ := newManager(t, slog.LevelInfo)
	var v struct{ Access, Loglevel string }
	if err := json.Unmarshal(m.XraySection(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Access != "none" {
		t.Errorf("журнал доступа Xray включён: %q", v.Access)
	}
	if v.Loglevel != "warning" {
		t.Errorf("loglevel %q", v.Loglevel)
	}
	if s := m.Settings(); s.XrayAccess != "none" || s.Level != slog.LevelInfo {
		t.Errorf("настройки: %+v", s)
	}
}
