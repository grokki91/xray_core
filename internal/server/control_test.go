package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// unit — подменяемое состояние службы для systemctl show.
type unit struct {
	loaded         bool
	active, sub    string
	restarts, port int
}

func controlEnv(t *testing.T, u *unit, onSleep func()) (*platform.Fake, Service) {
	t.Helper()
	f := platform.NewFake(t.TempDir(), time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	f.Handle("systemctl", func(c platform.Command) (platform.Result, error) {
		load := "not-found"
		if u.loaded {
			load = "loaded"
		}
		return platform.Result{Stdout: []byte(fmt.Sprintf("LoadState=%s\nActiveState=%s\nSubState=%s\nUnitFileState=enabled\nNRestarts=%d\nMainPID=1\n", load, u.active, u.sub, u.restarts))}, nil
	})
	return f, New(f, cfg).Service()
}

func short(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	t.Cleanup(cancel)
	return c
}

func TestCheckRunning(t *testing.T) {
	cases := map[string]struct {
		u    unit
		on   bool
		want bool
	}{
		"активна и слушает": {unit{loaded: true, active: "active", sub: "running"}, true, true},
		"порт не слушается": {unit{loaded: true, active: "active", sub: "running"}, false, false},
		"перезапускалась":   {unit{loaded: true, active: "active", sub: "running", restarts: 1}, true, false},
		"упала":             {unit{loaded: true, active: "failed", sub: "failed"}, true, false},
		"ждёт перезапуска":  {unit{loaded: true, active: "activating", sub: "auto-restart"}, true, false},
		"юнита нет":         {unit{}, true, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, s := controlEnv(t, &c.u, nil)
			f.SetListening(443, c.on)
			err := s.CheckRunning(short(t), 443)
			if c.want != (err == nil) {
				t.Fatalf("ждали успех=%v, получено %v", c.want, err)
			}
			if err != nil && !errors.Is(err, ErrControl) {
				t.Fatalf("ошибка не ErrControl: %v", err)
			}
		})
	}
}

func TestCheckRunningNeedsDeadline(t *testing.T) {
	u := unit{loaded: true, active: "active", sub: "running"}
	_, s := controlEnv(t, &u, nil)
	if err := s.CheckRunning(context.Background(), 443); !errors.Is(err, platform.ErrDeadline) {
		t.Fatalf("%v", err)
	}
}

// Служба поднялась, но падает после выдержки: один снимок успеха не принимается.
func TestCheckRunningRecheckAfterSettle(t *testing.T) {
	u := unit{loaded: true, active: "active", sub: "running"}
	f, s := controlEnv(t, &u, nil)
	f.SetListening(443, true)
	start := f.Clock().Now()
	if err := s.CheckRunning(short(t), 443); err != nil {
		t.Fatal(err)
	}
	if f.Clock().Now().Sub(start) < settle {
		t.Fatal("выдержка не выдержана")
	}
}

func TestCheckStopped(t *testing.T) {
	cases := map[string]struct {
		u    unit
		on   bool
		want bool
	}{
		"остановлена, порт свободен": {unit{loaded: true, active: "inactive", sub: "dead"}, false, true},
		"остановлена, порт занят":    {unit{loaded: true, active: "inactive", sub: "dead"}, true, false},
		"ещё активна":                {unit{loaded: true, active: "active", sub: "running"}, false, false},
		"упала, а не остановлена":    {unit{loaded: true, active: "failed", sub: "failed"}, false, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, s := controlEnv(t, &c.u, nil)
			f.SetListening(443, c.on)
			if err := s.CheckStopped(short(t), 443); c.want != (err == nil) {
				t.Fatalf("ждали успех=%v, получено %v", c.want, err)
			}
		})
	}
}

func TestUnitAndRestoreUnit(t *testing.T) {
	f := platform.NewFake(t.TempDir(), time.Time{})
	f.Handle("systemctl", func(platform.Command) (platform.Result, error) { return platform.Result{}, nil })
	if err := os.MkdirAll(f.Path("/etc/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New(f, cfg)
	if b, err := m.Unit(); b != nil || err != nil {
		t.Fatalf("юнита нет: %v %v", b, err)
	}
	own := []byte(Label + "\n[Service]\nUser=xray\n")
	if err := m.RestoreUnit(ctx(t), own); err != nil {
		t.Fatal(err)
	}
	if b, _ := m.Unit(); string(b) != string(own) {
		t.Fatalf("юнит не возвращён побайтно: %q", b)
	}
	if err := m.RestoreUnit(ctx(t), []byte("[Service]\n")); !errors.Is(err, ErrForeign) {
		t.Fatalf("юнит без метки записан: %v", err)
	}
	if err := m.RestoreUnit(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := m.Unit(); b != nil {
		t.Fatal("юнит не удалён")
	}
}
