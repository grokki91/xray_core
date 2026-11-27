package diag

import (
	"context"
	"errors"
	"testing"

	"github.com/grokki91/xray_core/internal/platform"
)

type localCase struct {
	controlCase
	version func(context.Context) (string, error)
	inRange bool
	drift   func(context.Context) (bool, error)
}

func healthyLocal() localCase {
	c := healthy()
	c.selftest = nil
	return localCase{
		controlCase: c,
		version:     func(context.Context) (string, error) { return "26.11.9", nil },
		inRange:     true,
		drift:       func(context.Context) (bool, error) { return false, nil },
	}
}

func (c localCase) run(t *testing.T) Report {
	t.Helper()
	e, err := NewLocal(LocalDeps{
		ControlDeps: ControlDeps{Service: c.svc, Net: c.net, Port: c.port, Validate: c.validate},
		Version:     c.version,
		InRange:     func(string) bool { return c.inRange },
		Drift:       c.drift,
	})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	r, err := e.Run(context.Background(), SetLocal)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

func TestLocalHealthy(t *testing.T) {
	r := healthyLocal().run(t)
	if r.Health != HealthOK || r.Summary.OK != 7 {
		t.Fatalf("health %s, summary %+v", r.Health, r.Summary)
	}
}

func TestLocalCatalog(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mod    func(*localCase)
		check  string
		want   Status
		health Health
	}{
		{"нет Xray", func(c *localCase) { c.version = func(context.Context) (string, error) { return "", nil } }, CheckInstalled, StatusFail, HealthDown},
		{"версия не измерена", func(c *localCase) { c.version = func(context.Context) (string, error) { return "", errors.New("x") } }, CheckVersionRange, StatusSkip, HealthOK},
		{"вне диапазона", func(c *localCase) { c.inRange = false }, CheckVersionRange, StatusFail, HealthDegraded},
		{"перезапуски", func(c *localCase) { c.svc.st.Restarts = 3 }, CheckRestarts, StatusFail, HealthDegraded},
		{"служба стоит", func(c *localCase) { c.svc.st.Active = "inactive" }, CheckRestarts, StatusSkip, HealthDown},
		{"дрейф", func(c *localCase) { c.drift = func(context.Context) (bool, error) { return true, nil } }, CheckConfigDrift, StatusFail, HealthDegraded},
		{"дрейф не измерен", func(c *localCase) { c.drift = func(context.Context) (bool, error) { return false, errors.New("x") } }, CheckConfigDrift, StatusError, HealthOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := healthyLocal()
			c.svc.st = platform.UnitStatus{Loaded: true, Active: "active", Sub: "running"}
			tc.mod(&c)
			r := c.run(t)
			if got := status(r, tc.check); got != tc.want {
				t.Fatalf("%s: %s, want %s", tc.check, got, tc.want)
			}
			if r.Health != tc.health {
				t.Fatalf("health %s, want %s", r.Health, tc.health)
			}
		})
	}
}

func TestLocalRejectsSelftest(t *testing.T) {
	c := healthy()
	_, err := NewLocal(LocalDeps{
		ControlDeps: ControlDeps{Service: c.svc, Net: c.net, Port: c.port, Validate: c.validate, Selftest: c.selftest},
		Version:     func(context.Context) (string, error) { return "", nil },
		InRange:     func(string) bool { return true },
		Drift:       func(context.Context) (bool, error) { return false, nil },
	})
	if !errors.Is(err, ErrRegistry) {
		t.Fatalf("err %v", err)
	}
}
