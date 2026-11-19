package diag

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

type fakeService struct {
	st  platform.UnitStatus
	err error
}

func (f fakeService) Status(context.Context) (platform.UnitStatus, error) { return f.st, f.err }

type fakeNet struct {
	on  bool
	err error
	got int
}

func (f *fakeNet) Listening(_ context.Context, port int) (bool, error) {
	f.got = port
	return f.on, f.err
}

// controlCase — исходы трёх измерений; по умолчанию всё в порядке.
type controlCase struct {
	svc      fakeService
	net      *fakeNet
	port     func(context.Context) (int, error)
	validate func(context.Context) (bool, error)
	selftest SelftestDeps
}

// okHost — платформа, на которой самопроверка проходит: прямой запрос и запрос через сервер
// отвечают, сокета нет. Подробные случаи самопроверки — selftest_test.go.
type okHost struct{}

type okFS struct{ platform.FS }
type okNet struct{ platform.Net }
type okClock struct{ platform.Clock }

func (okFS) Remove(string) error                                    { return nil }
func (okNet) Get(context.Context, platform.Request) ([]byte, error) { return nil, nil }
func (okClock) Now() time.Time                                      { return time.Time{} }
func (okClock) Sleep(context.Context, time.Duration) error          { return nil }
func (okHost) FS() platform.FS                                      { return okFS{} }
func (okHost) Net() platform.Net                                    { return okNet{} }
func (okHost) Clock() platform.Clock                                { return okClock{} }

func healthy() controlCase {
	return controlCase{
		svc:      fakeService{st: platform.UnitStatus{Loaded: true, Active: "active", Sub: "running"}},
		net:      &fakeNet{on: true},
		port:     func(context.Context) (int, error) { return 8443, nil },
		validate: func(context.Context) (bool, error) { return true, nil },
		selftest: SelftestDeps{Host: okHost{}, Socket: SelftestSocket, Start: func(context.Context) (Process, error) { return newProc(false), nil }},
	}
}

func (c controlCase) run(t *testing.T) Report {
	t.Helper()
	e, err := NewControl(ControlDeps{Service: c.svc, Net: c.net, Port: c.port, Validate: c.validate, Selftest: c.selftest})
	if err != nil {
		t.Fatalf("NewControl: %v", err)
	}
	r, err := e.Run(context.Background(), SetControl)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

func status(r Report, check string) Status {
	for _, o := range r.Observations {
		if o.Check == check {
			return o.Status
		}
	}
	return "нет наблюдения"
}

func TestControlHealthy(t *testing.T) {
	c := healthy()
	r := c.run(t)
	if r.Health != HealthOK || r.Summary != (Summary{OK: 4}) {
		t.Fatalf("здоровая служба: %q %+v", r.Health, r.Summary)
	}
	if c.net.got != 8443 {
		t.Fatalf("порт из состояния не дошёл до проверки: %d", c.net.got)
	}
	for _, o := range r.Observations {
		if len(o.Limits) == 0 {
			t.Errorf("%s: нет limits", o.Check)
		}
	}
}

func TestControlServiceInactive(t *testing.T) {
	for _, st := range []platform.UnitStatus{
		{Loaded: true, Active: "inactive", Sub: "dead"},
		{Loaded: true, Active: "failed", Sub: "failed"},
		{Loaded: true, Active: "activating", Sub: "auto-restart"},
		{Loaded: false, Active: "inactive", Sub: "dead"},
	} {
		c := healthy()
		c.svc.st = st
		r := c.run(t)
		if r.Health != HealthDown || status(r, "xray.service.active") != StatusFail {
			t.Fatalf("%+v: %q, %v", st, r.Health, status(r, "xray.service.active"))
		}
		// порт без службы не измеряется: первопричина — служба, а не порт
		if status(r, "reach.listen") != StatusSkip || c.net.got != 0 {
			t.Fatalf("порт измерен при неактивной службе: %v, %d", status(r, "reach.listen"), c.net.got)
		}
		if cause := r.Cause(); cause == nil || cause.Evidence[0] != "xray.service.active" {
			t.Fatalf("первопричина: %+v", cause)
		}
	}
}

func TestControlPortNotListening(t *testing.T) {
	c := healthy()
	c.net.on = false
	r := c.run(t)
	if r.Health != HealthDown || status(r, "reach.listen") != StatusFail {
		t.Fatalf("%q, %v", r.Health, status(r, "reach.listen"))
	}
	if status(r, "xray.config.valid") != StatusOK {
		t.Fatal("провал порта не должен мешать проверке конфигурации")
	}
}

func TestControlConfigInvalid(t *testing.T) {
	c := healthy()
	c.validate = func(context.Context) (bool, error) { return false, nil }
	r := c.run(t)
	if r.Health != HealthDown || status(r, "xray.config.valid") != StatusFail {
		t.Fatalf("%q, %v", r.Health, status(r, "xray.config.valid"))
	}
}

// Нечем измерить — error с причиной и вердикт unknown, а не ok и не down.
func TestControlMeasurementErrors(t *testing.T) {
	boom := errors.New("сбой измерения")
	tests := []struct {
		name  string
		tweak func(*controlCase)
		check string
	}{
		{"состояние службы", func(c *controlCase) { c.svc.err = boom }, "xray.service.active"},
		{"порт из состояния", func(c *controlCase) { c.port = func(context.Context) (int, error) { return 0, boom } }, "reach.listen"},
		{"порт 0", func(c *controlCase) { c.port = func(context.Context) (int, error) { return 0, nil } }, "reach.listen"},
		{"таблицы сокетов", func(c *controlCase) { c.net.err = boom }, "reach.listen"},
		{"запуск xray", func(c *controlCase) { c.validate = func(context.Context) (bool, error) { return false, boom } }, "xray.config.valid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := healthy()
			tt.tweak(&c)
			r := c.run(t)
			if status(r, tt.check) != StatusError || r.Health != HealthUnknown {
				t.Fatalf("%v, %q", status(r, tt.check), r.Health)
			}
			for _, o := range r.Observations {
				if o.Status == StatusError && strings.Contains(o.Reason, boom.Error()) {
					t.Fatalf("текст ошибки измерения попал в причину: %q", o.Reason)
				}
			}
		})
	}
}

func TestNewControlRejectsMissingDeps(t *testing.T) {
	if _, err := NewControl(ControlDeps{}); !errors.Is(err, ErrRegistry) {
		t.Fatalf("err = %v", err)
	}
	c := healthy()
	if _, err := NewControl(ControlDeps{Service: c.svc, Net: c.net, Port: c.port, Validate: c.validate}); !errors.Is(err, ErrRegistry) {
		t.Fatalf("без измерений самопроверки: %v", err)
	}
}
