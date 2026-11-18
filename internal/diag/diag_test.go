package diag

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeCheck — проверка с заданным исходом; runs считает запуски.
type fakeCheck struct {
	id       string
	requires []string
	status   Status
	impact   Impact
	noLimits bool
	runs     int
}

func (c *fakeCheck) ID() string         { return c.id }
func (c *fakeCheck) Requires() []string { return c.requires }

func (c *fakeCheck) Run(context.Context) []Observation {
	c.runs++
	o := Observation{Target: "fake", Status: c.status, Limits: []string{"подделка"}}
	if c.noLimits {
		o.Limits = nil
	}
	if c.status == StatusSkip || c.status == StatusError {
		o.Reason = "причина подделки"
	}
	return []Observation{o}
}

func (c *fakeCheck) Fact(Observation) Finding {
	return Finding{Code: c.id + ".fail", Title: "провал " + c.id, Impact: c.impact,
		Actions: []string{"исправить " + c.id}}
}

func ok(id string, req ...string) *fakeCheck {
	return &fakeCheck{id: id, requires: req, status: StatusOK}
}

func failing(id string, impact Impact, req ...string) *fakeCheck {
	return &fakeCheck{id: id, requires: req, status: StatusFail, impact: impact}
}

func engine(t *testing.T, rules []Rule, checks ...Check) *Engine {
	t.Helper()
	ids := make([]string, len(checks))
	for i, c := range checks {
		ids[i] = c.ID()
	}
	e, err := New(checks, map[string][]string{SetControl: ids}, rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func run(t *testing.T, e *Engine) Report {
	t.Helper()
	r, err := e.Run(context.Background(), SetControl)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

func TestVerdict(t *testing.T) {
	tests := []struct {
		name   string
		checks []Check
		want   Health
	}{
		{"всё ok", []Check{ok("xray.service.active"), ok("reach.listen")}, HealthOK},
		{"факт down", []Check{failing("xray.service.active", ImpactDown)}, HealthDown},
		{"факт degraded", []Check{ok("xray.service.active"), failing("xray.drift", ImpactDegraded)}, HealthDegraded},
		{"skip набора control", []Check{ok("a.b"), &fakeCheck{id: "c.d", status: StatusSkip}}, HealthUnknown},
		{"error набора control", []Check{&fakeCheck{id: "c.d", status: StatusError}}, HealthUnknown},
		{"unknown старше degraded", []Check{failing("a.b", ImpactDegraded), &fakeCheck{id: "c.d", status: StatusSkip}}, HealthUnknown},
		// зависимый пропущен (unknown), но down старше
		{"down старше unknown", []Check{failing("xray.service.active", ImpactDown), ok("reach.listen", "xray.service.active")}, HealthDown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(t, engine(t, nil, tt.checks...)).Health; got != tt.want {
				t.Fatalf("Health = %q, хотели %q", got, tt.want)
			}
		})
	}
}

func TestHypothesisDoesNotChangeVerdict(t *testing.T) {
	hyp := func([]Observation) []Finding {
		return []Finding{{Code: "filter.suspect", Class: ClassHypothesis, Title: "возможно, фильтрация",
			Confirm: "подключение из другой сети", Refute: "подключение из той же сети"}}
	}
	r := run(t, engine(t, []Rule{hyp}, ok("xray.service.active")))
	if r.Health != HealthOK {
		t.Fatalf("гипотеза изменила вердикт: %q", r.Health)
	}
	if len(r.Findings) != 1 || r.Findings[0].Class != ClassHypothesis {
		t.Fatalf("вывод гипотезы потерян: %+v", r.Findings)
	}
	if c := r.Cause(); c != nil {
		t.Fatalf("гипотеза выдана за причину: %+v", c)
	}
}

func TestRuleCannotProduceFact(t *testing.T) {
	for _, f := range []Finding{
		{Code: "x.fact", Class: ClassFact, Title: "t", Impact: ImpactDown},
		{Code: "x.probable", Class: ClassProbable, Title: "t"}, // без альтернатив
		{Code: "x.hyp", Class: ClassHypothesis, Title: "t"},    // без confirm и refute
		{Code: "x.other", Class: "certain", Title: "t"},        // неизвестный класс
		{Code: "x.impact", Class: ClassHypothesis, Title: "t", Confirm: "c", Refute: "r", Impact: ImpactDown},
	} {
		rule := func([]Observation) []Finding { return []Finding{f} }
		_, err := engine(t, []Rule{rule}, ok("a.b")).Run(context.Background(), SetControl)
		if !errors.Is(err, ErrRule) {
			t.Errorf("%s: err = %v, хотели ErrRule", f.Code, err)
		}
	}
}

func TestRequiresSkipsDependent(t *testing.T) {
	svc := failing("xray.service.active", ImpactDown)
	listen := ok("reach.listen", "xray.service.active")
	r := run(t, engine(t, nil, svc, listen))
	if listen.runs != 0 {
		t.Fatal("зависимая проверка запущена при провале зависимости")
	}
	o := r.Observations[1]
	if o.Check != "reach.listen" || o.Status != StatusSkip || !strings.Contains(o.Reason, "xray.service.active") {
		t.Fatalf("наблюдение зависимой: %+v", o)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("пропуск дал вывод: %+v", r.Findings)
	}
	c := r.Cause()
	if c == nil || c.Code != "xray.service.active.fail" || c.Class != ClassFact ||
		len(c.Evidence) != 1 || c.Evidence[0] != "xray.service.active" {
		t.Fatalf("первопричина: %+v", c)
	}
	if r.Summary != (Summary{Fail: 1, Skip: 1}) {
		t.Fatalf("Summary = %+v", r.Summary)
	}
}

func TestCauseDownBeforeDegraded(t *testing.T) {
	r := run(t, engine(t, nil, failing("xray.drift", ImpactDegraded), failing("xray.config.valid", ImpactDown)))
	if c := r.Cause(); c == nil || c.Code != "xray.config.valid.fail" {
		t.Fatalf("первопричина: %+v", c)
	}
}

func TestBrokenObservationIsError(t *testing.T) {
	tests := []struct {
		name  string
		check Check
	}{
		{"без limits", &fakeCheck{id: "a.b", status: StatusOK, noLimits: true}},
		{"неизвестное состояние", &fakeCheck{id: "a.b", status: "maybe"}},
		{"skip без причины", &noReason{fakeCheck{id: "a.b"}}},
		{"нет наблюдений", &empty{fakeCheck{id: "a.b"}}},
		{"факт без влияния", failing("a.b", "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, engine(t, nil, tt.check))
			if r.Observations[0].Status != StatusError || r.Health != HealthUnknown {
				t.Fatalf("наблюдение %+v, вердикт %q", r.Observations[0], r.Health)
			}
			if len(r.Findings) != 0 {
				t.Fatalf("сломанная проверка дала вывод: %+v", r.Findings)
			}
		})
	}
}

type noReason struct{ fakeCheck }

func (*noReason) Run(context.Context) []Observation {
	return []Observation{{Status: StatusSkip, Limits: []string{"l"}}}
}

type empty struct{ fakeCheck }

func (*empty) Run(context.Context) []Observation { return nil }

func TestCanceledContext(t *testing.T) {
	c := ok("a.b")
	e := engine(t, nil, c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := e.Run(ctx, SetControl)
	if err != nil {
		t.Fatal(err)
	}
	if c.runs != 0 || r.Observations[0].Status != StatusError || r.Health != HealthUnknown {
		t.Fatalf("истёкший срок: runs=%d, %+v, %q", c.runs, r.Observations[0], r.Health)
	}
}

func TestNewRejects(t *testing.T) {
	tests := []struct {
		name   string
		checks []Check
		sets   map[string][]string
	}{
		{"повтор ID", []Check{ok("a.b"), ok("a.b")}, nil},
		{"ID не по правилу", []Check{ok("A.b")}, nil},
		{"ID без категории", []Check{ok("ab")}, nil},
		{"неизвестная зависимость", []Check{ok("a.b", "c.d")}, nil},
		{"зависимость позже", []Check{ok("a.b", "c.d"), ok("c.d")}, nil},
		{"зависимость вне набора", []Check{ok("c.d"), ok("a.b", "c.d")}, map[string][]string{SetControl: {"a.b"}}},
		{"нет набора control", []Check{ok("a.b")}, map[string][]string{"full": {"a.b"}}},
		{"неизвестная проверка в наборе", []Check{ok("a.b")}, map[string][]string{SetControl: {"x.y"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sets := tt.sets
			if sets == nil {
				sets = map[string][]string{SetControl: {}}
			}
			if _, err := New(tt.checks, sets, nil); !errors.Is(err, ErrRegistry) {
				t.Fatalf("err = %v, хотели ErrRegistry", err)
			}
		})
	}
}

func TestUnknownSet(t *testing.T) {
	if _, err := engine(t, nil, ok("a.b")).Run(context.Background(), "full"); !errors.Is(err, ErrUnknownSet) {
		t.Fatalf("err = %v", err)
	}
}

func TestOnlyControlSkipMakesUnknown(t *testing.T) {
	a, b := ok("a.b"), &fakeCheck{id: "ipv6.outbound", status: StatusSkip}
	e, err := New([]Check{a, b}, map[string][]string{SetControl: {"a.b"}, "full": {"a.b", "ipv6.outbound"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Run(context.Background(), "full")
	if err != nil {
		t.Fatal(err)
	}
	if r.Health != HealthOK {
		t.Fatalf("skip вне набора control изменил вердикт: %q", r.Health)
	}
}
