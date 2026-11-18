// Пакет diag — движок диагностики: реестр проверок, наборы, зависимости, анализ и вердикт
// здоровья (ADR-0011, ADR-0024). Проверка возвращает наблюдения, а не вердикт; вывод класса
// fact по провалу даёт сама проверка, выводы probable и hypothesis — правила анализа. Вердикт
// строится только по фактам и исходам набора control: предположение не делает сервер неисправным.
// Движок ничего не меняет в системе; измерения проверки получают через конструктор.
package diag

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

var (
	// ErrRegistry — реестр проверок или наборов составлен неверно; ошибка программы, не ввода.
	ErrRegistry = errors.New("diag: неверный реестр проверок")
	// ErrUnknownSet — набора с таким именем нет.
	ErrUnknownSet = errors.New("diag: неизвестный набор проверок")
	// ErrRule — правило анализа вернуло вывод, нарушающий модель (ADR-0011).
	ErrRule = errors.New("diag: правило анализа нарушает модель выводов")
)

// SetControl — набор контроля транзакции; его skip и error дают вердикт unknown (ADR-0024).
const SetControl = "control"

// Status — исход наблюдения.
type Status string

const (
	StatusOK    Status = "ok"
	StatusFail  Status = "fail"
	StatusSkip  Status = "skip"  // нечем измерить; причина обязательна
	StatusError Status = "error" // сама проверка сломалась; причина обязательна
)

// Class — класс вывода (docs/operations/diagnostics.md §1).
type Class string

const (
	ClassFact       Class = "fact"
	ClassProbable   Class = "probable"
	ClassHypothesis Class = "hypothesis"
)

// Impact — что факт значит для подключения; у выводов других классов пусто.
type Impact string

const (
	ImpactDown     Impact = "down"     // подключение невозможно
	ImpactDegraded Impact = "degraded" // возможно не для всех или под угрозой
)

// Health — вердикт здоровья.
type Health string

const (
	HealthOK       Health = "ok"
	HealthDegraded Health = "degraded"
	HealthDown     Health = "down"
	HealthUnknown  Health = "unknown"
)

// Observation — результат одного измерения. Check ставит движок.
type Observation struct {
	Check  string
	Target string
	Status Status
	Value  any
	Reason string   // причина skip и error
	Limits []string // чего измерение не различает; обязательно для ok и fail
}

// Finding — вывод. Evidence — ID проверок, на наблюдениях которых он стоит.
type Finding struct {
	Code         string
	Class        Class
	Title        string
	Evidence     []string
	Alternatives []string // probable: другие объяснения
	Confirm      string   // hypothesis: что подтвердит
	Refute       string   // hypothesis: что опровергнет
	Actions      []string
	Impact       Impact // только у fact
}

// Check — одна проверка реестра.
type Check interface {
	ID() string         // <категория>.<предмет>[.<свойство>]; категория — первая часть
	Requires() []string // проверки, без успеха которых эта не измеряет; раньше в реестре
	Run(ctx context.Context) []Observation
	// Fact — вывод класса fact по наблюдению fail: Code, Title, Impact, Actions. Class и
	// Evidence ставит движок.
	Fact(o Observation) Finding
}

// Rule — правило анализа: выводы probable и hypothesis над наблюдениями прогона.
type Rule func(obs []Observation) []Finding

// Summary — число наблюдений по исходам.
type Summary struct{ OK, Fail, Skip, Error int }

// Report — итог прогона набора.
type Report struct {
	Set          string
	Observations []Observation
	Findings     []Finding // сначала факты в порядке проверок, затем выводы правил
	Summary      Summary
	Health       Health
}

// Engine — реестр проверок и наборов. Неизменяем после New.
type Engine struct {
	checks  []Check
	byID    map[string]Check
	sets    map[string][]string
	control map[string]bool
	rules   []Rule
}

var idRule = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_-]+)+$`)

// New проверяет реестр: ID по правилу и без повторов, зависимость зарегистрирована раньше
// зависимой (циклов нет) и входит в те же наборы, набор control есть.
func New(checks []Check, sets map[string][]string, rules []Rule) (*Engine, error) {
	e := &Engine{byID: map[string]Check{}, sets: map[string][]string{}, control: map[string]bool{}}
	for _, c := range checks {
		id := c.ID()
		if !idRule.MatchString(id) {
			return nil, fmt.Errorf("%w: ID %q не по правилу", ErrRegistry, id)
		}
		if _, dup := e.byID[id]; dup {
			return nil, fmt.Errorf("%w: повтор %q", ErrRegistry, id)
		}
		for _, r := range c.Requires() {
			if _, earlier := e.byID[r]; !earlier {
				return nil, fmt.Errorf("%w: %q требует %q, которой нет раньше в реестре", ErrRegistry, id, r)
			}
		}
		e.byID[id] = c
		e.checks = append(e.checks, c)
	}
	if _, ok := sets[SetControl]; !ok {
		return nil, fmt.Errorf("%w: нет набора %q", ErrRegistry, SetControl)
	}
	for name, ids := range sets {
		in := map[string]bool{}
		for _, id := range ids {
			if _, ok := e.byID[id]; !ok {
				return nil, fmt.Errorf("%w: в наборе %q неизвестная проверка %q", ErrRegistry, name, id)
			}
			in[id] = true
		}
		var members []string
		for _, c := range e.checks { // порядок реестра: зависимость раньше зависимой
			if !in[c.ID()] {
				continue
			}
			for _, r := range c.Requires() {
				if !in[r] {
					return nil, fmt.Errorf("%w: в наборе %q у %q нет зависимости %q", ErrRegistry, name, c.ID(), r)
				}
			}
			members = append(members, c.ID())
		}
		e.sets[name] = members
	}
	for _, id := range e.sets[SetControl] {
		e.control[id] = true
	}
	e.rules = append([]Rule(nil), rules...)
	return e, nil
}

// Run выполняет набор по порядку реестра. Проверка с проваленной или не измеренной зависимостью
// не запускается и даёт skip. Сломанное наблюдение становится error; ошибка Run — только
// неизвестный набор или правило, нарушившее модель.
func (e *Engine) Run(ctx context.Context, set string) (Report, error) {
	ids, ok := e.sets[set]
	if !ok {
		return Report{}, fmt.Errorf("%w: %q", ErrUnknownSet, set)
	}
	r := Report{Set: set}
	passed := map[string]bool{}
	unknown := false
	worst := Impact("")
	for _, id := range ids {
		c := e.byID[id]
		passed[id] = true
		for _, m := range e.observe(ctx, c, passed) {
			o := m.obs
			r.Observations = append(r.Observations, o)
			switch o.Status {
			case StatusOK:
				r.Summary.OK++
			case StatusFail:
				r.Summary.Fail++
				f := m.fact
				f.Class, f.Evidence = ClassFact, []string{id}
				r.Findings = append(r.Findings, f)
				if f.Impact == ImpactDown || worst == "" {
					worst = f.Impact
				}
			case StatusSkip:
				r.Summary.Skip++
			case StatusError:
				r.Summary.Error++
			}
			if o.Status != StatusOK {
				passed[id] = false
			}
			if e.control[id] && (o.Status == StatusSkip || o.Status == StatusError) {
				unknown = true
			}
		}
	}
	for _, rule := range e.rules {
		for _, f := range rule(r.Observations) {
			if err := checkRuleFinding(f); err != nil {
				return Report{}, err
			}
			r.Findings = append(r.Findings, f)
		}
	}
	switch {
	case worst == ImpactDown:
		r.Health = HealthDown
	case unknown:
		r.Health = HealthUnknown
	case worst == ImpactDegraded:
		r.Health = HealthDegraded
	default:
		r.Health = HealthOK
	}
	return r, nil
}

// measured — наблюдение и, для fail, факт проверки по нему: Fact вызывается один раз.
type measured struct {
	obs  Observation
	fact Finding
}

// observe запускает проверку или объясняет, почему она не запущена, и приводит наблюдения к
// модели: нарушение — error с причиной, а не тихий ok.
func (e *Engine) observe(ctx context.Context, c Check, passed map[string]bool) []measured {
	id := c.ID()
	fail := func(st Status, reason string) []measured {
		return []measured{{obs: Observation{Check: id, Status: st, Reason: reason}}}
	}
	for _, r := range c.Requires() {
		if !passed[r] {
			return fail(StatusSkip, "не прошла зависимость "+r)
		}
	}
	if ctx.Err() != nil {
		return fail(StatusError, "срок прогона истёк до проверки")
	}
	obs := c.Run(ctx)
	if len(obs) == 0 {
		return fail(StatusError, "проверка не вернула наблюдений")
	}
	out := make([]measured, len(obs))
	for i, o := range obs {
		o.Check = id
		m := measured{obs: o}
		if o.Status == StatusFail {
			m.fact = c.Fact(o)
		}
		if reason := broken(m); reason != "" {
			m = measured{obs: Observation{Check: id, Target: o.Target, Status: StatusError, Reason: reason}}
		}
		out[i] = m
	}
	return out
}

func broken(m measured) string {
	o := m.obs
	switch o.Status {
	case StatusOK, StatusFail:
		if len(o.Limits) == 0 {
			return "наблюдение без limits"
		}
		if o.Status == StatusFail && m.fact.Impact != ImpactDown && m.fact.Impact != ImpactDegraded {
			return "факт провала без влияния на подключение"
		}
	case StatusSkip, StatusError:
		if o.Reason == "" {
			return "skip или error без причины"
		}
	default:
		return fmt.Sprintf("неизвестное состояние %q", o.Status)
	}
	return ""
}

// checkRuleFinding: факты дают только проверки — правило не может объявить причину
// установленной; у probable есть альтернативы, у hypothesis — чем подтвердить и опровергнуть.
func checkRuleFinding(f Finding) error {
	switch {
	case f.Class == ClassProbable && len(f.Alternatives) > 0 && f.Impact == "":
	case f.Class == ClassHypothesis && f.Confirm != "" && f.Refute != "" && f.Impact == "":
	default:
		return fmt.Errorf("%w: вывод %q класса %q", ErrRule, f.Code, f.Class)
	}
	return nil
}

// Cause — первопричина для человека: первый факт down, иначе первый факт degraded; нет — nil.
// Проверка с проваленной зависимостью не запускается, поэтому любой факт — без проваленных
// зависимостей.
func (r Report) Cause() *Finding {
	for _, want := range []Impact{ImpactDown, ImpactDegraded} {
		for i := range r.Findings {
			if f := &r.Findings[i]; f.Class == ClassFact && f.Impact == want {
				return f
			}
		}
	}
	return nil
}
