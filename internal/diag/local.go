package diag

import (
	"context"
	"fmt"
)

// LocalDeps — измерения каталога точки наблюдения local (фаза 5): набор control и проверки
// категории xray, которых контролю транзакции не нужно.
type LocalDeps struct {
	ControlDeps
	// Version — версия установленного Xray; "" без ошибки — Xray не установлен.
	Version func(ctx context.Context) (string, error)
	// InRange — входит ли версия в проверенный диапазон этой версии xm (update.Verified).
	InRange func(version string) bool
	// Drift — отличается ли конфигурация на диске от отрисованной из состояния.
	Drift func(ctx context.Context) (bool, error)
}

// SetLocal — каталог MVP с самого сервера (docs/operations/diagnostics.md §4).
const SetLocal = "local"

// Идентификаторы проверок каталога сверх набора control.
const (
	CheckInstalled    = "xray.installed"
	CheckVersionRange = "xray.version.range"
	CheckRestarts     = "xray.service.restarts"
	CheckConfigDrift  = "xray.config.drift"
)

// NewLocal собирает движок с наборами control (без самопроверки: она только в контроле
// изменения, ADR-0033) и local — весь каталог MVP.
func NewLocal(d LocalDeps) (*Engine, error) {
	if d.Selftest != nil {
		return nil, fmt.Errorf("%w: самопроверка не входит в каталог local", ErrRegistry)
	}
	if d.Service == nil || d.Net == nil || d.Port == nil || d.Validate == nil ||
		d.Version == nil || d.InRange == nil || d.Drift == nil {
		return nil, fmt.Errorf("%w: не все измерения каталога local заданы", ErrRegistry)
	}
	c := d.ControlDeps
	checks := []Check{installed{d}, versionRange{d}, serviceActive{c}, restarts{c}, listen{c}, configValid{c}, configDrift{d}}
	ids := make([]string, len(checks))
	for i, ch := range checks {
		ids[i] = ch.ID()
	}
	return New(checks, map[string][]string{
		SetControl: {CheckServiceActive, CheckListen, CheckConfigValid},
		SetLocal:   ids,
	}, nil)
}

type installed struct{ d LocalDeps }

func (installed) ID() string         { return CheckInstalled }
func (installed) Requires() []string { return nil }

func (c installed) Run(ctx context.Context) []Observation {
	v, err := c.d.Version(ctx)
	if err != nil {
		return errObs("xray.binary", "не удалось определить версию Xray")
	}
	return obs("xray.binary", v != "", v, "версия — по бинарнику на диске; исправность запуска этим не доказана")
}

func (installed) Fact(Observation) Finding {
	return Finding{Code: "xray.installed.missing", Title: "Xray не установлен", Impact: ImpactDown,
		Actions: []string{"xm update — поставить проверенную версию; xm restore <id> — вернуть снимок"}}
}

type versionRange struct{ d LocalDeps }

func (versionRange) ID() string         { return CheckVersionRange }
func (versionRange) Requires() []string { return []string{CheckInstalled} }

func (c versionRange) Run(ctx context.Context) []Observation {
	v, err := c.d.Version(ctx)
	if err != nil || v == "" {
		return errObs("xray.binary", "не удалось определить версию Xray")
	}
	return obs("xray.binary", c.d.InRange(v), v,
		"вне диапазона — не проверено этой версией xm, а не заведомо неисправно")
}

func (versionRange) Fact(Observation) Finding {
	return Finding{Code: "xray.version.unverified", Title: "версия Xray вне проверенного диапазона xm", Impact: ImpactDegraded,
		Actions: []string{"xm update --check; xm update — перейти на проверенную версию"}}
}

type restarts struct{ d ControlDeps }

func (restarts) ID() string         { return CheckRestarts }
func (restarts) Requires() []string { return []string{CheckServiceActive} }

func (c restarts) Run(ctx context.Context) []Observation {
	st, err := c.d.Service.Status(ctx)
	if err != nil {
		return errObs("xray.service", "не удалось получить состояние службы")
	}
	return obs("xray.service", st.Restarts == 0, st.Restarts,
		"NRestarts считает авто-перезапуски с последнего ручного запуска: идёт ли цикл сейчас, один снимок не различает")
}

func (restarts) Fact(Observation) Finding {
	return Finding{Code: "xray.service.restarted", Title: "служба xray перезапускалась после сбоев", Impact: ImpactDegraded,
		Actions: []string{"xm logs --since 1h — причина падений"}}
}

type configDrift struct{ d LocalDeps }

func (configDrift) ID() string         { return CheckConfigDrift }
func (configDrift) Requires() []string { return nil }

func (c configDrift) Run(ctx context.Context) []Observation {
	drift, err := c.d.Drift(ctx)
	if err != nil {
		return errObs("xray.config", "не удалось сравнить конфигурацию с состоянием")
	}
	return obs("xray.config", !drift, drift,
		"сравнивается файл на диске; конфигурация, загруженная в работающий процесс, не читается")
}

func (configDrift) Fact(Observation) Finding {
	return Finding{Code: "xray.config.drift", Title: "конфигурация Xray правлена вне xm", Impact: ImpactDegraded,
		Actions: []string{"правки вручную не сохраняются: внести их через xm; вернуть конфигурацию — xm restore <id>"}}
}
