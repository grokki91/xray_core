package diag

import (
	"context"
	"fmt"

	"github.com/grokki91/xray_core/internal/platform"
)

// ControlDeps — измерения набора control. Интерфейсы объявлены здесь, реализации подставляет
// app из менеджеров: менеджеры друг друга не импортируют (ADR-0024, ADR-0030).
type ControlDeps struct {
	// Service — состояние службы xray.service.
	Service interface {
		Status(ctx context.Context) (platform.UnitStatus, error)
	}
	// Net — слушает ли хост порт.
	Net interface {
		Listening(ctx context.Context, port int) (bool, error)
	}
	// Port — порт сервера из состояния на момент вызова: транзакция сохраняет состояние до
	// перезапуска, откат — восстанавливает до контроля.
	Port func(ctx context.Context) (int, error)
	// Validate — `xray run -test` действующей версией на действующей конфигурации: false без
	// ошибки — конфигурация не принята; ошибка — проверить не удалось.
	Validate func(ctx context.Context) (valid bool, err error)
}

// Идентификаторы проверок набора control.
const (
	CheckServiceActive = "xray.service.active"
	CheckListen        = "reach.listen"
	CheckConfigValid   = "xray.config.valid"
)

// NewControl собирает движок с набором control: служба активна, порт слушается, конфигурация
// принята Xray. Порядок — порядок зависимостей: порт без службы не измеряется. Остальной каталог —
// фаза 5; самопроверка reach.selftest — шаг 7 фазы 3.
func NewControl(d ControlDeps) (*Engine, error) {
	if d.Service == nil || d.Net == nil || d.Port == nil || d.Validate == nil {
		return nil, fmt.Errorf("%w: не все измерения набора control заданы", ErrRegistry)
	}
	checks := []Check{serviceActive{d}, listen{d}, configValid{d}}
	ids := make([]string, len(checks))
	for i, c := range checks {
		ids[i] = c.ID()
	}
	return New(checks, map[string][]string{SetControl: ids}, nil)
}

// errObs — измерить не удалось. Текст ошибки в причину не идёт: он попадёт в отчёт и ошибку
// команды, а в ошибках платформы бывают пути и фрагменты конфигурации.
func errObs(target, reason string) []Observation {
	return []Observation{{Target: target, Status: StatusError, Reason: reason}}
}

func obs(target string, ok bool, value any, limits ...string) []Observation {
	st := StatusOK
	if !ok {
		st = StatusFail
	}
	return []Observation{{Target: target, Status: st, Value: value, Limits: limits}}
}

type serviceActive struct{ d ControlDeps }

func (serviceActive) ID() string         { return CheckServiceActive }
func (serviceActive) Requires() []string { return nil }

func (c serviceActive) Run(ctx context.Context) []Observation {
	st, err := c.d.Service.Status(ctx)
	if err != nil {
		return errObs("xray.service", "не удалось получить состояние службы")
	}
	active := st.Loaded && st.Active == "active" && st.Sub == "running"
	return obs("xray.service", active, map[string]string{"active": st.Active, "sub": st.Sub},
		"снимок состояния в момент проверки: цикл перезапусков по нему не виден (его ловит контроль запуска)")
}

func (serviceActive) Fact(Observation) Finding {
	return Finding{Code: "xray.service.not_active", Title: "служба xray не активна", Impact: ImpactDown,
		Actions: []string{"systemctl status xray; journalctl -u xray -n 50"}}
}

type listen struct{ d ControlDeps }

func (listen) ID() string         { return CheckListen }
func (listen) Requires() []string { return []string{CheckServiceActive} }

func (c listen) Run(ctx context.Context) []Observation {
	port, err := c.d.Port(ctx)
	if err != nil || port <= 0 || port > 65535 {
		return errObs("server.port", "порт сервера из состояния недоступен")
	}
	on, err := c.d.Net.Listening(ctx, port)
	if err != nil {
		return errObs("server.port", "не удалось прочитать таблицы сокетов")
	}
	return obs("server.port", on, on,
		"порт слушается на каком-либо адресе, семейства IPv4 и IPv6 не различаются",
		"сервер готов принимать; доступность извне этим не доказана")
}

func (listen) Fact(Observation) Finding {
	return Finding{Code: "reach.listen.closed", Title: "порт сервера не слушается", Impact: ImpactDown,
		Actions: []string{"ss -ltn; journalctl -u xray -n 50"}}
}

type configValid struct{ d ControlDeps }

func (configValid) ID() string         { return CheckConfigValid }
func (configValid) Requires() []string { return nil }

func (c configValid) Run(ctx context.Context) []Observation {
	valid, err := c.d.Validate(ctx)
	if err != nil {
		return errObs("xray.config", "не удалось запустить проверку конфигурации")
	}
	return obs("xray.config", valid, valid,
		"xray run -test принимает файл; поведение под нагрузкой и доступность извне он не доказывает")
}

func (configValid) Fact(Observation) Finding {
	return Finding{Code: "xray.config.invalid", Title: "Xray не принимает действующую конфигурацию", Impact: ImpactDown,
		Actions: []string{"xm status — проверить дрейф; вернуть конфигурацию из снимка: xm restore <id>"}}
}
