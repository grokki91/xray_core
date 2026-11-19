package diag

import (
	"context"
	"errors"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// Самопроверка (ADR-0032): клиент Xray из состояния подключается к собственному серверу и
// запрашивает тестовый адрес. Один адрес для боя и для L3 (docs/dev/dependencies.md §5).
const (
	// SelftestSocket — сокет клиента самопроверки в бою; каталог /run/xm — root 0700, порта нет.
	SelftestSocket = "/run/xm/selftest.sock"

	selftestURL  = "https://cp.cloudflare.com/generate_204"
	selftestHost = "cp.cloudflare.com"
	// selftestWindow — сколько ждём, пока клиент поднимется и пропустит запрос; selftestStep —
	// пауза между попытками; selftestAttempt — срок одной попытки.
	selftestWindow  = 15 * time.Second
	selftestStep    = 200 * time.Millisecond
	selftestAttempt = 5 * time.Second
	selftestMax     = 1 << 10
)

// CheckSelftest — идентификатор проверки.
const CheckSelftest = "reach.selftest"

// Host — примитивы платформы, нужные измерениям с процессом и сетью. Объявлен здесь: `app`
// не импортирует platform, `cmd/xm` подставляет саму платформу.
type Host interface {
	FS() platform.FS
	Net() platform.Net
	Clock() platform.Clock
}

// Process — фоновый процесс клиента самопроверки; тот же набор методов, что у platform.Process.
type Process interface {
	Done() <-chan struct{}
	Stop()
}

// SelftestDeps — измерения самопроверки.
type SelftestDeps struct {
	Host Host
	// Socket — путь сокета клиента: в бою SelftestSocket, в L3 — во временном каталоге.
	Socket string
	// Start запускает клиента из состояния, слушающего Socket. Процесс останавливает проверка.
	// Текст ошибки в отчёт не попадает.
	Start func(ctx context.Context) (Process, error)
}

type selftest struct{ d SelftestDeps }

func (selftest) ID() string         { return CheckSelftest }
func (selftest) Requires() []string { return []string{CheckListen} }

func (c selftest) get(ctx context.Context, proxy string) error {
	ctx, cancel := context.WithTimeout(ctx, selftestAttempt)
	defer cancel()
	_, err := c.d.Host.Net().Get(ctx, platform.Request{
		URL: selftestURL, Hosts: []string{selftestHost}, Max: selftestMax, Proxy: proxy, Status: 204,
	})
	return err
}

// Run: прямой запрос к тестовому адресу (недоступен с сервера — не измерено), удаление прежнего
// сокета, запуск клиента, запрос через сервер с повторами в пределах окна, остановка клиента.
func (c selftest) Run(ctx context.Context) []Observation {
	const target = "selftest.target"
	h := c.d.Host
	if err := c.get(ctx, ""); err != nil {
		return []Observation{{Target: target, Status: StatusSkip,
			Reason: "тестовый адрес " + selftestHost + " недоступен с самого сервера: самопроверка не измерена"}}
	}
	// Сокет и его .lock: Xray создаёт оба, убитый клиент оставляет оба.
	removeSocket := func() error {
		for _, p := range []string{c.d.Socket, c.d.Socket + ".lock"} {
			if err := h.FS().Remove(p); err != nil && !errors.Is(err, platform.ErrNotFound) {
				return err
			}
		}
		return nil
	}
	if removeSocket() != nil {
		return errObs("selftest.client", "не удалось убрать прежний сокет клиента самопроверки")
	}
	sctx, cancel := context.WithTimeout(ctx, selftestWindow+2*selftestAttempt)
	defer cancel()
	proc, err := c.d.Start(sctx)
	if err != nil {
		return errObs("selftest.client", "клиент самопроверки не запустился")
	}
	defer func() {
		proc.Stop()
		// Остановка убивает процесс, и сокет остаётся; убрать его — не условие результата: прежний
		// сокет всё равно удаляется перед следующим запуском.
		_ = removeSocket()
	}()

	deadline := h.Clock().Now().Add(selftestWindow)
	for {
		err := c.get(sctx, c.d.Socket)
		if err == nil {
			return obs(target, true, true, selftestLimits...)
		}
		select {
		case <-proc.Done():
			return errObs("selftest.client", "клиент самопроверки завершился до ответа")
		default:
		}
		if ctx.Err() != nil {
			return errObs("selftest.client", "срок контроля истёк до конца самопроверки")
		}
		if !h.Clock().Now().Before(deadline) {
			return obs(target, false, false, selftestLimits...)
		}
		if h.Clock().Sleep(ctx, selftestStep) != nil {
			return errObs("selftest.client", "срок контроля истёк до конца самопроверки")
		}
	}
}

var selftestLimits = []string{
	"клиент на этом же сервере проходит через него к тестовому адресу; доступность извне и из сети клиента не доказана",
	"провал не различает сбой сервера, REALITY-цели и обратного пути до тестового адреса: прямой запрос с сервера к нему прошёл",
}

func (selftest) Fact(Observation) Finding {
	return Finding{Code: "reach.selftest.failed", Title: "клиент из состояния не получил ответ через сервер", Impact: ImpactDown,
		Actions: []string{"journalctl -u xray -n 50; xm restart"}}
}
