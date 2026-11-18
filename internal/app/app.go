// Пакет app — сценарии использования. Единственный слой, который знает порядок шагов:
// изменение системы — транзакция со снимком и откатом (ADR-0005, ADR-0023). О терминале и HTTP
// не знает; к platform не обращается — только через менеджеры.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/logging"
	"github.com/grokki91/xray_core/internal/profile"
	"github.com/grokki91/xray_core/internal/security"
	"github.com/grokki91/xray_core/internal/server"
	"github.com/grokki91/xray_core/internal/store"
)

var (
	// ErrRolledBack — изменение не применено: на каком-то шаге случился сбой, система возвращена
	// к исходному состоянию и проверена. Код выхода 1.
	ErrRolledBack = errors.New("изменение не применено, прежнее состояние возвращено")
	// ErrRollbackFailed — откат не удался или его результат не прошёл контроль. Код выхода 5:
	// xm больше ничего не меняет, пока владелец не разберётся.
	ErrRollbackFailed = errors.New("откат не удался")
)

const (
	defaultControlTimeout = 30 * time.Second
	rollbackTimeout       = 2 * time.Minute
)

// Services — менеджеры, из которых собирается транзакция; создаёт их cmd/xm.
type Services struct {
	Store   *store.Store
	Backup  *backup.Manager
	Config  *config.Manager
	Core    *core.Manager
	Server  *server.Manager
	Logging *logging.Manager
	Profile *profile.Manager
	// Security — базовая защита в начале каждой транзакции и ключи установки.
	Security *security.Manager
	// Releases — источник релизов Xray для установки.
	Releases Releases
	// Redactor — реестр редактора: значения состояния регистрируются сразу, как app их узнал.
	Redactor Redactor
	XM       string           // версия xm — в манифест снимка
	Now      func() time.Time // часы платформы
	// ControlTimeout — срок контроля после перезапуска; ноль — 30 секунд.
	ControlTimeout time.Duration
}

// App — прикладной слой.
type App struct{ s Services }

// New создаёт слой поверх менеджеров.
func New(s Services) *App {
	if s.ControlTimeout == 0 {
		s.ControlTimeout = defaultControlTimeout
	}
	return &App{s}
}

// Change — одно изменение системы.
type Change struct {
	Reason string           // причина снимка: [a-z0-9-]
	State  store.State      // новое состояние; поле Applied заполняет транзакция
	Unit   *server.UnitSpec // nil — юнит не меняется
	Core   core.Version     // пусто — ядро не меняется; иначе версия уже выложена (core.Stage)
	// Edit — изменение поверх текущего состояния, вычисляется под блокировкой: чтение и запись
	// не разделены, параллельная команда не потеряет чужое изменение. Задан Edit — State не
	// используется, а установка должна быть (иначе ErrNotInstalled).
	Edit func(store.State) (store.State, error)
	// Create — установка: состояния быть не должно, иначе ErrInstalled. Проверка идёт под
	// блокировкой: две одновременные установки не перезапишут друг друга.
	Create bool
}

// Apply выполняет изменение транзакцией: блокировка → базовая защита → (откат незавершённой) →
// отрисовка → снимок → журнал → проверка `xray run -test` → ядро, юнит, конфигурация, состояние →
// перезапуск → контроль → фиксация. Сбой после журнала — откат; результат отката проверяется.
// Службу, которую владелец остановил, транзакция не запускает: изменение вступит в силу после
// `xm start` (ADR-0025). Срок у ctx обязателен (его требует platform).
func (a *App) Apply(ctx context.Context, ch Change) error {
	unlock, err := a.s.Store.Lock(ctx)
	if err != nil {
		return fmt.Errorf("блокировка: %w", err)
	}
	defer unlock()
	// Каталоги и права по манифесту нужны снимку и журналу; чужие права не исправляются молча,
	// поэтому сбой здесь — отказ до всякого изменения (docs/security/policy.md §2).
	if err := a.s.Security.EnsureBaseline(ctx); err != nil {
		return err
	}
	if _, err := a.recover(ctx); err != nil {
		return err
	}

	// До первого изменения: всё, что можно проверить без записи.
	prev, hadState, err := a.loadPrev()
	if err != nil {
		return err
	}
	if ch.Create && hadState {
		return ErrInstalled
	}
	if ch.Edit != nil {
		if !hadState {
			return ErrNotInstalled
		}
		if ch.State, err = ch.Edit(prev); err != nil {
			return err
		}
	}
	a.register(ch.State)
	coreBefore, err := a.s.Core.Current(ctx)
	if err != nil {
		return err
	}
	version := coreBefore
	if ch.Core != "" {
		version = ch.Core
	}
	if version == "" {
		return errors.New("нет версии Xray: сначала установить ядро")
	}
	st := ch.State
	rendered, err := a.s.Config.Render(st, json.RawMessage(a.s.Logging.XraySection()))
	if err != nil {
		return err
	}
	st.Applied = store.Applied{ConfigSHA256: rendered.SHA256, At: a.s.Now().UTC()}

	unitBefore, err := a.s.Server.Unit()
	if err != nil {
		return err
	}
	status, err := a.s.Server.Service().Status(ctx)
	if err != nil {
		return err
	}
	tx := store.Tx{CoreBefore: string(coreBefore), UnitBefore: unitBefore, WasActive: status.Active == "active", Started: a.s.Now().UTC()}
	// Запускаем службу, что работала, и службу новой установки; остановленную владельцем — нет.
	run := tx.WasActive || unitBefore == nil
	if hadState {
		tx.PortBefore = prev.Server.Port
	}

	snap, err := a.s.Backup.Create(ctx, ch.Reason, backup.Meta{XM: a.s.XM, Xray: string(coreBefore)})
	if err != nil {
		return fmt.Errorf("снимок: %w", err)
	}
	tx.Snapshot = snap.ID
	if err := a.s.Store.WriteTx(tx); err != nil {
		return fmt.Errorf("журнал транзакции: %w", err)
	}

	if err := a.change(ctx, ch, st, rendered, version, coreBefore, run); err != nil {
		return a.fail(ctx, tx, err)
	}
	if err := a.s.Store.ClearTx(); err != nil {
		return fmt.Errorf("фиксация: %w", err)
	}
	// Изменение уже зафиксировано: сбой хранения его не отменяет, а повторится при следующем.
	if err := a.s.Backup.Prune(ctx, backup.AutoKeep); err != nil {
		a.s.Logging.Logger().Warn("старые снимки не удалены", "причина", err.Error())
	}
	return nil
}

// change — шаги 4–7 ADR-0005: после журнала любой сбой откатывается вызывающим.
func (a *App) change(ctx context.Context, ch Change, st store.State, r config.Rendered, version, coreBefore core.Version, run bool) error {
	path, err := a.s.Config.Stage(r)
	if err != nil {
		return err
	}
	// Кандидат с секретами нужен только проверке: убираем сразу, а не в конце.
	err = a.s.Core.Validate(ctx, version, path)
	if uerr := a.s.Config.Unstage(); err == nil {
		err = uerr
	}
	if err != nil {
		return err
	}
	if version != coreBefore {
		if err := a.s.Core.Activate(ctx, version); err != nil {
			return err
		}
	}
	if ch.Unit != nil {
		if err := a.s.Server.InstallUnit(ctx, *ch.Unit); err != nil {
			return err
		}
	}
	if err := a.s.Config.Write(ctx, r); err != nil {
		return err
	}
	if err := a.s.Store.Save(st); err != nil {
		return err
	}
	if !run {
		return nil
	}
	svc := a.s.Server.Service()
	if err := svc.Restart(ctx); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, a.s.ControlTimeout)
	defer cancel()
	return svc.CheckRunning(cctx, st.Server.Port)
}

// fail откатывает транзакцию после сбоя cause и сводит итог в одну из двух ошибок.
func (a *App) fail(ctx context.Context, tx store.Tx, cause error) error {
	a.s.Logging.Logger().Error("транзакция не прошла, откат", "причина", cause.Error())
	if err := a.rollback(ctx, tx); err != nil {
		return fmt.Errorf("%w: %w (причина отката: %w)", ErrRollbackFailed, err, cause)
	}
	return fmt.Errorf("%w: %w", ErrRolledBack, cause)
}

func (a *App) loadPrev() (st store.State, had bool, err error) {
	st, err = a.s.Store.Load()
	if errors.Is(err, store.ErrNoState) {
		return store.State{}, false, nil
	}
	if err != nil {
		return store.State{}, false, fmt.Errorf("состояние: %w", err)
	}
	a.register(st)
	return st, true, nil
}

// Redactor — реестр точных значений редактора (kind — вид значения: key, short-id, server-ip,
// domain). Нужен, чтобы шаблоны не были единственной защитой: shortId шаблон не ловит.
type Redactor interface{ Register(kind, value string) }

// register вносит в редактор секреты и данные установки из состояния.
func (a *App) register(st store.State) {
	r := a.s.Redactor
	for _, in := range st.Inbounds {
		r.Register("key", in.Reality.PrivateKey)
		r.Register("key", in.Reality.PublicKey)
		for _, id := range in.Reality.ShortIDs {
			r.Register("short-id", id)
		}
		for _, n := range in.Reality.ServerNames {
			r.Register("domain", n)
		}
	}
	for _, p := range st.Profiles {
		r.Register("uuid", p.ID)
	}
	ad := st.Server.Addresses
	r.Register("server-ip", ad.IPv4)
	r.Register("server-ip", ad.IPv6)
	r.Register("domain", ad.Domain)
}

// Recover откатывает незавершённую транзакцию, если следующий запуск xm её нашёл
// (ADR-0005). Возвращает, был ли откат.
func (a *App) Recover(ctx context.Context) (bool, error) {
	unlock, err := a.s.Store.Lock(ctx)
	if err != nil {
		return false, fmt.Errorf("блокировка: %w", err)
	}
	defer unlock()
	return a.recover(ctx)
}

func (a *App) recover(ctx context.Context) (bool, error) {
	tx, ok, err := a.s.Store.ReadTx()
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrRollbackFailed, err)
	}
	if !ok {
		return false, nil
	}
	a.s.Logging.Logger().Warn("найдена незавершённая транзакция, откат", "снимок", tx.Snapshot)
	if err := a.rollback(ctx, tx); err != nil {
		return false, fmt.Errorf("%w: %w", ErrRollbackFailed, err)
	}
	return true, nil
}

// rollback возвращает систему к снимку и журналу: служба останавливается, возвращаются ядро,
// юнит, состояние и конфигурация; служба, что работала, поднимается и проходит контроль.
// Отмена ctx откат не прерывает: он идёт под собственным сроком.
func (a *App) rollback(ctx context.Context, tx store.Tx) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	arch, err := a.s.Backup.Read(ctx, tx.Snapshot)
	if err != nil {
		return fmt.Errorf("снимок %s: %w", tx.Snapshot, err)
	}
	svc := a.s.Server.Service()
	st, err := svc.Status(ctx)
	if err != nil {
		return err
	}
	if st.Loaded && st.Active != "inactive" {
		if err := svc.Stop(ctx); err != nil {
			return err
		}
	}
	if tx.CoreBefore != "" {
		before := core.Version(tx.CoreBefore)
		cur, err := a.s.Core.Current(ctx)
		if err != nil {
			return err
		}
		if cur != before {
			if err := a.s.Core.Activate(ctx, before); err != nil {
				return err
			}
		}
	}
	if err := a.s.Server.RestoreUnit(ctx, tx.UnitBefore); err != nil {
		return err
	}
	if err := a.s.Store.Restore(arch.State); err != nil {
		return err
	}
	if arch.Config != nil {
		err = a.s.Config.Write(ctx, config.Rendered{Data: arch.Config})
	} else {
		err = a.s.Config.Remove()
	}
	if err != nil {
		return err
	}
	if err := a.s.Config.Unstage(); err != nil {
		return err
	}
	if tx.UnitBefore != nil && tx.WasActive {
		// Службы без состояния не бывает; порта нет — поднимать и проверять нечего, служба
		// остаётся остановленной (ADR-0023).
		if tx.PortBefore == 0 {
			return a.s.Store.ClearTx()
		}
		if err := svc.Restart(ctx); err != nil {
			return err
		}
		cctx, cancel := context.WithTimeout(ctx, a.s.ControlTimeout)
		defer cancel()
		if err := svc.CheckRunning(cctx, tx.PortBefore); err != nil {
			return fmt.Errorf("после отката: %w", err)
		}
	}
	return a.s.Store.ClearTx()
}
