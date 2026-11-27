package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/store"
	"github.com/grokki91/xray_core/internal/update"
)

// selfUnchecked — чего контроль после `xm update --self` не доказывает.
const selfUnchecked = "подлинность релиза xm держится на HTTPS до GitHub и SHA256SUMS того же релиза, как у install.sh"

// Self — релизы и бинарник самого xm (ADR-0045); настоящий — update.Self.
type Self interface {
	Latest(ctx context.Context) (update.Release, error)
	Stage(ctx context.Context, r update.Release) error
	Probe(ctx context.Context) (string, error)
	Apply(ctx context.Context, prev string) ([]byte, int, error)
	Install() error
	Restore() error
	Discard() error
}

// updateSelf — `xm update --self` в старом xm: загрузка, сверка, проверка версии нового
// бинарника и запуск его `self-apply`; транзакцию ведёт новый xm (ADR-0045).
func (a *App) updateSelf(ctx context.Context) (contract.Update, error) {
	if err := a.needRoot(); err != nil {
		return contract.Update{}, err
	}
	if err := a.selfInstalled(ctx); err != nil {
		return contract.Update{}, err
	}
	r, err := a.s.Self.Latest(ctx)
	if err != nil {
		return contract.Update{}, err
	}
	res := contract.Update{Component: contract.ComponentXM, Current: a.s.XM, Target: r.Version(), Latest: r.Version(),
		InRange: true, Checked: a.s.Now().UTC().Format(time.RFC3339), Unchecked: selfUnchecked}
	if !update.NewerSelf(res.Target, res.Current) {
		return res, nil
	}
	defer func() {
		if err := a.s.Self.Discard(); err != nil {
			a.s.Logging.Logger().Warn("новый бинарник xm не убран", "причина", err.Error())
		}
	}()
	if err := a.s.Self.Stage(ctx, r); err != nil {
		return contract.Update{}, err
	}
	v, err := a.s.Self.Probe(ctx)
	if err != nil {
		return contract.Update{}, err
	}
	if v != res.Target {
		return contract.Update{}, fmt.Errorf("новый xm сообщает версию %q, а релиз — %s: %w", v, res.Target, update.ErrIntegrity)
	}
	out, code, err := a.s.Self.Apply(ctx, res.Current)
	if err != nil {
		return contract.Update{}, err
	}
	return selfResult(out, code)
}

// selfInstalled — состояние есть; незавершённая транзакция откатывается здесь, старым xm: её
// журнал записан этой версией.
func (a *App) selfInstalled(ctx context.Context) error {
	unlock, err := a.s.Store.Lock(ctx)
	if err != nil {
		return fmt.Errorf("блокировка: %w", err)
	}
	defer unlock()
	if _, err := a.recover(ctx); err != nil {
		return err
	}
	_, ok, err := a.installed()
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotInstalled
	}
	return nil
}

// selfResult разбирает документ нового xm: данные — итог, ошибка — та же ошибка с тем же
// классом, чтобы код выхода совпал.
func selfResult(out []byte, code int) (contract.Update, error) {
	var doc struct {
		Data  *contract.Update `json:"data"`
		Error *contract.Error  `json:"error"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return contract.Update{}, fmt.Errorf("новый xm (код %d): ответ не разобран", code)
	}
	switch {
	case doc.Error != nil:
		cause := errors.New(doc.Error.Message)
		switch doc.Error.Code {
		case "app.rollback_failed":
			return contract.Update{}, fmt.Errorf("%w: новый xm: %w", ErrRollbackFailed, cause)
		case "app.rolled_back":
			return contract.Update{}, fmt.Errorf("%w: новый xm: %w", ErrRolledBack, cause)
		}
		return contract.Update{}, fmt.Errorf("новый xm: %w", cause)
	case doc.Data == nil || code != 0:
		return contract.Update{}, fmt.Errorf("новый xm (код %d): нет итога", code)
	}
	return *doc.Data, nil
}

// SelfApply — служебная команда `self-apply` нового xm (ADR-0045): поставить себя на место
// действующего и применить состояние своими правилами одной транзакцией. Провал — прежний
// бинарник на месте.
func (a *App) SelfApply(ctx context.Context, previous string) (res contract.Update, err error) {
	if !update.ValidSelfVersion(previous) {
		return contract.Update{}, fmt.Errorf("%w: --previous: версия xm недопустима", ErrInput)
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	if err := a.needRoot(); err != nil {
		return contract.Update{}, err
	}
	unlock, err := a.s.Store.Lock(ctx)
	if err != nil {
		return contract.Update{}, fmt.Errorf("блокировка: %w", err)
	}
	defer unlock()
	if _, err := a.recover(ctx); err != nil {
		return contract.Update{}, err
	}
	if _, ok, err := a.installed(); err != nil {
		return contract.Update{}, err
	} else if !ok {
		return contract.Update{}, ErrNotInstalled
	}
	// Замена — до журнала транзакции (ADR-0045): после неё откат знает, что возвращать.
	if err := a.s.Self.Install(); err != nil {
		if rerr := a.s.Self.Restore(); rerr != nil && !errors.Is(rerr, update.ErrNoPreviousXM) {
			return contract.Update{}, fmt.Errorf("%w: %w; прежний xm: %w", ErrRollbackFailed, err, rerr)
		}
		return contract.Update{}, err
	}
	err = a.apply(ctx, Change{Reason: "self-update", XMReplaced: true, Edit: func(st store.State) (store.State, error) {
		st.XM.Previous = previous
		return st, nil
	}})
	if err != nil {
		// Откат транзакции уже вернул бинарник; провал до журнала — нет. Повтор безопасен.
		if rerr := a.s.Self.Restore(); rerr != nil {
			return contract.Update{}, fmt.Errorf("%w: %w; прежний xm: %w", ErrRollbackFailed, err, rerr)
		}
		return contract.Update{}, err
	}
	return contract.Update{Component: contract.ComponentXM, Current: previous, Target: a.s.XM, Latest: a.s.XM,
		InRange: true, Updated: true, Checked: a.s.Now().UTC().Format(time.RFC3339), Unchecked: selfUnchecked}, nil
}
