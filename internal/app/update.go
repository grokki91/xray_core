package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/store"
	"github.com/grokki91/xray_core/internal/update"
)

const updateTimeout = 15 * time.Minute

// updateUnchecked — чего контроль после обновления не доказывает (docs/operations/updates.md §5).
const updateUnchecked = "подключение сторонних клиентских ядер (sing-box и его форки) не проверялось: его закрывают проверенный диапазон и таблица совместимости клиентов"

// ErrNoPrevious — `xm update --rollback`: предыдущей версии нет в состоянии или на диске.
var ErrNoPrevious = errors.New("предыдущей версии Xray нет: откатывать не на что")

// UpdateOptions — параметры `xm update`. To — версия N.N.N (допустима ведущая «v»); пусто —
// последняя стабильная внутри проверенного диапазона. Rollback — вернуть предыдущую версию
// (updates.md §6); с Check и To не сочетается.
type UpdateOptions struct {
	Check    bool
	To       string
	Rollback bool
}

// Update выбирает версию Xray и, кроме --check и удержания, переключает на неё транзакцией с
// контролем и автоматическим откатом (docs/operations/updates.md §4–§6). Итог проверки без --to
// сохраняется для `xm status`.
func (a *App) Update(ctx context.Context, o UpdateOptions) (contract.Update, error) {
	to := strings.TrimPrefix(o.To, "v")
	if o.To != "" {
		if _, err := core.ParseVersion(to); err != nil {
			return contract.Update{}, fmt.Errorf("%w: --to: %w", ErrInput, err)
		}
	}
	if o.Rollback && (o.Check || o.To != "") {
		return contract.Update{}, fmt.Errorf("%w: --rollback не сочетается с --check и --to", ErrInput)
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	if err := a.needRoot(); err != nil {
		return contract.Update{}, err
	}
	// Одна блокировка от чтения состояния до удаления старых версий: параллельная команда не
	// подменит активную версию между выбором и транзакцией и не потеряет выложенную (updates.md §4, шаг 1).
	unlock, err := a.s.Store.Lock(ctx)
	if err != nil {
		return contract.Update{}, fmt.Errorf("блокировка: %w", err)
	}
	defer unlock()
	if _, err := a.recover(ctx); err != nil {
		return contract.Update{}, err
	}
	st, ok, err := a.installed()
	if err != nil {
		return contract.Update{}, err
	}
	if !ok {
		return contract.Update{}, ErrNotInstalled
	}
	cur, err := a.s.Core.Current(ctx)
	if err != nil {
		return contract.Update{}, err
	}
	rg := update.Verified()
	res := contract.Update{Current: string(cur), Range: contract.Range{Min: rg.Min, Max: rg.Max},
		Held: st.Core.Hold, Unchecked: updateUnchecked}

	if o.Rollback {
		return a.rollbackCore(ctx, st, cur, res)
	}

	var target update.Release
	if to != "" {
		target, err = a.s.Releases.Tag(ctx, to)
	} else {
		var latest update.Release
		target, latest, err = update.Choose(ctx, a.s.Releases, rg)
		res.Latest = latest.Version()
	}
	if err != nil {
		return contract.Update{}, err
	}
	now := a.s.Now().UTC()
	res.Target, res.InRange, res.Checked = target.Version(), rg.Contains(target.Version()), now.Format(time.RFC3339)
	if to == "" {
		if err := a.s.Checks.Save(update.Check{Target: res.Target, Latest: res.Latest, Checked: now}); err != nil {
			return contract.Update{}, err
		}
	}
	if o.Check || res.Held || res.Target == res.Current {
		return res, nil
	}

	v := core.Version(res.Target)
	arch, err := a.s.Releases.Fetch(ctx, target, update.ArchAMD64)
	if err != nil {
		return contract.Update{}, err
	}
	if err := a.s.Core.Stage(ctx, v, arch.Data); err != nil {
		return contract.Update{}, err
	}
	// До транзакции: новая версия проверяет действующую конфигурацию, провал не трогает службу
	// (updates.md §4, шаг 3); откат транзакции её перезапускал бы.
	if err := a.s.Core.Validate(ctx, v, config.Path); err != nil {
		return contract.Update{}, err
	}
	err = a.apply(ctx, Change{Reason: "update", Core: v, Edit: func(st store.State) (store.State, error) {
		st.Core.Previous, st.Core.Version = string(cur), string(v)
		return st, nil
	}})
	if err != nil {
		return contract.Update{}, err
	}
	res.Updated = true
	// Версии старше предыдущей удаляются только после успешного контроля; провал удаления не
	// отменяет обновление.
	if err := a.s.Core.Prune(v, cur); err != nil {
		a.s.Logging.Logger().Warn("старые версии Xray не удалены", "причина", err.Error())
	}
	return res, nil
}

// rollbackCore — `xm update --rollback`: та же транзакция в обратную сторону, без сети
// (updates.md §6). Удержание соблюдается; каталоги версий не удаляются: обе остаются для
// повторного переключения. Провал контроля — автоматический возврат на активную версию.
func (a *App) rollbackCore(ctx context.Context, st store.State, cur core.Version, res contract.Update) (contract.Update, error) {
	if st.Core.Previous == "" || st.Core.Previous == string(cur) {
		return contract.Update{}, ErrNoPrevious
	}
	prev := core.Version(st.Core.Previous)
	rg := update.Verified()
	res.Target, res.InRange, res.Checked = string(prev), rg.Contains(string(prev)), a.s.Now().UTC().Format(time.RFC3339)
	if res.Held {
		return res, nil
	}
	if err := a.s.Core.Validate(ctx, prev, config.Path); err != nil {
		if errors.Is(err, core.ErrNotStaged) {
			return contract.Update{}, fmt.Errorf("%w: каталог версии %s удалён", ErrNoPrevious, prev)
		}
		return contract.Update{}, err
	}
	err := a.apply(ctx, Change{Reason: "rollback", Core: prev, Edit: func(st store.State) (store.State, error) {
		st.Core.Previous, st.Core.Version = string(cur), string(prev)
		return st, nil
	}})
	if err != nil {
		return contract.Update{}, err
	}
	res.Updated = true
	return res, nil
}

// available — доступное обновление для status по итогу последней проверки, без сети.
func (a *App) available(cur core.Version) (contract.Available, error) {
	ch, ok, err := a.s.Checks.Load()
	if err != nil || !ok {
		return contract.Available{}, err
	}
	out := contract.Available{Checked: ch.Checked.UTC().Format(time.RFC3339)}
	if cur == "" || update.Compare(ch.Target, string(cur)) > 0 {
		out.Version = ch.Target
	}
	return out, nil
}
