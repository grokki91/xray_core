package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/store"
)

const backupTimeout = 2 * time.Minute

// Backup создаёт ручной снимок установки (data-model.md §4) и оставляет ManualKeep последних
// ручных; автоснимки не трогаются. Систему не меняет, но идёт под блокировкой транзакции: она
// обеспечивает единственность идентификатора и не даёт снять состояние посреди изменения.
func (a *App) Backup(ctx context.Context) (contract.BackupItem, error) {
	if err := a.needRoot(); err != nil {
		return contract.BackupItem{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	unlock, err := a.s.Store.Lock(ctx)
	if err != nil {
		return contract.BackupItem{}, fmt.Errorf("блокировка: %w", err)
	}
	defer unlock()
	if err := a.s.Security.EnsureBaseline(ctx); err != nil {
		return contract.BackupItem{}, err
	}
	// Незавершённая транзакция сначала откатывается: снимок фиксирует целое состояние.
	if _, err := a.recover(ctx); err != nil {
		return contract.BackupItem{}, err
	}
	if _, ok, err := a.installed(); err != nil {
		return contract.BackupItem{}, err
	} else if !ok {
		return contract.BackupItem{}, ErrNotInstalled
	}
	xray, err := a.s.Core.Current(ctx)
	if err != nil {
		return contract.BackupItem{}, err
	}
	meta := backup.Meta{XM: a.s.XM, Xray: string(xray)}
	snap, err := a.s.Backup.Create(ctx, backup.ManualReason, meta)
	if err != nil {
		return contract.BackupItem{}, fmt.Errorf("снимок (один ручной снимок в секунду): %w", err)
	}
	// Снимок уже создан: сбой хранения его не отменяет и повторится при следующем.
	if err := a.s.Backup.Prune(ctx, backup.Manual, backup.ManualKeep); err != nil {
		a.s.Logging.Logger().Warn("старые ручные снимки не удалены", "причина", err.Error())
	}
	return contract.BackupItem{ID: snap.ID, Created: snap.Created.Unix(), Kind: string(backup.Manual), XM: meta.XM, Xray: meta.Xray, Valid: true}, nil
}

// BackupList — снимки от старого к новому, каждый проверен (`xm backup --list`).
func (a *App) BackupList(ctx context.Context) (contract.Backups, error) {
	if err := a.needRoot(); err != nil {
		return contract.Backups{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	list, err := a.s.Backup.List(ctx)
	if err != nil {
		return contract.Backups{}, err
	}
	out := contract.Backups{Backups: []contract.BackupItem{}}
	for _, e := range list {
		out.Backups = append(out.Backups, contract.BackupItem{ID: e.ID, Created: e.Created.Unix(), Kind: string(e.Kind),
			XM: e.Manifest.XM, Xray: e.Manifest.Xray, Valid: e.Corrupt == nil})
	}
	return out, nil
}

// ErrSnapshot — снимок нельзя восстановить: его нет, он повреждён или в нём нет целого
// состояния. Ничего не изменено. Код выхода 1.
var ErrSnapshot = errors.New("снимок нельзя восстановить")

// Restore восстанавливает установку из снимка id (data-model.md §4): проверка манифеста и сумм
// → обычная транзакция с состоянием из архива; её автоснимок сохраняет текущее состояние.
// Конфигурация Xray перерисовывается из восстановленного состояния (инвариант 3), версия ядра
// не меняется. Подтверждение — забота адаптера.
func (a *App) Restore(ctx context.Context, id string) error {
	if err := a.needRoot(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	// Текущее состояние может быть повреждено: транзакция его не требует (Change.Restore).
	// Снимок читается под блокировкой: хранение другой транзакции не удалит его между
	// проверкой и применением.
	return a.Apply(ctx, Change{Reason: "restore", Restore: func(prev *store.State) (store.State, error) {
		arch, err := a.s.Backup.Read(ctx, id)
		switch {
		case errors.Is(err, backup.ErrInput):
			return store.State{}, fmt.Errorf("%w: идентификатор снимка — как в xm backup --list", ErrInput)
		case err != nil:
			return store.State{}, fmt.Errorf("%w: %w", ErrSnapshot, err)
		case arch.State == nil:
			return store.State{}, fmt.Errorf("%w: %s снят до установки, в нём нет состояния", ErrSnapshot, id)
		}
		st, err := a.s.Store.Parse(arch.State)
		if err != nil {
			return store.State{}, fmt.Errorf("%w: состояние в %s не проходит проверку: %w", ErrSnapshot, id, err)
		}
		// Правило UFW открыто для текущего порта; другой порт снимка закрыл бы службу для
		// клиентов, а самопроверка с петли этого не заметит.
		if prev != nil && prev.Server.Port != st.Server.Port {
			return store.State{}, fmt.Errorf("%w: порт в %s — %d, у установки — %d; восстановление сменило бы порт", ErrSnapshot, id, st.Server.Port, prev.Server.Port)
		}
		return st, nil
	}})
}
