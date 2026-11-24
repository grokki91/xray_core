package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/server"
)

const uninstallTimeout = 5 * time.Minute

// Uninstall удаляет установку xm (ADR-0042). Это не транзакция: шаги идут в постоянном порядке —
// снимок (без purge) → остановка службы → юнит → правило UFW, поставленное xm → бинарники
// Xray и xm → с purge конфигурация, данные, снимки, пользователь xray и последним состояние.
// Каждый шаг с отсутствующим предметом — не ошибка: после сбоя повтор доводит удаление до
// конца. Чужой юнит — отказ до всякого изменения. Подтверждение purge — забота адаптера.
func (a *App) Uninstall(ctx context.Context, purge bool) error {
	ctx, cancel := context.WithTimeout(ctx, uninstallTimeout)
	defer cancel()
	if err := a.needRoot(); err != nil {
		return err
	}
	unlock, err := a.s.Store.Lock(ctx)
	if err != nil {
		return fmt.Errorf("блокировка: %w", err)
	}
	defer unlock()
	// Незавершённая транзакция откатывается, пока ядро на месте: удаляется целая установка.
	if _, err := a.recover(ctx); err != nil {
		return err
	}
	st, ok, err := a.installed()
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotInstalled
	}
	// Чужой юнит — отказ с кодом 3 до всякого изменения (docs/security/policy.md §8).
	if _, err := a.s.Server.Unit(); errors.Is(err, server.ErrForeign) {
		return &PreflightError{[]server.Issue{{Code: server.CodeForeignInstall,
			Message: "найден " + server.UnitPath + " без метки xm: чужая установка Xray, ничего не удалено"}}}
	} else if err != nil {
		return err
	}
	xray, err := a.s.Core.Current(ctx)
	if err != nil {
		return err
	}
	// Состояние и снимки остаются: снимок фиксирует установку до удаления. Ядра уже нет —
	// прошлый uninstall дошёл до бинарников, снимок у него есть.
	if !purge && xray != "" {
		if _, err := a.s.Backup.Create(ctx, "uninstall", backup.Meta{XM: a.s.XM, Xray: string(xray)}); err != nil {
			return fmt.Errorf("снимок: %w", err)
		}
	}
	svc := a.s.Server.Service()
	status, err := svc.Status(ctx)
	if err != nil {
		return err
	}
	if status.Loaded && status.Active != "inactive" {
		if err := svc.Stop(ctx); err != nil {
			return err
		}
	}
	if err := a.s.Server.RemoveUnit(ctx); err != nil {
		return err
	}
	// Только правило, поставленное xm (метка в состоянии, ADR-0041); чужие правила не трогаются.
	if st.Firewall.UFWRule {
		if err := a.s.Network.RevokePort(ctx, st.Server.Port); err != nil {
			return err
		}
	}
	return a.s.Security.Remove(ctx, purge)
}
