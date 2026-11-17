package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// ErrControl — контроль после изменения не пройден (ADR-0023).
var ErrControl = errors.New("контроль не пройден")

const (
	// controlStep — интервал опроса; settle — выдержка после первого успеха: цикл перезапусков
	// не виден по одному снимку состояния (NRestarts растёт после первого авто-перезапуска).
	controlStep = 500 * time.Millisecond
	settle      = 2 * time.Second
)

// CheckRunning ждёт до срока ctx, пока служба станет активной и порт port начнёт слушаться, и
// после выдержки проверяет это ещё раз: активна, не перезапускалась, порт слушается. Срок у
// ctx обязателен. Доступность извне и сквозная самопроверка — не здесь (фаза 3).
//
// «Не перезапускалась» — NRestarts не вырос от первого снимка контроля: ручной перезапуск, пока
// systemd ждёт авто-перезапуска, счётчик не обнуляет (ADR-0023, compatibility.md). Вызывать
// сразу после запуска: раньше RestartSec авто-перезапуск счётчик не изменит.
func (s Service) CheckRunning(ctx context.Context, port int) error {
	base := -1
	return s.wait(ctx, func(st platform.UnitStatus, on bool) (ok bool, fatal string) {
		if base < 0 {
			base = st.Restarts
		}
		switch {
		case !st.Loaded:
			return false, "юнит не найден"
		case st.Restarts > base:
			return false, "служба перезапускалась после запуска"
		case st.Active == "failed":
			return false, "служба завершилась с ошибкой"
		}
		return st.Active == "active" && st.Sub == "running" && on, ""
	}, true, port)
}

// CheckStopped ждёт, пока служба станет неактивной и порт port освободится (контроль `xm stop`).
func (s Service) CheckStopped(ctx context.Context, port int) error {
	return s.wait(ctx, func(st platform.UnitStatus, on bool) (bool, string) {
		return st.Active == "inactive" && !on, ""
	}, false, port)
}

type probe func(st platform.UnitStatus, listening bool) (ok bool, fatal string)

func (s Service) wait(ctx context.Context, check probe, again bool, port int) error {
	if _, ok := ctx.Deadline(); !ok {
		return platform.ErrDeadline
	}
	confirmed := false
	for {
		st, on, err := s.observe(ctx, port)
		if err != nil {
			return err
		}
		ok, fatal := check(st, on)
		switch {
		case fatal != "":
			return fmt.Errorf("%w: %s", ErrControl, fatal)
		case ok && (confirmed || !again):
			return nil
		case ok:
			confirmed = true
			if err := s.clock.Sleep(ctx, settle); err != nil {
				return fmt.Errorf("%w: %w", ErrControl, err)
			}
			continue
		}
		confirmed = false
		if err := s.clock.Sleep(ctx, controlStep); err != nil {
			return fmt.Errorf("%w: состояние %s/%s, порт слушается: %t: %w", ErrControl, st.Active, st.Sub, on, err)
		}
	}
}

// observe снимает состояние службы и порта; ошибка по сроку — это непройденный контроль.
func (s Service) observe(ctx context.Context, port int) (platform.UnitStatus, bool, error) {
	st, err := s.s.Status(ctx)
	var on bool
	if err == nil {
		on, err = s.net.Listening(ctx, port)
	}
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("%w: %w", ErrControl, ctx.Err())
	}
	return st, on, err
}
