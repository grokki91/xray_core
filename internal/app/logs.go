package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/grokki91/xray_core/internal/logging"
)

const (
	logsTimeout = 30 * time.Second
	// logsFollowLimit — срок `xm logs -f`: у процесса срок обязателен; прерывается он Ctrl-C.
	logsFollowLimit = 24 * time.Hour
)

// LogsOptions — флаги `xm logs`.
type LogsOptions struct {
	Since  string
	Follow bool
}

// Logs печатает в w журнал Xray и xm. Данные установки регистрируются в редакторе до чтения:
// строки журнала проходят его в logging. Установки нет — журнал всё равно читается.
func (a *App) Logs(ctx context.Context, o LogsOptions, w io.Writer) error {
	limit := logsTimeout
	if o.Follow {
		limit = logsFollowLimit
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	if err := a.needRoot(); err != nil {
		return err
	}
	if _, _, err := a.installed(); err != nil { // чтение состояния регистрирует его в редакторе
		return err
	}
	rc, err := a.s.Logging.XrayLog(ctx, logging.Query{Since: o.Since, Follow: o.Follow})
	if errors.Is(err, logging.ErrSince) {
		return fmt.Errorf("%w: %w", ErrInput, err)
	}
	if err != nil {
		return err
	}
	defer rc.Close()
	_, err = io.Copy(w, rc)
	if o.Follow && errors.Is(ctx.Err(), context.Canceled) {
		return nil // Ctrl-C — обычный конец слежения
	}
	return err
}
