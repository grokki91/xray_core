package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/logging"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/redact"
)

// Новый процесс xm ещё ничего не регистрировал в редакторе: Logs берёт данные установки из
// состояния до чтения, и домен установки из строки журнала не выходит.
func TestLogsRedactsStateSecretsInFreshProcess(t *testing.T) {
	s := installed(t)
	reg := redact.New()
	svc := s.app.s
	svc.Redactor, svc.Logging = regAdapter{reg}, logging.New(s.f, reg, slog.LevelInfo)
	fresh := New(svc)
	s.f.HandleStream(platform.Journalctl, func(platform.Command) (io.Reader, error) {
		return strings.NewReader(`{"__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"xray","MESSAGE":"sni example.com"}` + "\n"), nil
	})
	var out strings.Builder
	if err := fresh.Logs(ctx(t), LogsOptions{}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "xray: sni ") || strings.Contains(out.String(), "example.com") {
		t.Fatalf("вывод: %q", out.String())
	}
}

// Неверный --since — ошибка ввода (код 2), journalctl не запускается.
func TestLogsBadSinceIsInput(t *testing.T) {
	s := newFresh(t)
	if err := s.app.Logs(ctx(t), LogsOptions{Since: "вчера"}, io.Discard); !errors.Is(err, ErrInput) {
		t.Fatalf("%v, нужно ErrInput", err)
	}
	for _, c := range s.f.Calls() {
		if c.Op == "stream" {
			t.Fatalf("journalctl запущен: %+v", c)
		}
	}
}

// Конец слежения -f по отмене (Ctrl-C) — не ошибка.
func TestLogsFollowCancelIsOK(t *testing.T) {
	s := newFresh(t)
	pr, _ := io.Pipe()
	s.f.HandleStream(platform.Journalctl, func(platform.Command) (io.Reader, error) { return pr, nil })
	c, cancel := context.WithCancel(ctx(t))
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	go func() { <-c.Done(); pr.CloseWithError(c.Err()) }()
	if err := s.app.Logs(c, LogsOptions{Follow: true}, io.Discard); err != nil {
		t.Fatalf("%v", err)
	}
}
