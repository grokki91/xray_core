// Команда xm — менеджер Xray-core. Здесь только сборка зависимостей: логика живёт в internal.
package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/cli"
	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/logging"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/redact"
	"github.com/grokki91/xray_core/internal/security"
	"github.com/grokki91/xray_core/internal/server"
	"github.com/grokki91/xray_core/internal/store"
	"github.com/grokki91/xray_core/internal/update"
)

// version подставляется при сборке: -ldflags "-X main.version=<версия>". Пакетная переменная —
// единственный способ принять значение от компоновщика; после старта она не меняется.
var version = "dev"

// redactingWriter пропускает вывод через редактор: сообщения об ошибках берутся из системы и не
// должны нести данные установки. Один Write — одно сообщение: cli пишет их целиком.
type redactingWriter struct {
	w io.Writer
	r *redact.Redactor
}

func (rw redactingWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(rw.w, rw.r.Text(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

func main() {
	// Ctrl-C отменяет команду, но не откат транзакции: он идёт под собственным сроком. Убитый
	// процесс оставляет журнал, и следующий запуск откатит транзакцию (ADR-0005).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx)
	stop()
	os.Exit(code)
}

func run(ctx context.Context) int {
	p := platform.New()
	reg := redact.New()
	a := app.New(app.Services{
		Store:    store.New(p.FS()),
		Backup:   backup.New(p),
		Config:   config.New(p),
		Core:     core.New(p),
		Server:   server.New(p, config.Path),
		Logging:  logging.New(p, reg, slog.LevelInfo),
		Security: security.New(p),
		Releases: update.NewGitHub(p),
		XM:       version,
		Now:      p.Clock().Now,
	})
	return cli.Run(os.Args[1:], cli.Env{
		Ctx: ctx, Stdout: os.Stdout, Stderr: redactingWriter{os.Stderr, reg}, Version: version, Clock: p.Clock(), App: a,
	})
}
