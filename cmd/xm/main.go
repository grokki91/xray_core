// Команда xm — менеджер Xray-core. Здесь только сборка зависимостей: логика живёт в internal.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/cli"
	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/logging"
	"github.com/grokki91/xray_core/internal/network"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/profile"
	"github.com/grokki91/xray_core/internal/redact"
	"github.com/grokki91/xray_core/internal/security"
	"github.com/grokki91/xray_core/internal/server"
	"github.com/grokki91/xray_core/internal/store"
	"github.com/grokki91/xray_core/internal/update"
)

// version подставляется при сборке: -ldflags "-X main.version=<версия>". Пакетная переменная —
// единственный способ принять значение от компоновщика; после старта она не меняется.
var version = "dev"

// registry связывает app с редактором: app называет вид значения строкой и не знает пакета redact.
type registry struct{ r *redact.Redactor }

func (g registry) Register(kind, value string) { g.r.Register(redact.Kind(kind), value) }

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
	token := githubToken(os.Getenv, reg)
	a := app.New(app.Services{
		Store:    store.New(p.FS()),
		Backup:   backup.New(p),
		Config:   config.New(p),
		Core:     core.New(p),
		Server:   server.New(p, config.Path),
		Logging:  logging.New(p, reg, slog.LevelInfo),
		Profile:  profile.New(),
		Network:  network.New(p),
		Security: security.New(p),
		Redactor: registry{reg},
		Host:     p,
		Releases: update.NewGitHub(p, token),
		Checks:   update.NewChecks(p),
		XM:       version,
		Now:      p.Clock().Now,
	})
	return cli.Run(os.Args[1:], cli.Env{
		Ctx: ctx, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Version: version, Clock: p.Clock(), App: a, Redact: reg.Text,
	})
}

// githubToken — значение update.TokenEnv (ADR-0031). Верное по формату регистрируется в
// редакторе; неверное — нет: короткое значение редактор заменял бы во всём выводе, а команду,
// которой нужен релиз, всё равно остановит проверка формата в update.
func githubToken(getenv func(string) string, reg *redact.Redactor) string {
	t := getenv(update.TokenEnv)
	if update.ValidToken(t) {
		reg.Register(redact.Token, t)
	}
	return t
}
