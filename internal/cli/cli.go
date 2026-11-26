// Пакет cli — адаптер командной строки: разбирает аргументы, вызывает прикладной слой и
// показывает результат. Таблица команд и коды выхода — docs/architecture/interfaces.md §1.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/contract"
)

// Коды выхода — docs/architecture/interfaces.md §1.
const (
	exitOK        = 0
	exitFail      = 1
	exitUsage     = 2
	exitPreflight = 3
	exitRollback  = 5
)

// Clock — источник времени для поля time машинного вывода; настоящий даёт platform.
type Clock interface {
	Now() time.Time
}

// App — сценарии, которые вызывают команды; настоящий — app.App.
type App interface {
	Install(ctx context.Context, o app.InstallOptions) (app.InstallResult, error)
	Uninstall(ctx context.Context, purge bool) error
	Service(ctx context.Context, a app.Action) error
	Status(ctx context.Context) (contract.Status, error)
	Update(ctx context.Context, o app.UpdateOptions) (contract.Update, error)
	ProfileAdd(ctx context.Context, name string, o app.ShareOptions) (app.ProfileView, error)
	ProfileList(ctx context.Context) (contract.Profiles, error)
	ProfileShow(ctx context.Context, name string, o app.ShareOptions) (app.ProfileView, error)
	ProfileRemove(ctx context.Context, name string) error
}

// Env — то, что получает команда: потоки вывода, версия сборки, часы и прикладной слой. Ctx
// отменяется по сигналу; сроки операций задаёт сам прикладной слой.
type Env struct {
	Ctx            context.Context
	Stdin          io.Reader // ввод слова подтверждения разрушительных действий
	Stdout, Stderr io.Writer
	Version        string
	Clock          Clock
	App            App
	// Redact убирает данные установки из текстов ошибок: они приходят из системы. Нужен везде,
	// где печатается ошибка сценария — в stderr и в документе error.
	Redact func(string) string
}

type command struct {
	name    string
	usage   string
	summary string
	json    bool                   // команда поддерживает --json
	flags   func(fs *flag.FlagSet) // объявление собственных флагов
	// args — позиционные аргументы: сколько обязательных и сколько допустимых; флаги можно
	// ставить до, между и после них.
	minArgs, maxArgs int
	run              func(e Env, fs *flag.FlagSet, args []string, asJSON bool) int
}

// commands — закрытый список команд в порядке справки.
func commands() []command {
	return []command{
		{name: "install", usage: "xm install [--sni <домен>] [--address <адрес>] [--port <порт>]",
			summary: "установить Xray и запустить службу", flags: installFlags, run: runInstall},
		{name: "uninstall", usage: "xm uninstall [--purge [--yes]]",
			summary: "удалить службу и бинарники; --purge — ещё состояние и снимки", flags: uninstallFlags, run: runUninstall},
		{name: "start", usage: "xm start", summary: "запустить службу Xray", run: service(app.Start)},
		{name: "stop", usage: "xm stop", summary: "остановить службу Xray", run: service(app.Stop)},
		{name: "restart", usage: "xm restart", summary: "перезапустить службу Xray", run: service(app.Restart)},
		{name: "status", usage: "xm status [--json]", summary: "состояние службы, версии, адреса, порт",
			json: true, run: runStatus},
		{name: "update", usage: "xm update [--check] [--to <версия>] [--json]",
			summary: "обновить Xray до последней проверенной версии с контролем и откатом", json: true, flags: updateFlags, run: runUpdate},
		{name: "add", usage: "xm add [имя] [--client <id>] [--address <адрес>] [--json]",
			summary: "создать профиль, показать ссылки и QR", json: true, flags: shareFlags, maxArgs: 1, run: runAdd},
		{name: "list", usage: "xm list [--json]", summary: "профили: имя, дата, состояние", json: true, run: runList},
		{name: "show", usage: "xm show <имя> [--client <id>] [--address <адрес>] [--json]",
			summary: "ссылки и QR профиля повторно", json: true, flags: shareFlags, minArgs: 1, maxArgs: 1, run: runShow},
		{name: "rm", usage: "xm rm <имя>", summary: "удалить профиль", minArgs: 1, maxArgs: 1, run: runRemove},
		{name: "version", usage: "xm version [--json]", summary: "версия xm", json: true, run: runVersion},
		{name: "help", usage: "xm help", summary: "эта справка", run: runHelp},
	}
}

// Коды ошибок аргументов в машинном выводе.
const (
	codeUnknownCommand = "cli.unknown_command"
	codeBadArguments   = "cli.bad_arguments"
)

// Run выполняет команду из args (без имени программы) и возвращает код выхода.
func Run(args []string, e Env) int {
	if len(args) == 0 {
		writeUsage(e.Stderr)
		return exitUsage
	}
	// С --json ошибка аргументов тоже уходит документом: потребитель всегда получает конверт.
	asJSON := slices.Contains(args, "--json") || slices.Contains(args, "-json")
	for _, c := range commands() {
		if c.name != args[0] {
			continue
		}
		// Сообщения flag содержат ввод без экранирования, поэтому flag молчит, а ошибку печатает
		// usageError.
		fs := flag.NewFlagSet("xm "+c.name, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		if c.flags != nil {
			c.flags(fs)
		}
		if c.json {
			// Признак JSON уже известен из просмотра аргументов; флаг лишь объявлен, чтобы
			// Parse его принял.
			fs.Bool("json", false, "машинный вывод")
		}
		// Флаги и позиционные аргументы чередуются: flag останавливается на первом
		// позиционном, поэтому разбор повторяется по остатку.
		var pos []string
		rest := args[1:]
		for {
			if err := fs.Parse(rest); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					fmt.Fprintf(e.Stdout, "Использование: %s\n%s\n", c.usage, c.summary)
					return exitOK
				}
				return usageError(e, asJSON, codeBadArguments, flagMessage(err))
			}
			if fs.NArg() == 0 {
				break
			}
			pos = append(pos, fs.Arg(0))
			rest = fs.Args()[1:]
		}
		if len(pos) > c.maxArgs {
			return usageError(e, asJSON, codeBadArguments, "лишний аргумент «"+quote(pos[c.maxArgs])+"»")
		}
		if len(pos) < c.minArgs {
			return usageError(e, asJSON, codeBadArguments, "не хватает аргумента: "+c.usage)
		}
		return c.run(e, fs, pos, asJSON)
	}
	return usageError(e, asJSON, codeUnknownCommand, "неизвестная команда «"+quote(args[0])+"»")
}

func runVersion(e Env, _ *flag.FlagSet, _ []string, asJSON bool) int {
	if asJSON {
		return writeJSON(e, contract.New(e.Version, e.Clock.Now(), contract.Version{XM: e.Version}))
	}
	fmt.Fprintf(e.Stdout, "xm %s\n", e.Version)
	return exitOK
}

func runHelp(e Env, _ *flag.FlagSet, _ []string, _ bool) int {
	writeUsage(e.Stdout)
	return exitOK
}

func writeUsage(w io.Writer) {
	var b strings.Builder
	b.WriteString("Использование: xm <команда> [флаги]\n\nКоманды:\n")
	for _, c := range commands() {
		fmt.Fprintf(&b, "  %-8s %s\n", c.name, c.summary)
	}
	b.WriteString("\nСправка по команде: xm <команда> -h\n")
	io.WriteString(w, b.String())
}

// flagMessage — сообщение об ошибке разбора флагов по-русски; вводимое имя экранировано.
func flagMessage(err error) string {
	msg := err.Error()
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: "); ok {
		return "неизвестный флаг «" + quote(name) + "»"
	}
	return "неверный флаг: " + quote(msg)
}

// usageError сообщает об ошибке аргументов: человеку — в stderr, с --json — ещё и документом
// error в stdout. msg уже экранирован quote.
func usageError(e Env, asJSON bool, code, msg string) int {
	fmt.Fprintf(e.Stderr, "xm: %s\nСписок команд: xm help\n", msg)
	if asJSON {
		writeJSON(e, contract.NewError(e.Version, e.Clock.Now(), contract.Error{
			Code: code, Message: msg, Hint: "список команд: xm help",
		}))
	}
	return exitUsage
}

// writeJSON печатает документ в stdout. Ошибка записи в stdout — провал команды (код 1).
func writeJSON(e Env, env contract.Envelope) int {
	if err := contract.Encode(e.Stdout, env); err != nil {
		fmt.Fprintf(e.Stderr, "xm: не удалось вывести результат: %v\n", err)
		return exitFail
	}
	return exitOK
}

// quote экранирует управляющие символы ввода, чтобы он не управлял терминалом при выводе.
func quote(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
