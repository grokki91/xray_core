// Пакет cli — адаптер командной строки: разбирает аргументы, вызывает прикладной слой и
// показывает результат. Таблица команд и коды выхода — docs/architecture/interfaces.md §1.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Коды выхода — docs/architecture/interfaces.md §1.
const (
	exitOK    = 0
	exitUsage = 2
)

// env — то, что получает команда: потоки вывода и версия сборки.
type env struct {
	stdout, stderr io.Writer
	version        string
}

type command struct {
	name    string
	summary string
	run     func(e env) int
}

// commands — закрытый список команд в порядке справки.
func commands() []command {
	return []command{
		{name: "version", summary: "версия xm", run: runVersion},
		{name: "help", summary: "эта справка", run: runHelp},
	}
}

// Run выполняет команду из args (без имени программы) и возвращает код выхода.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	e := env{stdout: stdout, stderr: stderr, version: version}
	if len(args) == 0 {
		writeUsage(stderr)
		return exitUsage
	}
	for _, c := range commands() {
		if c.name != args[0] {
			continue
		}
		// Сообщения flag содержат ввод без экранирования, поэтому flag молчит, а ошибку печатает
		// usageError.
		fs := flag.NewFlagSet("xm "+c.name, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprintf(stdout, "Использование: xm %s\n%s\n", c.name, c.summary)
				return exitOK
			}
			return usageError(stderr, "%s", quote(err.Error()))
		}
		if fs.NArg() > 0 {
			return usageError(stderr, "лишний аргумент «%s»", quote(fs.Arg(0)))
		}
		return c.run(e)
	}
	return usageError(stderr, "неизвестная команда «%s»", quote(args[0]))
}

func runVersion(e env) int {
	fmt.Fprintf(e.stdout, "xm %s\n", e.version)
	return exitOK
}

func runHelp(e env) int {
	writeUsage(e.stdout)
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

func usageError(stderr io.Writer, format string, a ...any) int {
	fmt.Fprintf(stderr, "xm: "+format+"\nСписок команд: xm help\n", a...)
	return exitUsage
}

// quote экранирует управляющие символы ввода, чтобы он не управлял терминалом при выводе.
func quote(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
