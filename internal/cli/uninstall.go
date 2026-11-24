package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"
)

// purgeWord — слово подтверждения `uninstall --purge` (interfaces.md §1, ADR-0042).
const purgeWord = "purge"

func uninstallFlags(fs *flag.FlagSet) {
	fs.Bool("purge", false, "удалить ещё состояние, профили, ключи и снимки — без возврата")
	fs.Bool("yes", false, "не спрашивать слово подтверждения (только вместе с --purge)")
}

func runUninstall(e Env, fs *flag.FlagSet, _ []string, _ bool) int {
	purge := fs.Lookup("purge").Value.String() == "true"
	yes := fs.Lookup("yes").Value.String() == "true"
	if yes && !purge {
		return usageError(e, false, codeBadArguments, "--yes заменяет подтверждение только у --purge")
	}
	if purge && !yes {
		fmt.Fprintf(e.Stderr, "Будут удалены состояние, профили, ключи и снимки — без возврата.\nДля подтверждения введите %s: ", purgeWord)
		if !confirmed(e.Stdin) {
			fmt.Fprintln(e.Stderr, "\nxm: подтверждение не получено, ничего не удалено")
			return exitUsage
		}
	}
	if err := e.App.Uninstall(e.Ctx, purge); err != nil {
		return fail(e, false, err)
	}
	if purge {
		fmt.Fprintln(e.Stdout, "xm удалён полностью: служба, бинарники, состояние, профили и снимки.")
	} else {
		fmt.Fprintln(e.Stdout, "Служба, юнит и бинарники Xray и xm удалены. Состояние и снимки сохранены в /etc/xm и /var/lib/xm/backups.")
	}
	return exitOK
}

// confirmed читает одну строку и сверяет её со словом подтверждения.
func confirmed(r io.Reader) bool {
	if r == nil {
		return false
	}
	line, err := bufio.NewReader(io.LimitReader(r, 64)).ReadString('\n')
	if err != nil && err != io.EOF {
		return false
	}
	return strings.TrimSpace(line) == purgeWord
}
