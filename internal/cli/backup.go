package cli

import (
	"flag"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/contract"
)

// restoreWord — слово подтверждения `xm restore` (interfaces.md §1).
const restoreWord = "restore"

func backupFlags(fs *flag.FlagSet) {
	fs.Bool("list", false, "показать снимки, ничего не создавая")
}

func restoreFlags(fs *flag.FlagSet) {
	fs.Bool("yes", false, "не спрашивать слово подтверждения")
}

func runBackup(e Env, fs *flag.FlagSet, _ []string, asJSON bool) int {
	if fs.Lookup("list").Value.String() == "true" {
		list, err := e.App.BackupList(e.Ctx)
		if err != nil {
			return fail(e, asJSON, err)
		}
		if asJSON {
			return writeJSON(e, contract.New(e.Version, e.Clock.Now(), list))
		}
		printBackups(e, list)
		return exitOK
	}
	b, err := e.App.Backup(e.Ctx)
	if err != nil {
		return fail(e, asJSON, err)
	}
	if asJSON {
		return writeJSON(e, contract.New(e.Version, e.Clock.Now(), contract.Backups{Backups: []contract.BackupItem{b}}))
	}
	fmt.Fprintf(e.Stdout, "Снимок создан: %s\nВосстановить: xm restore %s\n", b.ID, b.ID)
	return exitOK
}

func printBackups(e Env, list contract.Backups) {
	if len(list.Backups) == 0 {
		fmt.Fprintln(e.Stdout, "Снимков нет: xm backup")
		return
	}
	kinds := map[string]string{"auto": "авто", "manual": "ручной"}
	for _, b := range list.Backups {
		xray := quote(b.Xray)
		if xray == "" {
			xray = "не установлен" // снимок снят до установки ядра
		}
		note := "xm " + quote(b.XM) + ", Xray " + xray
		if !b.Valid {
			note = "повреждён — восстановить нельзя"
		}
		fmt.Fprintf(e.Stdout, "%-40s %s  %-6s  %s\n", quote(b.ID), time.Unix(b.Created, 0).UTC().Format("2006-01-02 15:04"), kinds[b.Kind], note)
	}
}

func runRestore(e Env, fs *flag.FlagSet, args []string, _ bool) int {
	if fs.Lookup("yes").Value.String() != "true" {
		fmt.Fprintf(e.Stderr, "Состояние и профили будут заменены снимком %s; текущее сохранится автоснимком.\nДля подтверждения введите %s: ", quote(args[0]), restoreWord)
		if !confirmed(e.Stdin, restoreWord) {
			fmt.Fprintln(e.Stderr, "\nxm: подтверждение не получено, ничего не изменено")
			return exitUsage
		}
	}
	if err := e.App.Restore(e.Ctx, args[0]); err != nil {
		return fail(e, false, err)
	}
	fmt.Fprintf(e.Stdout, "Состояние восстановлено из снимка %s, служба проверена. Прежнее — в автоснимке: xm backup --list\n", quote(args[0]))
	return exitOK
}
