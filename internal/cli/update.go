package cli

import (
	"flag"
	"fmt"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/contract"
)

func updateFlags(fs *flag.FlagSet) {
	fs.Bool("check", false, "только проверить, есть ли новая версия")
	fs.String("to", "", "поставить версию N.N.N, в том числе вне проверенного диапазона")
	fs.Bool("rollback", false, "вернуть предыдущую версию Xray")
}

func runUpdate(e Env, fs *flag.FlagSet, _ []string, asJSON bool) int {
	check, _ := fs.Lookup("check").Value.(flag.Getter).Get().(bool)
	rollback, _ := fs.Lookup("rollback").Value.(flag.Getter).Get().(bool)
	res, err := e.App.Update(e.Ctx, app.UpdateOptions{Check: check, To: fs.Lookup("to").Value.String(), Rollback: rollback})
	if err != nil {
		return fail(e, asJSON, err)
	}
	if asJSON {
		return writeJSON(e, contract.New(e.Version, e.Clock.Now(), res))
	}
	printUpdate(e, res, check, rollback)
	return exitOK
}

func printUpdate(e Env, r contract.Update, check, rollback bool) {
	if r.Latest != "" && r.Latest != r.Target {
		fmt.Fprintf(e.Stdout, "Последний стабильный релиз Xray %s новее проверенного диапазона %s–%s.\n", quote(r.Latest), r.Range.Min, r.Range.Max)
	}
	if !r.InRange {
		fmt.Fprintf(e.Stdout, "Внимание: Xray %s вне проверенного диапазона %s–%s: работа пресета и совместимость клиентов на нём не проверены.\n",
			quote(r.Target), r.Range.Min, r.Range.Max)
	}
	switch {
	case rollback && r.Held:
		fmt.Fprintf(e.Stdout, "Откат на Xray %s удержан (core.hold): ничего не изменено.\n", quote(r.Target))
	case rollback && r.Updated:
		fmt.Fprintf(e.Stdout, "Xray возвращён на предыдущую версию: %s → %s, служба работает, контроль пройден.\nНе проверено: %s.\n", quote(r.Current), quote(r.Target), quote(r.Unchecked))
	case r.Target == r.Current:
		fmt.Fprintf(e.Stdout, "Xray %s — уже эта версия, ничего не изменено.\n", quote(r.Current))
	case r.Held:
		fmt.Fprintf(e.Stdout, "Доступен Xray %s (сейчас %s), но обновление удержано (core.hold): ничего не изменено.\n", quote(r.Target), quote(r.Current))
	case check:
		fmt.Fprintf(e.Stdout, "Доступен Xray %s (сейчас %s): xm update\n", quote(r.Target), quote(r.Current))
	case r.Updated:
		fmt.Fprintf(e.Stdout, "Xray обновлён: %s → %s, служба работает, контроль пройден.\nНе проверено: %s.\n", quote(r.Current), quote(r.Target), quote(r.Unchecked))
	}
}
