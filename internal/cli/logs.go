package cli

import (
	"flag"

	"github.com/grokki91/xray_core/internal/app"
)

func logsFlags(fs *flag.FlagSet) {
	fs.Bool("f", false, "следить за новыми записями до Ctrl-C")
	fs.String("since", "", "с какого времени: N m|h|d назад (1–9999) или дата ГГГГ-ММ-ДД, UTC")
}

// runLogs печатает строки, уже очищенные и отредактированные в logging.
func runLogs(e Env, fs *flag.FlagSet, _ []string, _ bool) int {
	follow, _ := fs.Lookup("f").Value.(flag.Getter).Get().(bool)
	if err := e.App.Logs(e.Ctx, app.LogsOptions{Since: fs.Lookup("since").Value.String(), Follow: follow}, e.Stdout); err != nil {
		return fail(e, false, err)
	}
	return exitOK
}
