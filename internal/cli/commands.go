package cli

import (
	"errors"
	"flag"
	"fmt"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/contract"
)

func installFlags(fs *flag.FlagSet) {
	fs.String("sni", "", "домен цели REALITY, например example.com")
	fs.String("address", "", "адрес сервера для клиентов: IPv4, IPv6 или домен")
	fs.Int("port", app.DefaultPort, "порт сервера")
}

func runInstall(e Env, fs *flag.FlagSet, _ bool) int {
	port, _ := fs.Lookup("port").Value.(flag.Getter).Get().(int)
	res, err := e.App.Install(e.Ctx, app.InstallOptions{
		SNI: fs.Lookup("sni").Value.String(), Address: fs.Lookup("address").Value.String(), Port: port,
	})
	if err != nil {
		return fail(e, false, err)
	}
	fmt.Fprintf(e.Stdout, "Xray %s установлен, служба запущена.\nАдрес %s, порт %d.\n", res.Xray, quote(res.Address), res.Port)
	fmt.Fprintln(e.Stdout, "Клиентских профилей пока нет: подключиться нельзя, пока не появится команда xm add.")
	return exitOK
}

// service строит команду start, stop или restart.
func service(a app.Action) func(Env, *flag.FlagSet, bool) int {
	done := map[app.Action]string{app.Start: "запущена", app.Stop: "остановлена", app.Restart: "перезапущена"}
	return func(e Env, _ *flag.FlagSet, _ bool) int {
		if err := e.App.Service(e.Ctx, a); err != nil {
			return fail(e, false, err)
		}
		fmt.Fprintf(e.Stdout, "Служба Xray %s.\n", done[a])
		return exitOK
	}
}

func runStatus(e Env, _ *flag.FlagSet, asJSON bool) int {
	st, err := e.App.Status(e.Ctx)
	if err != nil {
		return fail(e, asJSON, err)
	}
	if asJSON {
		return writeJSON(e, contract.New(e.Version, e.Clock.Now(), st))
	}
	if !st.Installed {
		fmt.Fprintf(e.Stdout, "xm %s. Xray не установлен: xm install --sni <домен> --address <адрес>\n", quote(st.Versions.XM))
		return exitOK
	}
	yes := map[bool]string{true: "да", false: "нет"}
	fmt.Fprintf(e.Stdout, "Служба: %s (%s), автозапуск: %s, перезапусков: %d\n",
		quote(st.Service.Active), quote(st.Service.Sub), yes[st.Service.Enabled], st.Service.Restarts)
	fmt.Fprintf(e.Stdout, "Версии: xm %s, Xray %s\n", quote(st.Versions.XM), quote(st.Versions.Xray))
	for _, a := range []struct{ name, v string }{{"IPv4", st.Addresses.IPv4}, {"IPv6", st.Addresses.IPv6}, {"Домен", st.Addresses.Domain}} {
		if a.v != "" {
			fmt.Fprintf(e.Stdout, "%s: %s\n", a.name, quote(a.v))
		}
	}
	fmt.Fprintf(e.Stdout, "Порт: %d\n", st.Port)
	if st.Drift {
		fmt.Fprintln(e.Stdout, "Конфигурация Xray расходится с состоянием: её правили вручную или она повреждена.")
	} else {
		fmt.Fprintln(e.Stdout, "Конфигурация Xray совпадает с состоянием.")
	}
	return exitOK
}

// fail сообщает об ошибке сценария: что случилось, что сделала система, что делать владельцу;
// код выхода — по interfaces.md §1. С --json в stdout уходит ещё и документ error.
func fail(e Env, asJSON bool, err error) int {
	var (
		exit       = exitFail
		code, hint string
		pe         *app.PreflightError
	)
	switch {
	case errors.Is(err, app.ErrInput):
		exit, code, hint = exitUsage, "cli.bad_arguments", "справка по команде: xm <команда> -h"
	case errors.As(err, &pe):
		exit, code, hint = exitPreflight, pe.Issues[0].Code, "исправьте названное и повторите команду"
	case errors.Is(err, app.ErrInstalled):
		exit, code, hint = exitPreflight, "app.already_installed", "состояние установки: xm status"
	case errors.Is(err, app.ErrNotInstalled):
		exit, code, hint = exitPreflight, "app.not_installed", "установка: xm install --sni <домен> --address <адрес>"
	case errors.Is(err, app.ErrRollbackFailed):
		exit, code = exitRollback, "app.rollback_failed"
		hint = "xm больше ничего не меняет, пока откат не выполнен: повторите любую команду службы, откат повторится при запуске; " +
			"не помогло — снимок для ручного возврата лежит в /var/lib/xm/backups"
	case errors.Is(err, app.ErrRolledBack):
		code, hint = "app.rolled_back", "изменение не применено, прежнее состояние возвращено; причина указана выше"
	default:
		code, hint = "app.failed", "причина указана выше"
	}
	msg := quote(err.Error())
	fmt.Fprintf(e.Stderr, "xm: %s\n%s\n", msg, hint)
	if asJSON {
		writeJSON(e, contract.NewError(e.Version, e.Clock.Now(), contract.Error{Code: code, Message: msg, Hint: hint}))
	}
	return exit
}
