package cli

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/contract"
)

func installFlags(fs *flag.FlagSet) {
	fs.String("sni", "", "домен цели REALITY, например example.com (по умолчанию — выбор из закрытого списка)")
	fs.String("address", "", "внешний адрес сервера: IPv4, IPv6 или домен (по умолчанию — определяется)")
	fs.Int("port", 0, "порт сервера (по умолчанию 443)")
}

func runInstall(e Env, fs *flag.FlagSet, _ []string, _ bool) int {
	port, _ := fs.Lookup("port").Value.(flag.Getter).Get().(int)
	res, err := e.App.Install(e.Ctx, app.InstallOptions{
		SNI: fs.Lookup("sni").Value.String(), Address: fs.Lookup("address").Value.String(), Port: port,
	})
	if err != nil {
		return fail(e, false, err)
	}
	if res.Existing {
		fmt.Fprintf(e.Stdout, "Xray %s уже установлен, ничего не изменено.\nАдрес %s, порт %d.\n", res.Xray, quote(res.Address), res.Port)
	} else {
		fmt.Fprintf(e.Stdout, "Xray %s установлен, служба запущена.\nАдрес %s, порт %d.\n", res.Xray, quote(res.Address), res.Port)
	}
	// Установка завершается ссылкой и QR первого профиля: подключиться можно сразу.
	if res.Profile == "" {
		fmt.Fprintln(e.Stdout, "Профилей нет: xm add")
	} else {
		v, err := e.App.ProfileShow(e.Ctx, res.Profile, app.ShareOptions{})
		if err != nil {
			return fail(e, false, err)
		}
		printProfile(e, "Первый профиль", v)
	}
	printFirewall(e, res)
	printHealth(e, res.Health)
	return exitOK
}

func shareFlags(fs *flag.FlagSet) {
	fs.String("client", "", "клиент из таблицы совместимости (v2rayn, v2rayng, hiddify-5…): проверить, подойдёт ли он")
	fs.String("address", "", "адрес сервера, для которого построить QR (по умолчанию первый: домен, IPv4, IPv6)")
}

func shareOptions(fs *flag.FlagSet) app.ShareOptions {
	return app.ShareOptions{Client: fs.Lookup("client").Value.String(), Address: fs.Lookup("address").Value.String()}
}

func runAdd(e Env, fs *flag.FlagSet, args []string, asJSON bool) int {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}
	v, err := e.App.ProfileAdd(e.Ctx, name, shareOptions(fs))
	if err != nil {
		return fail(e, asJSON, err)
	}
	return showProfile(e, "Профиль создан", v, asJSON)
}

func runShow(e Env, fs *flag.FlagSet, args []string, asJSON bool) int {
	v, err := e.App.ProfileShow(e.Ctx, args[0], shareOptions(fs))
	if err != nil {
		return fail(e, asJSON, err)
	}
	return showProfile(e, "Профиль", v, asJSON)
}

func runList(e Env, _ *flag.FlagSet, _ []string, asJSON bool) int {
	ps, err := e.App.ProfileList(e.Ctx)
	if err != nil {
		return fail(e, asJSON, err)
	}
	if asJSON {
		return writeJSON(e, contract.New(e.Version, e.Clock.Now(), ps))
	}
	if len(ps.Profiles) == 0 {
		fmt.Fprintln(e.Stdout, "Профилей нет: xm add")
		return exitOK
	}
	state := map[bool]string{true: "включён", false: "выключен"}
	for _, p := range ps.Profiles {
		fmt.Fprintf(e.Stdout, "%-32s %s  %s\n", quote(p.Name), time.Unix(p.Created, 0).UTC().Format("2006-01-02"), state[p.Enabled])
	}
	return exitOK
}

func runRemove(e Env, _ *flag.FlagSet, args []string, _ bool) int {
	if err := e.App.ProfileRemove(e.Ctx, args[0]); err != nil {
		return fail(e, false, err)
	}
	fmt.Fprintf(e.Stdout, "Профиль «%s» удалён: его ссылка больше не подключается.\n", quote(args[0]))
	return exitOK
}

func showProfile(e Env, title string, v app.ProfileView, asJSON bool) int {
	if asJSON {
		return writeJSON(e, contract.New(e.Version, e.Clock.Now(), v.Profile))
	}
	printProfile(e, title, v)
	return exitOK
}

// printProfile печатает ссылки и QR профиля. Это секреты: команды, которые сюда попадают,
// существуют ради их показа (interfaces.md §1). QR несёт ANSI-цвета и предназначен терминалу.
// Клиенты, которым ссылка не подойдёт, — предупреждение в stderr.
func printProfile(e Env, title string, v app.ProfileView) {
	fmt.Fprintf(e.Stdout, "%s «%s».\nСсылки:\n", title, quote(v.Name))
	for _, l := range v.Links {
		fmt.Fprintf(e.Stdout, "  %s\n    %s\n", quote(l.Address), quote(l.URI))
	}
	fmt.Fprintf(e.Stdout, "QR для %s:\n%s", quote(v.QRAddress), v.QR)
	for _, u := range v.Unfit {
		fmt.Fprintf(e.Stderr, "Предупреждение: %s не подключится: %s\n", quote(u.Client), quote(u.Reason))
	}
}

// service строит команду start, stop или restart.
func service(a app.Action) func(Env, *flag.FlagSet, []string, bool) int {
	done := map[app.Action]string{app.Start: "запущена", app.Stop: "остановлена", app.Restart: "перезапущена"}
	return func(e Env, _ *flag.FlagSet, _ []string, _ bool) int {
		if err := e.App.Service(e.Ctx, a); err != nil {
			return fail(e, false, err)
		}
		fmt.Fprintf(e.Stdout, "Служба Xray %s.\n", done[a])
		return exitOK
	}
}

func runStatus(e Env, _ *flag.FlagSet, _ []string, asJSON bool) int {
	st, err := e.App.Status(e.Ctx)
	if err != nil {
		return fail(e, asJSON, err)
	}
	if asJSON {
		return writeJSON(e, contract.New(e.Version, e.Clock.Now(), st))
	}
	if !st.Installed {
		fmt.Fprintf(e.Stdout, "xm %s. Xray не установлен: xm install\n", quote(st.Versions.XM))
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
	fmt.Fprintf(e.Stdout, "Профилей: %d\n", st.Profiles)
	for _, c := range st.Clients {
		switch {
		case !c.Works:
			fmt.Fprintf(e.Stdout, "Клиент %s: не подключится (%s)\n", quote(c.Name), quote(c.Reason))
		case c.Condition != "":
			fmt.Fprintf(e.Stdout, "Клиент %s: подключится, если %s\n", quote(c.Name), quote(c.Condition))
		default:
			fmt.Fprintf(e.Stdout, "Клиент %s: подключится\n", quote(c.Name))
		}
	}
	if st.Drift {
		fmt.Fprintln(e.Stdout, "Конфигурация Xray расходится с состоянием: её правили вручную или она повреждена.")
	} else {
		fmt.Fprintln(e.Stdout, "Конфигурация Xray совпадает с состоянием.")
	}
	printHealth(e, st.Health)
	return exitOK
}

// printFirewall — что установка сделала с фаерволом; при повторном запуске ничего не сделано и
// не читалось — строки нет. Состояние — локальный факт: фаервол хостера с сервера не виден.
func printFirewall(e Env, res app.InstallResult) {
	if res.Existing {
		return
	}
	f := res.Firewall
	switch {
	case f.Added:
		fmt.Fprintf(e.Stdout, "Фаервол: в UFW добавлено правило для порта %d/tcp; его снимет xm uninstall.\n", res.Port)
	case f.State == "allowed":
		fmt.Fprintf(e.Stdout, "Фаервол: порт %d/tcp локально не закрыт; фаервол хостера с сервера не виден.\n", res.Port)
	default:
		fmt.Fprintf(e.Stdout, "Фаервол: порт %d/tcp не определён как открытый (%s). Если подключение не проходит, откройте порт сами: %s\n",
			res.Port, quote(f.Note), quote(f.Open))
	}
}

// printHealth — последняя строка install и status: вердикт, первопричина, действие; при ok —
// что не проверено (ADR-0024).
func printHealth(e Env, h contract.Health) {
	switch h.Verdict {
	case "ok":
		fmt.Fprintf(e.Stdout, "Состояние: работает. Не проверено: %s.\n", quote(h.Unchecked))
	case "":
		return
	default:
		names := map[string]string{"down": "не работает", "degraded": "работает не полностью", "unknown": "не определено"}
		fmt.Fprintf(e.Stdout, "Состояние: %s. Причина: %s. Что делать: %s.\n", names[h.Verdict], quote(h.Cause), quote(h.Action))
	}
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
		exit, code, hint = exitPreflight, "app.not_installed", "установка: xm install"
	case errors.Is(err, app.ErrIncompatible):
		code, hint = "profile.incompatible", "клиенты и причины — xm status; ссылка без проверки клиента — та же команда без --client"
	case errors.Is(err, app.ErrRollbackFailed):
		exit, code = exitRollback, "app.rollback_failed"
		hint = "xm больше ничего не меняет, пока откат не выполнен: повторите любую команду службы, откат повторится при запуске; " +
			"не помогло — снимок для ручного возврата лежит в /var/lib/xm/backups"
	case errors.Is(err, app.ErrRolledBack):
		code, hint = "app.rolled_back", "изменение не применено, прежнее состояние возвращено; причина указана выше"
	default:
		code, hint = "app.failed", "причина указана выше"
	}
	msg := e.Redact(quote(err.Error()))
	fmt.Fprintf(e.Stderr, "xm: %s\n%s\n", msg, hint)
	if asJSON {
		writeJSON(e, contract.NewError(e.Version, e.Clock.Now(), contract.Error{Code: code, Message: msg, Hint: hint}))
	}
	return exit
}
