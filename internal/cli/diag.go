package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/contract"
)

// exitProblems — `xm diag`: вердикт прогона не ok (interfaces.md §1).
const exitProblems = 4

func diagFlags(fs *flag.FlagSet) {
	fs.String("only", "", "одна категория каталога: xray, reach, ipv4, ipv6")
	fs.String("export", "", "новый файл в /root, /home или /tmp для отредактированного отчёта")
}

// runDiag показывает отчёт, уже прошедший редактор в app: сначала факты, затем вероятные
// причины, затем гипотезы (diagnostics.md §1, правило 5). Вердикт не ok — код 4.
func runDiag(e Env, fs *flag.FlagSet, _ []string, asJSON bool) int {
	env, err := e.App.Diagnose(e.Ctx, app.DiagOptions{Only: fs.Lookup("only").Value.String(), Export: fs.Lookup("export").Value.String()})
	if err != nil {
		return fail(e, asJSON, err)
	}
	r, _ := env.Data.(contract.DiagReport)
	if asJSON {
		if code := writeJSON(e, env); code != exitOK {
			return code
		}
	} else {
		printDiag(e, r)
	}
	if r.Health != "ok" {
		return exitProblems
	}
	return exitOK
}

func printDiag(e Env, r contract.DiagReport) {
	marks := map[string]string{"ok": "ok  ", "fail": "FAIL", "skip": "skip", "error": "ERR "}
	for _, o := range r.Observations {
		line := fmt.Sprintf("  %s %s", marks[o.Status], quote(o.Check))
		if o.Target != "" {
			line += " (" + quote(o.Target) + ")"
		}
		if o.Reason != "" {
			line += ": " + quote(o.Reason)
		}
		fmt.Fprintln(e.Stdout, line)
	}
	for _, sec := range []struct{ class, title string }{{"fact", "Факты"}, {"probable", "Вероятные причины"}, {"hypothesis", "Гипотезы"}} {
		first := true
		for _, f := range r.Findings {
			if f.Class != sec.class {
				continue
			}
			if first {
				fmt.Fprintf(e.Stdout, "%s:\n", sec.title)
				first = false
			}
			fmt.Fprintf(e.Stdout, "  %s", quote(f.Title))
			if len(f.Actions) > 0 {
				fmt.Fprintf(e.Stdout, ". Что делать: %s", quote(strings.Join(f.Actions, "; ")))
			}
			fmt.Fprintln(e.Stdout)
		}
	}
	names := map[string]string{"ok": "проблем не найдено", "down": "не работает", "degraded": "работает не полностью", "unknown": "не определено"}
	s := r.Summary
	fmt.Fprintf(e.Stdout, "Итог: %s (ok %d, fail %d, skip %d, error %d). Отчёт %s сохранён.\n", names[r.Health], s.OK, s.Fail, s.Skip, s.Error, quote(r.ID))
	if r.Health == "ok" {
		fmt.Fprintln(e.Stdout, "Проверено только с самого сервера: доступность порта снаружи и из сети клиента не измерена.")
	}
}
