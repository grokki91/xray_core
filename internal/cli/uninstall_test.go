package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/app"
)

// uninstallApp записывает вызов Uninstall.
type uninstallApp struct {
	fakeApp
	called, purge bool
}

func (u *uninstallApp) Uninstall(_ context.Context, purge bool) error {
	u.called, u.purge = true, purge
	return u.err
}

func runInput(a App, stdin string, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(args, Env{Ctx: context.Background(), Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
		Version: "0.1.0", Clock: fixedClock{}, App: a, Redact: func(s string) string { return s }})
	return code, out.String(), errOut.String()
}

func TestUninstallPurgeNeedsWord(t *testing.T) {
	for _, in := range []string{"", "yes\n", "purge now\n", "PURGE\n"} {
		u := &uninstallApp{}
		if code, _, _ := runInput(u, in, "uninstall", "--purge"); code != exitUsage || u.called {
			t.Errorf("ввод %q: код %d, вызван %v", in, code, u.called)
		}
	}
	u := &uninstallApp{}
	if code, out, _ := runInput(u, "purge\n", "uninstall", "--purge"); code != exitOK || !u.called || !u.purge || !strings.Contains(out, "полностью") {
		t.Fatalf("слово введено: код %d, %+v, %q", code, u, out)
	}
	u = &uninstallApp{}
	if code, _, _ := runInput(u, "", "uninstall", "--purge", "--yes"); code != exitOK || !u.purge {
		t.Fatalf("--yes: код %d, %+v", code, u)
	}
}

func TestUninstallWithoutPurgeAsksNothing(t *testing.T) {
	u := &uninstallApp{}
	if code, out, _ := runInput(u, "", "uninstall"); code != exitOK || !u.called || u.purge || !strings.Contains(out, "сохранены") {
		t.Fatalf("код %d, %+v, %q", code, u, out)
	}
	// --yes без --purge — ошибка аргументов: флаг разрушительного действия обязателен.
	u = &uninstallApp{}
	if code, _, _ := runInput(u, "", "uninstall", "--yes"); code != exitUsage || u.called {
		t.Fatalf("--yes без --purge: код %d", code)
	}
	u = &uninstallApp{fakeApp: fakeApp{err: app.ErrNotInstalled}}
	if code, _, _ := runInput(u, "", "uninstall"); code != exitPreflight {
		t.Fatalf("не установлен: код %d", code)
	}
}
