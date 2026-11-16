package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/server"
)

// fakeApp запоминает, что у него просили, и отвечает заданным.
type fakeApp struct {
	opts   app.InstallOptions
	action app.Action
	status contract.Status
	err    error
}

func (f *fakeApp) Install(_ context.Context, o app.InstallOptions) (app.InstallResult, error) {
	f.opts = o
	return app.InstallResult{Xray: "26.11.9", Address: o.Address, Port: o.Port}, f.err
}

func (f *fakeApp) Service(_ context.Context, a app.Action) error { f.action = a; return f.err }

func (f *fakeApp) Status(context.Context) (contract.Status, error) { return f.status, f.err }

func runWith(a App, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, Env{Ctx: context.Background(), Stdout: &out, Stderr: &errOut, Version: "0.1.0", Clock: fixedClock{}, App: a,
		Redact: func(s string) string { return strings.ReplaceAll(s, "CANARY", "[секрет]") }})
	return code, out.String(), errOut.String()
}

func TestInstallPassesFlagsAndDefaultPort(t *testing.T) {
	f := &fakeApp{}
	code, stdout, stderr := runWith(f, "install", "--sni", "example.com", "--address", "203.0.113.10")
	if code != exitOK || stderr != "" || !strings.Contains(stdout, "Xray 26.11.9 установлен") {
		t.Fatalf("код %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := (app.InstallOptions{SNI: "example.com", Address: "203.0.113.10", Port: 443}); f.opts != want {
		t.Fatalf("app получил %+v", f.opts)
	}
	runWith(f, "install", "--sni", "example.com", "--address", "vpn.example.org", "--port", "8443")
	if f.opts.Port != 8443 {
		t.Fatalf("порт %d", f.opts.Port)
	}
	if code, _, _ := runWith(f, "install", "--port", "много"); code != exitUsage {
		t.Fatalf("нечисловой порт: код %d", code)
	}
}

func TestServiceCommandsCallAction(t *testing.T) {
	for _, a := range []app.Action{app.Start, app.Stop, app.Restart} {
		f := &fakeApp{}
		if code, stdout, _ := runWith(f, string(a)); code != exitOK || f.action != a || !strings.HasPrefix(stdout, "Служба Xray ") {
			t.Fatalf("%s: код %d, действие %q, stdout %q", a, code, f.action, stdout)
		}
	}
}

// Коды выхода — docs/architecture/interfaces.md §1.
func TestFailureExitCodes(t *testing.T) {
	cases := []struct {
		err  error
		exit int
		code string
	}{
		{fmt.Errorf("%w: нужен --sni", app.ErrInput), 2, "cli.bad_arguments"},
		{&app.PreflightError{Issues: []server.Issue{{Code: server.CodeNotRoot, Message: "нужен root"}}}, 3, "preflight.not_root"},
		{app.ErrInstalled, 3, "app.already_installed"},
		{app.ErrNotInstalled, 3, "app.not_installed"},
		{fmt.Errorf("%w: %w", app.ErrRolledBack, errors.New("порт не слушается")), 1, "app.rolled_back"},
		{fmt.Errorf("%w: %w (причина: %w)", app.ErrRollbackFailed, errors.New("служба"), errors.New("контроль")), 5, "app.rollback_failed"},
		{errors.New("что-то иное"), 1, "app.failed"},
	}
	for _, tc := range cases {
		f := &fakeApp{err: tc.err}
		code, _, stderr := runWith(f, "start")
		if code != tc.exit || !strings.HasPrefix(stderr, "xm: ") || strings.Count(stderr, "\n") < 2 {
			t.Errorf("%v: код %d, stderr %q", tc.err, code, stderr)
		}
		code, stdout, _ := runWith(f, "status", "--json")
		if code != tc.exit || !strings.Contains(stdout, `"name": "error"`) || !strings.Contains(stdout, `"code": "`+tc.code+`"`) {
			t.Errorf("%v: status --json: код %d, stdout %q", tc.err, code, stdout)
		}
	}
}

// Текст ошибки приходит из системы: управляющие последовательности в терминал не попадают.
func TestFailureMessageIsEscaped(t *testing.T) {
	f := &fakeApp{err: errors.New("плохо\x1b[31m")}
	if _, _, stderr := runWith(f, "start"); strings.Contains(stderr, "\x1b") {
		t.Fatalf("в stderr управляющий символ: %q", stderr)
	}
}

var installed = contract.Status{
	Installed: true,
	Service:   contract.ServiceState{Loaded: true, Active: "active", Sub: "running", Enabled: true},
	Versions:  contract.Versions{XM: "0.1.0", Xray: "26.11.9"},
	Addresses: contract.ServerAddress{IPv4: "203.0.113.10"},
	Port:      443,
}

// Вывод xm status --json побайтно совпадает с эталоном схемы status.
func TestStatusJSONMatchesGolden(t *testing.T) {
	want, err := os.ReadFile("../contract/testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runWith(&fakeApp{status: installed}, "status", "--json")
	if code != exitOK || stderr != "" || stdout != string(want) {
		t.Fatalf("код %d, stderr %q, stdout:\n%s", code, stderr, stdout)
	}
}

func TestStatusHuman(t *testing.T) {
	code, stdout, _ := runWith(&fakeApp{status: installed}, "status")
	for _, want := range []string{"active (running)", "Xray 26.11.9", "IPv4: 203.0.113.10", "Порт: 443", "совпадает с состоянием"} {
		if code != exitOK || !strings.Contains(stdout, want) {
			t.Errorf("нет %q: код %d, stdout:\n%s", want, code, stdout)
		}
	}
	drift := installed
	drift.Drift = true
	if _, stdout, _ := runWith(&fakeApp{status: drift}, "status"); !strings.Contains(stdout, "расходится") {
		t.Fatalf("дрейф не показан:\n%s", stdout)
	}
	none := contract.Status{Versions: contract.Versions{XM: "0.1.0"}}
	if code, stdout, _ := runWith(&fakeApp{status: none}, "status"); code != exitOK || !strings.Contains(stdout, "не установлен") {
		t.Fatalf("не установлено: код %d, stdout %q", code, stdout)
	}
}

// Текст ошибки идёт через редактор и в stderr, и в документе error в stdout.
func TestFailureMessageGoesThroughRedactor(t *testing.T) {
	f := &fakeApp{err: errors.New("не прочитать CANARY")}
	_, _, stderr := runWith(f, "start")
	_, stdout, _ := runWith(f, "status", "--json")
	for name, out := range map[string]string{"stderr": stderr, "stdout": stdout} {
		if strings.Contains(out, "CANARY") || !strings.Contains(out, "[секрет]") {
			t.Errorf("%s: %q", name, out)
		}
	}
}
