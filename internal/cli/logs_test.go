package cli

import (
	"testing"

	"github.com/grokki91/xray_core/internal/app"
)

// Флаги доходят до app как есть; вывод app идёт в stdout; ошибка ввода — код 2.
func TestLogsFlags(t *testing.T) {
	f := &fakeApp{}
	code, out, _ := runWith(f, "logs", "-f", "--since", "2h")
	if code != exitOK || out != "line\n" || f.logs != (app.LogsOptions{Since: "2h", Follow: true}) {
		t.Fatalf("код %d, вывод %q, параметры %+v", code, out, f.logs)
	}
	f = &fakeApp{err: app.ErrInput}
	if code, _, _ := runWith(f, "logs", "--since", "x"); code != exitUsage {
		t.Fatalf("код %d, нужно %d", code, exitUsage)
	}
	if code, _, _ := runWith(&fakeApp{}, "logs", "extra"); code != exitUsage {
		t.Fatalf("лишний аргумент: код %d", code)
	}
}
