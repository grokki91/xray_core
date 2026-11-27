package cli

import (
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/contract"
)

// Вердикт не ok — код 4 и в тексте, и с --json; факты раньше гипотез; флаги доходят до app.
func TestDiagExitAndOrder(t *testing.T) {
	f := &fakeApp{diag: contract.DiagReport{ID: "20260101T000000Z", Health: "down",
		Observations: []contract.DiagObservation{{Check: "xray.service.active", Status: "fail"}},
		Findings: []contract.DiagFinding{
			{Class: "hypothesis", Title: "гипотеза"},
			{Class: "fact", Title: "служба не активна", Actions: []string{"xm start"}},
		}, Summary: contract.DiagSummary{Fail: 1}}}
	code, out, _ := runWith(f, "diag", "--only", "xray", "--export", "/root/d.json")
	if code != exitProblems || f.diagOpts != (app.DiagOptions{Only: "xray", Export: "/root/d.json"}) {
		t.Fatalf("код %d, параметры %+v", code, f.diagOpts)
	}
	if i, j := strings.Index(out, "служба не активна"), strings.Index(out, "гипотеза"); i < 0 || j < i {
		t.Fatalf("порядок выводов:\n%s", out)
	}
	if code, out, _ := runWith(f, "diag", "--json"); code != exitProblems || !strings.Contains(out, `"name": "diag-report"`) {
		t.Fatalf("--json: код %d\n%s", code, out)
	}
	f.diag.Health = "ok"
	if code, _, _ := runWith(f, "diag"); code != exitOK {
		t.Fatalf("ok: код %d", code)
	}
	f.err = app.ErrInput
	if code, _, _ := runWith(f, "diag", "--only", "dns"); code != exitUsage {
		t.Fatalf("ошибка ввода: код %d", code)
	}
}
