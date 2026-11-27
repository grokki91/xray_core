package app

import (
	"errors"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/diag"
)

// Отчёт сохраняется в историю и экспортируется одним и тем же отредактированным документом.
func TestDiagnoseSavesAndExports(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.f.Path("/root"), 0o700); err != nil {
		t.Fatal(err)
	}
	env, err := s.app.Diagnose(ctx(t), DiagOptions{Export: "/root/diag.json"})
	if err != nil {
		t.Fatal(err)
	}
	r := env.Data.(contract.DiagReport)
	if r.ID == "" || r.Vantage.Kind != "local" || r.Env.XM != "0.1.0" || r.Env.Xray == "" || len(r.Observations) < 10 {
		t.Fatalf("отчёт: %+v", r)
	}
	saved, err := os.ReadFile(s.f.Path(path.Join(diag.HistoryDir, r.ID+".json")))
	if err != nil {
		t.Fatal(err)
	}
	exported, err := os.ReadFile(s.f.Path("/root/diag.json"))
	if err != nil || string(saved) != string(exported) || !strings.Contains(string(saved), `"diag-report"`) {
		t.Fatalf("экспорт расходится с историей: %v", err)
	}
	again, err := s.app.Diagnose(ctx(t), DiagOptions{Only: "xray"})
	if err != nil {
		t.Fatal(err)
	}
	r2 := again.Data.(contract.DiagReport)
	if r2.ID != r.ID+"-2" {
		t.Fatalf("повтор в ту же секунду: %q", r2.ID)
	}
	for _, o := range r2.Observations {
		if diag.Category(o.Check) != "xray" {
			t.Fatalf("--only xray запустил %s", o.Check)
		}
	}
}

// Редактор проходит весь отчёт: адрес сервера и ключ из наблюдения в документ не попадают.
func TestDiagnoseRedacts(t *testing.T) {
	s := installed(t)
	_, doc, err := s.app.redactReport(s.f.Clock().Now(), contract.DiagReport{Observations: []contract.DiagObservation{
		{Check: "reach.listen", Target: "203.0.113.10:443", Status: "ok", Value: map[string]string{"key": secretKey}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc), "203.0.113.10") || strings.Contains(string(doc), secretKey) {
		t.Fatalf("данные установки в отчёте:\n%s", doc)
	}
}

func TestDiagnoseInput(t *testing.T) {
	s := installed(t)
	if err := os.MkdirAll(s.f.Path("/root"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.f.Path("/root/old.json"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, o := range []DiagOptions{{Only: "dns"}, {Export: "diag.json"}, {Export: "/root/../x.json"}, {Export: "/root/old.json"},
		{Export: "/etc/ssh/sshd_config"}, {Export: "/var/lib/xm/state.json"}, {Export: "/root/"}, {Export: "/rootx/a.json"}} {
		if _, err := s.app.Diagnose(ctx(t), o); !errors.Is(err, ErrInput) {
			t.Fatalf("%+v: %v", o, err)
		}
	}
	if b, _ := os.ReadFile(s.f.Path("/root/old.json")); string(b) != "keep" {
		t.Fatalf("существующий файл заменён: %q", b)
	}
}
