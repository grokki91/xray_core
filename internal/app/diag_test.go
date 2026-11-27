package app

import (
	"errors"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/diag"
	"github.com/grokki91/xray_core/internal/platform"
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

// Категория host связана с измерениями узла: место, память, OOM службы, часы.
func TestDiagnoseHost(t *testing.T) {
	s := installed(t)
	for _, p := range []string{"/var/lib/xm", "/usr/local/lib/xm"} {
		s.f.SetUsage(p, platform.DiskUsage{Avail: 8 << 30, Total: 20 << 30})
	}
	if err := s.f.FS().WriteFile("/proc/meminfo", []byte("MemTotal: 2000000 kB\nMemAvailable: 1000000 kB\n"), 0o644, platform.Root()); err != nil {
		t.Fatal(err)
	}
	s.f.Handle(platform.Journalctl, func(platform.Command) (platform.Result, error) {
		return platform.Result{Stdout: []byte("xray.service: Failed with result 'oom-kill'.\n")}, nil
	})
	s.f.Handle(platform.Timedatectl, func(platform.Command) (platform.Result, error) {
		return platform.Result{Stdout: []byte("yes\n")}, nil
	})
	env, err := s.app.Diagnose(ctx(t), DiagOptions{Only: "host"})
	if err != nil {
		t.Fatal(err)
	}
	r := env.Data.(contract.DiagReport)
	got := map[string]string{}
	for _, o := range r.Observations {
		got[o.Check+" "+o.Target] = o.Status
	}
	want := map[string]string{
		"host.disk disk:/var/lib/xm": "ok", "host.disk disk:/usr/local/lib/xm": "ok",
		"host.memory memory": "ok", "host.memory.oom xray.service": "fail", "host.clock clock": "ok",
	}
	if len(got) != len(want) {
		t.Fatalf("наблюдения: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, нужно %q (все: %v)", k, got[k], v, got)
		}
	}
	if r.Health != "degraded" {
		t.Errorf("health %s, нужно degraded", r.Health)
	}
}
