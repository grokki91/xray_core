package server

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

const cfg = "/usr/local/etc/xray/config.json"

var now = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

// host — здоровая машина: Ubuntu 24.04, 2 ГБ, systemd работает; systemctl записывает вызовы.
type host struct {
	f     *platform.Fake
	m     *Manager
	calls [][]string // аргументы systemctl без общих флагов
	state string     // ответ is-system-running
	code  int        // код всех остальных подкоманд
}

func newHost(t *testing.T) *host {
	t.Helper()
	h := &host{f: platform.NewFake(t.TempDir(), now), state: "running\n"}
	h.m = New(h.f, cfg)
	h.f.Handle("systemctl", func(c platform.Command) (platform.Result, error) {
		args := c.Args[2:]
		h.calls = append(h.calls, args)
		if args[0] == "is-system-running" {
			return platform.Result{Stdout: []byte(h.state)}, nil
		}
		return platform.Result{ExitCode: h.code}, nil
	})
	if err := os.MkdirAll(h.f.Path("/etc/systemd/system"), 0o755); err != nil { // есть на любой Ubuntu
		t.Fatal(err)
	}
	h.write(t, "/usr/lib/os-release", "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n")
	h.write(t, "/proc/meminfo", "MemTotal:        2008064 kB\nMemFree: 1 kB\n")
	return h
}

func (h *host) write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(h.f.Path(dirOf(path)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := h.f.FS().WriteFile(path, []byte(data), 0o644, platform.Root()); err != nil {
		t.Fatal(err)
	}
}

func dirOf(p string) string { return p[:strings.LastIndex(p, "/")] }

func codes(is []Issue) []string {
	var c []string
	for _, i := range is {
		c = append(c, i.Code)
	}
	return c
}

func TestPreflightCleanHost(t *testing.T) {
	h := newHost(t)
	facts, issues := h.m.Preflight(ctx(t))
	if len(issues) != 0 {
		t.Fatalf("замечания на здоровой машине: %v", issues)
	}
	if facts.OS != "ubuntu 24.04" || facts.MemMiB != 1961 || facts.Arch == "" {
		t.Fatalf("факты: %+v", facts)
	}
}

func TestPreflightFindsEachProblem(t *testing.T) {
	cases := map[string]struct {
		mutate func(*testing.T, *host)
		want   string
	}{
		"не root": {func(_ *testing.T, h *host) { h.f.SetEffective(platform.Owner{UID: 1000, GID: 1000}) }, CodeNotRoot},
		"Ubuntu 20.04": {func(t *testing.T, h *host) {
			h.write(t, "/usr/lib/os-release", "ID=ubuntu\nVERSION_ID=\"20.04\"\n")
		}, CodeOS},
		"Ubuntu 26.04 до решения Q8": {func(t *testing.T, h *host) {
			h.write(t, "/usr/lib/os-release", "ID=ubuntu\nVERSION_ID=\"26.04\"\n")
		}, CodeOS},
		"Debian": {func(t *testing.T, h *host) {
			h.write(t, "/usr/lib/os-release", "ID=debian\nVERSION_ID=\"24.04\"\n")
		}, CodeOS},
		"нет os-release": {func(t *testing.T, h *host) {
			if err := os.Remove(h.f.Path("/usr/lib/os-release")); err != nil {
				t.Fatal(err)
			}
		}, CodeOS},
		"мало памяти":  {func(t *testing.T, h *host) { h.write(t, "/proc/meminfo", "MemTotal: 262144 kB\n") }, CodeResources},
		"нет MemTotal": {func(t *testing.T, h *host) { h.write(t, "/proc/meminfo", "MemFree: 1 kB\n") }, CodeResources},
		"нет systemd":  {func(_ *testing.T, h *host) { h.state = "offline\n" }, CodeSystemd},
		"часы назад":   {func(_ *testing.T, h *host) { h.f.SetNow(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)) }, CodeClock},
		"чужой юнит": {func(t *testing.T, h *host) {
			h.write(t, UnitPath, "[Service]\nExecStart=/usr/local/bin/xray\n")
		}, CodeForeignInstall},
		"чужая конфигурация": {func(t *testing.T, h *host) { h.write(t, cfg, "{}") }, CodeForeignInstall},
	}
	for name, c := range cases {
		h := newHost(t)
		c.mutate(t, h)
		_, issues := h.m.Preflight(ctx(t))
		if got := codes(issues); !slices.Contains(got, c.want) {
			t.Errorf("%s: замечания %v, нужно %s", name, got, c.want)
		}
	}
}

func TestPreflightReportsAllAtOnce(t *testing.T) {
	h := newHost(t)
	h.f.SetEffective(platform.Owner{UID: 1})
	h.state = "offline\n"
	h.write(t, "/proc/meminfo", "MemTotal: 1024 kB\n")
	if _, issues := h.m.Preflight(ctx(t)); len(issues) < 3 {
		t.Fatalf("найдено %v", codes(issues))
	}
}

func TestPreflightOwnInstallIsNotForeign(t *testing.T) {
	h := newHost(t)
	if err := h.m.InstallUnit(ctx(t), UnitSpec{}); err != nil {
		t.Fatal(err)
	}
	h.write(t, cfg, "{}") // конфигурация рядом с юнитом xm — своя
	if _, issues := h.m.Preflight(ctx(t)); len(issues) != 0 {
		t.Fatalf("своя установка названа чужой: %v", issues)
	}
}

func TestInstallUnitContentAndCalls(t *testing.T) {
	h := newHost(t)
	spec := UnitSpec{Hardening: []UnitOption{{"NoNewPrivileges", "true"}, {"RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX"}}}
	if err := h.m.InstallUnit(ctx(t), spec); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(h.f.Path(UnitPath))
	if err != nil {
		t.Fatal(err)
	}
	want := `# managed-by: xm
[Unit]
Description=Xray (managed by xm)
After=network.target nss-lookup.target

[Service]
Type=simple
User=xray
ExecStart=/usr/local/lib/xm/core/current/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
`
	if string(b) != want {
		t.Fatalf("юнит:\n%s", b)
	}
	if o, ok := h.f.Owner(UnitPath); !ok || o != platform.Root() {
		t.Fatalf("владелец юнита: %v, %v", o, ok)
	}
	if fi, _ := os.Stat(h.f.Path(UnitPath)); fi.Mode().Perm() != 0o644 {
		t.Fatalf("права юнита: %v", fi.Mode().Perm())
	}
	if got := verbs(h); !slices.Equal(got, []string{"daemon-reload", "enable"}) {
		t.Fatalf("вызовы systemctl: %v", got)
	}
	// Повтор — тот же файл (идемпотентность).
	if err := h.m.InstallUnit(ctx(t), spec); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(h.f.Path(UnitPath))
	if string(b2) != want {
		t.Fatal("повторная установка изменила юнит")
	}
}

func verbs(h *host) []string {
	var v []string
	for _, c := range h.calls {
		v = append(v, c[0])
	}
	return v
}

func TestInstallUnitRejectsBadSpec(t *testing.T) {
	bad := []UnitOption{
		{"ExecStart", "/bin/sh"}, {"User", "root"}, {"Restart", "no"},
		{"Key\nExecStart", "x"}, {"Key=x", "y"}, {"", "x"}, {"NoNewPrivileges", ""},
		{"NoNewPrivileges", "true\nExecStartPre=/bin/sh"}, {"NoNewPrivileges", " true"}, {"A", "b\x00"},
	}
	for _, o := range bad {
		h := newHost(t)
		err := h.m.InstallUnit(ctx(t), UnitSpec{Hardening: []UnitOption{o}})
		if !errors.Is(err, ErrSpec) {
			t.Errorf("%q: ошибка %v", o, err)
		}
		if _, err := os.Stat(h.f.Path(UnitPath)); !errors.Is(err, fs.ErrNotExist) || len(h.calls) != 0 {
			t.Errorf("%q: до проверки что-то сделано", o)
		}
	}
	for _, cfgPath := range []string{"", "etc/x.json", "/etc/x y.json", "/etc/../x", "/etc/x\nExecStartPre=/bin/sh"} {
		h := newHost(t)
		if err := New(h.f, cfgPath).InstallUnit(ctx(t), UnitSpec{}); !errors.Is(err, ErrSpec) {
			t.Errorf("путь %q: ошибка %v", cfgPath, err)
		}
	}
}

func TestInstallUnitKeepsForeign(t *testing.T) {
	h := newHost(t)
	h.write(t, UnitPath, "[Service]\nExecStart=/usr/local/bin/xray\n")
	if err := h.m.InstallUnit(ctx(t), UnitSpec{}); !errors.Is(err, ErrForeign) {
		t.Fatalf("ошибка %v", err)
	}
	if b, _ := os.ReadFile(h.f.Path(UnitPath)); !strings.Contains(string(b), "/usr/local/bin/xray") || len(h.calls) != 0 {
		t.Fatal("чужой юнит изменён")
	}
	if err := h.m.RemoveUnit(ctx(t)); !errors.Is(err, ErrForeign) {
		t.Fatalf("RemoveUnit чужого: %v", err)
	}
	if _, err := os.Stat(h.f.Path(UnitPath)); err != nil {
		t.Fatal("чужой юнит удалён")
	}
}

func TestInstallUnitSystemctlFailure(t *testing.T) {
	h := newHost(t)
	h.code = 1
	if err := h.m.InstallUnit(ctx(t), UnitSpec{}); err == nil {
		t.Fatal("сбой systemctl принят")
	}
}

func TestRemoveUnit(t *testing.T) {
	h := newHost(t)
	if err := h.m.RemoveUnit(ctx(t)); err != nil || len(h.calls) != 0 {
		t.Fatalf("юнита нет: %v, вызовы %v", err, h.calls)
	}
	if err := h.m.InstallUnit(ctx(t), UnitSpec{}); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	if err := h.m.RemoveUnit(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.f.Path(UnitPath)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("юнит не удалён")
	}
	if got := verbs(h); !slices.Equal(got, []string{"disable", "daemon-reload"}) {
		t.Fatalf("вызовы: %v", got)
	}
}

func TestServiceCommands(t *testing.T) {
	h := newHost(t)
	s := h.m.Service()
	for verb, call := range map[string]func(context.Context) error{"start": s.Start, "stop": s.Stop, "restart": s.Restart} {
		h.calls = nil
		if err := call(ctx(t)); err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		if len(h.calls) != 1 || !slices.Equal(h.calls[0], []string{verb, "xray.service"}) {
			t.Errorf("%s: вызовы %v", verb, h.calls)
		}
	}
	h.code = 3
	if err := s.Start(ctx(t)); err == nil {
		t.Fatal("сбой запуска принят")
	}
}

func TestServiceStatus(t *testing.T) {
	h := newHost(t)
	h.f.Handle("systemctl", func(platform.Command) (platform.Result, error) {
		return platform.Result{Stdout: []byte("LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nNRestarts=0\nMainPID=77\n")}, nil
	})
	st, err := h.m.Service().Status(ctx(t))
	if err != nil || !st.Loaded || st.Active != "active" || !st.Enabled || st.MainPID != 77 {
		t.Fatalf("состояние %+v, %v", st, err)
	}
}
