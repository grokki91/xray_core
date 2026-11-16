package platform

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const showOK = "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nNRestarts=2\nMainPID=4242\n"

// systemctlStub — настоящая Real на заглушке systemctl: печатает stdout, пишет аргументы в файл.
func systemctlStub(t *testing.T, stdout string, code int) (*Real, string) {
	t.Helper()
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	stub := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(stub, []byte(fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\ncat <<'EOT'\n%sEOT\nexit %d\n", argsFile, stdout, code)), 0o700); err != nil {
		t.Fatal(err)
	}
	return newReal(map[string]string{systemctl: stub}, http.DefaultTransport), argsFile
}

func TestRealSystemdStatusPassesFixedArgs(t *testing.T) {
	r, argsFile := systemctlStub(t, showOK, 0)
	st, err := r.Systemd().Status(deadline(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	want := UnitStatus{Loaded: true, Active: "active", Sub: "running", Enabled: true, Restarts: 2, MainPID: 4242}
	if st != want {
		t.Fatalf("состояние %+v, нужно %+v", st, want)
	}
	b, _ := os.ReadFile(argsFile)
	wantArgs := "--no-ask-password\n--no-pager\nshow\nxray.service\n--property=LoadState,ActiveState,SubState,UnitFileState,NRestarts,MainPID\n"
	if string(b) != wantArgs {
		t.Fatalf("аргументы:\n%s", b)
	}
}

func TestSystemdVerbs(t *testing.T) {
	for verb, call := range map[string]func(Systemd) error{
		"enable":  func(s Systemd) error { return s.Enable(deadline(t, 5*time.Second)) },
		"disable": func(s Systemd) error { return s.Disable(deadline(t, 5*time.Second)) },
		"start":   func(s Systemd) error { return s.Start(deadline(t, 5*time.Second)) },
		"stop":    func(s Systemd) error { return s.Stop(deadline(t, 5*time.Second)) },
		"restart": func(s Systemd) error { return s.Restart(deadline(t, 5*time.Second)) },
	} {
		r, argsFile := systemctlStub(t, "", 0)
		if err := call(r.Systemd()); err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		b, _ := os.ReadFile(argsFile)
		if want := "--no-ask-password\n--no-pager\n" + verb + "\nxray.service\n"; string(b) != want {
			t.Errorf("%s: аргументы:\n%s", verb, b)
		}
		r, _ = systemctlStub(t, "", 5)
		if err := call(r.Systemd()); err == nil {
			t.Errorf("%s: ненулевой код принят", verb)
		}
	}
}

func TestSystemdReload(t *testing.T) {
	r, argsFile := systemctlStub(t, "", 0)
	if err := r.Systemd().Reload(deadline(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(argsFile)
	if want := "--no-ask-password\n--no-pager\ndaemon-reload\n"; string(b) != want {
		t.Fatalf("аргументы:\n%s", b)
	}
	r, _ = systemctlStub(t, "", 1)
	if r.Systemd().Reload(deadline(t, 5*time.Second)) == nil {
		t.Fatal("ненулевой код принят")
	}
}

func TestSystemdRunning(t *testing.T) {
	for state, ok := range map[string]bool{"running\n": true, "degraded\n": true, "offline\n": false, "starting\n": false, "": false} {
		code := 0
		if state != "running\n" {
			code = 1 // degraded у systemctl тоже даёт код 1: решает вывод, а не код
		}
		r, _ := systemctlStub(t, state, code)
		err := r.Systemd().Running(deadline(t, 5*time.Second))
		if ok && err != nil || !ok && !errors.Is(err, ErrNoSystemd) {
			t.Errorf("состояние %q: ошибка %v", state, err)
		}
	}
}

func TestSystemdStatusStrict(t *testing.T) {
	for name, out := range map[string]string{
		"нет свойства":   "LoadState=loaded\nActiveState=active\n",
		"нечисловой PID": strings.Replace(showOK, "MainPID=4242", "MainPID=x", 1),
		"отрицательные":  strings.Replace(showOK, "NRestarts=2", "NRestarts=-1", 1),
	} {
		r, _ := systemctlStub(t, out, 0)
		if _, err := r.Systemd().Status(deadline(t, 5*time.Second)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	// Юнита нет: systemctl show отвечает кодом 0 и LoadState=not-found.
	r, _ := systemctlStub(t, strings.Replace(showOK, "LoadState=loaded", "LoadState=not-found", 1), 0)
	st, err := r.Systemd().Status(deadline(t, 5*time.Second))
	if err != nil || st.Loaded {
		t.Fatalf("юнита нет: %+v, %v", st, err)
	}
}

func TestFakeSystemdUsesHandler(t *testing.T) {
	f := NewFake(t.TempDir(), time.Time{})
	f.Handle(systemctl, func(c Command) (Result, error) { return Result{Stdout: []byte(showOK)}, nil })
	if _, err := f.Systemd().Status(deadline(t, time.Second)); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range f.Calls() {
		if c.Op == "exec" && c.Path == systemctl {
			got = c.Args
		}
	}
	if !slices.Contains(got, ServiceUnit) {
		t.Fatalf("вызов systemctl не записан: %v", got)
	}
}

func TestSystemdRequiresDeadline(t *testing.T) {
	r, _ := systemctlStub(t, "", 0)
	if err := r.Systemd().Start(t.Context()); !errors.Is(err, ErrDeadline) {
		t.Fatalf("без срока: %v", err)
	}
}

func TestSystemctlInClosedList(t *testing.T) {
	if programs()[systemctl] != "/usr/bin/systemctl" {
		t.Fatalf("systemctl в закрытом списке: %q", programs()[systemctl])
	}
}

func TestUsersEffective(t *testing.T) {
	r := New()
	if o := r.Users().Effective(); o.UID != os.Geteuid() || o.GID != os.Getegid() {
		t.Fatalf("настоящий: %+v", o)
	}
	f := NewFake(t.TempDir(), time.Time{})
	if f.Users().Effective() != Root() {
		t.Fatal("поддельный по умолчанию — не root")
	}
	f.SetEffective(Owner{UID: 1000, GID: 1000})
	if f.Users().Effective() != (Owner{UID: 1000, GID: 1000}) {
		t.Fatal("SetEffective не действует")
	}
}
