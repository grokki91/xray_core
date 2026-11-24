package platform

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUsersRejectBadNames(t *testing.T) {
	for _, i := range impls(t) {
		for _, name := range []string{"", "Xray", "x ray", "xray;id", "-x", "../x", "xray\n", "sshd2", "root"} {
			if _, err := i.p.Users().Ensure(deadline(t, time.Second), name); !errors.Is(err, ErrName) {
				t.Errorf("%s: имя %q: ошибка %v, нужна ErrName", i.name, name, err)
			}
		}
	}
}

func TestUsersEnsureExisting(t *testing.T) {
	// root есть на любой машине: поиск по имени читает идентификаторы без запуска программ.
	o, ok, err := lookup("root")
	if err != nil || !ok || o != Root() {
		t.Fatalf("root: %v, %v, %v", o, ok, err)
	}
	if _, ok, err := lookup("no-such-user-xm"); err != nil || ok {
		t.Fatalf("несуществующий: %v, %v", ok, err)
	}
}

func TestFakeUsersStable(t *testing.T) {
	f := NewFake(t.TempDir(), time.Time{})
	a, err := f.Users().Ensure(deadline(t, time.Second), "xray")
	if err != nil || a.UID == 0 {
		t.Fatalf("xray: %v, %v", a, err)
	}
	b, _ := f.Users().Ensure(deadline(t, time.Second), "xray")
	if a != b {
		t.Fatalf("повтор %v %v", a, b)
	}
	if _, err := f.Users().Ensure(t.Context(), "xray"); !errors.Is(err, ErrDeadline) {
		t.Fatalf("без срока: %v", err)
	}
}

func TestUsersRequireDeadline(t *testing.T) {
	for _, i := range impls(t) {
		if _, err := i.p.Users().Ensure(t.Context(), ServiceUser); !errors.Is(err, ErrDeadline) {
			t.Errorf("%s: без срока: %v", i.name, err)
		}
	}
}

// useraddStub — программа вместо useradd: пишет свои аргументы в файл и выходит с кодом code.
func useraddStub(t *testing.T, code int) (r *Real, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	stub := filepath.Join(dir, "useradd")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\nexit %d\n", argsFile, code)
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return newReal(map[string]string{useradd: stub}, http.DefaultTransport), argsFile
}

func TestRealUsersCreateRunsUseradd(t *testing.T) {
	if _, ok, _ := lookup(ServiceUser); ok {
		t.Skip("пользователь xray уже есть на машине теста")
	}
	// Заглушка ничего не создаёт: Ensure обязан заметить, что пользователь не появился.
	r, argsFile := useraddStub(t, 0)
	if _, err := r.Users().Ensure(deadline(t, 5*time.Second), ServiceUser); err == nil {
		t.Fatal("отсутствующий после useradd пользователь принят")
	}
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "--system\n--user-group\n--no-create-home\n--shell\n/usr/sbin/nologin\nxray\n"
	if string(b) != want {
		t.Fatalf("аргументы useradd:\n%s", b)
	}
}

func TestRealUsersUseraddFailure(t *testing.T) {
	if _, ok, _ := lookup(ServiceUser); ok {
		t.Skip("пользователь xray уже есть на машине теста")
	}
	r, _ := useraddStub(t, 9)
	if _, err := r.Users().Ensure(deadline(t, 5*time.Second), ServiceUser); err == nil {
		t.Fatal("ненулевой код useradd принят")
	}
}

func TestUseraddInClosedList(t *testing.T) {
	if programs()[useradd] != "/usr/sbin/useradd" {
		t.Fatal("useradd не в закрытом списке")
	}
}

func TestUsersRemoveChecks(t *testing.T) {
	for _, i := range impls(t) {
		if err := i.p.Users().Remove(deadline(t, time.Second), "root"); !errors.Is(err, ErrName) {
			t.Errorf("%s: root: %v, нужна ErrName", i.name, err)
		}
		if err := i.p.Users().Remove(t.Context(), ServiceUser); !errors.Is(err, ErrDeadline) {
			t.Errorf("%s: без срока: %v", i.name, err)
		}
	}
	f := NewFake(t.TempDir(), time.Time{})
	if _, err := f.Users().Ensure(deadline(t, time.Second), ServiceUser); err != nil {
		t.Fatal(err)
	}
	for range 2 { // повтор — не ошибка
		if err := f.Users().Remove(deadline(t, time.Second), ServiceUser); err != nil {
			t.Fatal(err)
		}
	}
}
