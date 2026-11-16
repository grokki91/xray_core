package platform

import (
	"errors"
	"testing"
	"time"
)

func TestUsersRejectBadNames(t *testing.T) {
	for _, i := range impls(t) {
		for _, name := range []string{"", "Xray", "x ray", "xray;id", "-x", "../x", "x\n", string(make([]byte, 33))} {
			if _, err := i.p.Users().Ensure(deadline(t, time.Second), name); !errors.Is(err, ErrName) {
				t.Errorf("%s: имя %q: ошибка %v, нужна ErrName", i.name, name, err)
			}
		}
	}
}

func TestUsersEnsureExisting(t *testing.T) {
	// root есть на любой машине: настоящая реализация возвращает его без запуска useradd.
	o, err := New().Users().Ensure(deadline(t, time.Second), "root")
	if err != nil || o != Root() {
		t.Fatalf("root: %v, %v", o, err)
	}
}

func TestFakeUsersStable(t *testing.T) {
	f := NewFake(t.TempDir(), time.Time{})
	a, err := f.Users().Ensure(deadline(t, time.Second), "xray")
	if err != nil || a.UID == 0 {
		t.Fatalf("xray: %v, %v", a, err)
	}
	b, _ := f.Users().Ensure(deadline(t, time.Second), "xray")
	c, _ := f.Users().Ensure(deadline(t, time.Second), "other")
	if a != b || a == c {
		t.Fatalf("повтор %v %v, другой %v", a, b, c)
	}
	if _, err := f.Users().Ensure(t.Context(), "xray"); !errors.Is(err, ErrDeadline) {
		t.Fatalf("без срока: %v", err)
	}
}

func TestUseraddInClosedList(t *testing.T) {
	if programs()[useradd] != "/usr/sbin/useradd" {
		t.Fatal("useradd не в закрытом списке")
	}
}
