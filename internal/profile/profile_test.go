package profile

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/store"
)

var now = time.Date(2026, 11, 18, 12, 0, 0, 500, time.UTC)

// Фиктивные UUID v4: собираются во время теста.
func id(n byte) string {
	return strings.Repeat(string('0'+n), 8) + "-0000-4000-8000-" + strings.Repeat("0", 12)
}

func TestValidName(t *testing.T) {
	good := []string{"a", "phone", "0", "my-laptop_2", strings.Repeat("a", 32)}
	bad := []string{"", "-a", "_a", "Phone", "a b", "a.b", "имя", strings.Repeat("a", 33), "a/b", "a#b"}
	for _, n := range good {
		if !ValidName(n) {
			t.Errorf("%q отвергнуто", n)
		}
	}
	for _, n := range bad {
		if ValidName(n) {
			t.Errorf("%q принято", n)
		}
	}
}

func TestAddListGetRemove(t *testing.T) {
	m := New()
	orig := store.State{Profiles: []store.Profile{}}
	st, p, err := m.Add(orig, "phone", id(1), now)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || p.Name != "phone" || p.ID != id(1) || !p.Created.Equal(now.Truncate(time.Second)) {
		t.Fatalf("профиль: %+v", p)
	}
	if len(orig.Profiles) != 0 {
		t.Fatal("исходное состояние изменено")
	}
	st, _, err = m.Add(st, "laptop", id(2), now)
	if err != nil {
		t.Fatal(err)
	}
	if l := m.List(st); len(l) != 2 || l[0].Name != "phone" || l[1].Name != "laptop" {
		t.Fatalf("список: %+v", l)
	}
	if got, err := m.Get(st, "laptop"); err != nil || got.ID != id(2) {
		t.Fatalf("Get: %+v %v", got, err)
	}
	before := st
	st, err = m.Remove(st, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if l := m.List(st); len(l) != 1 || l[0].Name != "laptop" {
		t.Fatalf("после удаления: %+v", l)
	}
	if len(before.Profiles) != 2 || before.Profiles[0].Name != "phone" {
		t.Fatal("Remove изменил исходное состояние")
	}
}

func TestErrors(t *testing.T) {
	m := New()
	st, _, _ := m.Add(store.State{Profiles: []store.Profile{}}, "phone", id(1), now)
	cases := []struct {
		name string
		err  error
		run  func() error
	}{
		{"повтор имени", ErrExists, func() error { _, _, err := m.Add(st, "phone", id(2), now); return err }},
		{"повтор id", ErrInput, func() error { _, _, err := m.Add(st, "tab", id(1), now); return err }},
		{"плохое имя", ErrInput, func() error { _, _, err := m.Add(st, "Bad", id(2), now); return err }},
		{"плохой id", ErrInput, func() error { _, _, err := m.Add(st, "tab", "not-a-uuid", now); return err }},
		{"Get нет", ErrNotFound, func() error { _, err := m.Get(st, "none"); return err }},
		{"Get плохое имя", ErrInput, func() error { _, err := m.Get(st, "../x"); return err }},
		{"Remove нет", ErrNotFound, func() error { _, err := m.Remove(st, "none"); return err }},
	}
	for _, c := range cases {
		if err := c.run(); !errors.Is(err, c.err) {
			t.Errorf("%s: %v, нужно %v", c.name, err, c.err)
		}
	}
	// Ошибка не несёт идентификатор клиента.
	_, _, err := m.Add(st, "tab", id(1), now)
	if strings.Contains(err.Error(), id(1)) {
		t.Errorf("идентификатор в ошибке: %v", err)
	}
}
