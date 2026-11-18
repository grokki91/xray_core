package app

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/profile"
	"github.com/grokki91/xray_core/internal/server"
)

func installed(t *testing.T) *sys {
	t.Helper()
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf(), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	return s
}

func readConfig(t *testing.T, s *sys) string {
	t.Helper()
	b, err := os.ReadFile(s.f.Path(config.Path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Профиль добавляется и удаляется транзакцией: его ключ появляется в конфигурации Xray и
// исчезает из неё, служба перезапускается.
func TestProfileAddListShowRemove(t *testing.T) {
	s := installed(t)
	restarts := s.restarts
	p, err := s.app.AddProfile(ctx(t), "phone")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || p.Name != "phone" || p.ID == "" {
		t.Fatalf("профиль: %+v", p)
	}
	if !strings.Contains(readConfig(t, s), p.ID) {
		t.Fatal("ключ профиля не попал в конфигурацию")
	}
	if s.restarts == restarts || s.snap(t).tx {
		t.Fatal("изменение не применено транзакцией")
	}
	if _, err := s.app.AddProfile(ctx(t), "laptop"); err != nil {
		t.Fatal(err)
	}
	list, err := s.app.Profiles(ctx(t))
	if err != nil || len(list) != 2 || list[0].Name != "phone" || list[1].Name != "laptop" {
		t.Fatalf("список: %+v %v", list, err)
	}
	if got, err := s.app.Profile(ctx(t), "phone"); err != nil || got.ID != p.ID {
		t.Fatalf("показ: %+v %v", got, err)
	}
	if err := s.app.RemoveProfile(ctx(t), "phone"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readConfig(t, s), p.ID) {
		t.Fatal("ключ удалённого профиля остался в конфигурации")
	}
	if _, err := s.app.Profile(ctx(t), "phone"); !errors.Is(err, ErrInput) || !errors.Is(err, profile.ErrNotFound) {
		t.Fatalf("удалённый профиль: %v", err)
	}
}

// Отказ до изменения: система не тронута, снимка нет.
func TestProfileRefusals(t *testing.T) {
	s := installed(t)
	if _, err := s.app.AddProfile(ctx(t), "phone"); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	restarts := s.restarts
	for name, run := range map[string]func() error{
		"плохое имя":  func() error { _, err := s.app.AddProfile(ctx(t), "Phone"); return err },
		"повтор":      func() error { _, err := s.app.AddProfile(ctx(t), "phone"); return err },
		"rm нет":      func() error { return s.app.RemoveProfile(ctx(t), "none") },
		"rm плохое":   func() error { return s.app.RemoveProfile(ctx(t), "../x") },
		"show плохое": func() error { _, err := s.app.Profile(ctx(t), "a b"); return err },
	} {
		if err := run(); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v, нужен ErrInput", name, err)
		}
	}
	if after := s.snap(t); !before.equal(after) || s.restarts != restarts {
		t.Fatal("отказ изменил систему")
	}
}

func TestProfileNeedsInstallAndRoot(t *testing.T) {
	s := newFresh(t)
	if _, err := s.app.AddProfile(ctx(t), "phone"); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("add без установки: %v", err)
	}
	if _, err := s.app.Profiles(ctx(t)); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("list без установки: %v", err)
	}
	s.f.SetEffective(platform.Owner{UID: 1000, GID: 1000})
	var pe *PreflightError
	if _, err := s.app.Profiles(ctx(t)); !errors.As(err, &pe) || pe.Issues[0].Code != server.CodeNotRoot {
		t.Fatalf("list не от root: %v", err)
	}
}

// Провал контроля после добавления откатывает транзакцию: профиля нет ни в состоянии, ни в
// конфигурации.
func TestProfileAddRollsBack(t *testing.T) {
	s := installed(t)
	before := s.snap(t)
	s.nRestart, s.restartListens = 0, []bool{false}
	if _, err := s.app.AddProfile(ctx(t), "phone"); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("ждали ErrRolledBack: %v", err)
	}
	if after := s.snap(t); !before.equal(after) {
		t.Fatal("откат не вернул исходное")
	}
	if list, err := s.app.Profiles(ctx(t)); err != nil || len(list) != 0 {
		t.Fatalf("профиль остался: %+v %v", list, err)
	}
}
