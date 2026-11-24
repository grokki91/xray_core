package app

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/server"
	"github.com/grokki91/xray_core/internal/store"
)

// installedXM — машина после install с правилом UFW и посторонним файлом рядом с xm.
func installedXM(t *testing.T) *sys {
	t.Helper()
	s := fresh(t)
	s.ufwStatus = ufwDenyByDefault
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.f.Path("/usr/local/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/usr/local/bin/xm", "/usr/local/bin/other"} {
		if err := s.f.FS().WriteFile(p, []byte("x"), 0o755, platform.Root()); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func exists(s *sys, p string) bool {
	_, err := os.Lstat(s.f.Path(p))
	return err == nil
}

func TestUninstallKeepsStateAndSnapshots(t *testing.T) {
	s := installedXM(t)
	before := countSnapshots(t, s)
	if err := s.app.Uninstall(ctx(t), false); err != nil {
		t.Fatal(err)
	}
	got := s.snap(t)
	if got.unit != nil || got.active || got.current != "" || got.state == nil || got.config == nil {
		t.Fatalf("после uninstall: %+v", got)
	}
	if exists(s, "/usr/local/bin/xm") || exists(s, "/usr/local/lib/xm") || !exists(s, "/usr/local/bin/other") {
		t.Fatal("бинарники: удалено не то")
	}
	if n := countSnapshots(t, s); n != before+1 {
		t.Fatalf("снимков %d, ждали %d", n, before+1)
	}
	if strings.Join(s.ufwRules, "|") != "allow 443/tcp|delete allow 443/tcp" {
		t.Fatalf("ufw: %q", s.ufwRules)
	}
	// Повтор ничего не ломает.
	if err := s.app.Uninstall(ctx(t), false); err != nil {
		t.Fatalf("повтор: %v", err)
	}
}

func TestUninstallPurgeLeavesNoTrace(t *testing.T) {
	s := installedXM(t)
	if err := s.app.Uninstall(ctx(t), true); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{store.StatePath, "/etc/xm", backup.Dir, "/var/lib/xm", "/usr/local/etc/xray", "/run/xm", "/usr/local/lib/xm", "/usr/local/bin/xm", server.UnitPath} {
		if exists(s, p) {
			t.Errorf("остался %s", p)
		}
	}
	if !exists(s, "/usr/local/bin/other") || !exists(s, "/usr/local/etc") || !exists(s, "/var/lib") {
		t.Error("удалено постороннее")
	}
	if err := s.app.Uninstall(ctx(t), true); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("после purge: %v, ждали ErrNotInstalled", err)
	}
}

// Сбой посередине — ошибка; повтор доводит удаление до конца.
func TestUninstallRetryAfterFailure(t *testing.T) {
	s := installedXM(t)
	s.fs.removePath = server.UnitPath
	if err := s.app.Uninstall(ctx(t), true); err == nil {
		t.Fatal("сбой удаления юнита не дал ошибки")
	}
	if !exists(s, store.StatePath) {
		t.Fatal("состояние удалено до конца удаления")
	}
	if err := s.app.Uninstall(ctx(t), true); err != nil {
		t.Fatalf("повтор: %v", err)
	}
	if exists(s, "/etc/xm") || exists(s, server.UnitPath) {
		t.Fatal("повтор не довёл удаление")
	}
}

func TestUninstallRefusesForeignUnit(t *testing.T) {
	s := installedXM(t)
	foreign := "[Service]\nExecStart=/bin/true\n"
	if err := s.f.FS().WriteFile(server.UnitPath, []byte(foreign), 0o644, platform.Root()); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	var pe *PreflightError
	if err := s.app.Uninstall(ctx(t), true); !errors.As(err, &pe) || pe.Issues[0].Code != server.CodeForeignInstall {
		t.Fatalf("ждали отказ предусловия о чужой установке, получено %v", err)
	}
	if !s.snap(t).equal(before) || !exists(s, "/usr/local/bin/xm") {
		t.Fatal("изменено до отказа")
	}
}

func TestUninstallNotInstalled(t *testing.T) {
	if err := fresh(t).app.Uninstall(ctx(t), false); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("ждали ErrNotInstalled, получено %v", err)
	}
}
