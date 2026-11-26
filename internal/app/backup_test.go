package app

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/server"
	"github.com/grokki91/xray_core/internal/store"
)

// Снимок → порча → восстановление (docs/roadmap.md, фаза 5, шаг 4): испорченные состояние и
// конфигурация возвращаются к снимку, служба перезапущена, а испорченное состояние осталось в
// автоснимке восстановления.
func TestBackupCorruptRestore(t *testing.T) {
	s := installed(t)
	if _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	s.f.SetNow(s.f.Clock().Now().Add(time.Minute))
	b, err := s.app.Backup(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if b.Kind != "manual" || !b.Valid || b.Xray != v1 || !strings.HasSuffix(b.ID, "-manual") {
		t.Fatalf("снимок: %+v", b)
	}
	want := s.snap(t)

	for _, p := range []string{store.StatePath, config.Path} {
		if err := s.f.FS().WriteFile(p, []byte("испорчено"), 0o600, platform.Root()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.app.ProfileList(ctx(t)); err == nil {
		t.Fatal("порча не видна: состояние читается")
	}
	s.f.SetNow(s.f.Clock().Now().Add(time.Minute))
	restarts := s.restarts
	if err := s.app.Restore(ctx(t), b.ID); err != nil {
		t.Fatal(err)
	}
	got := s.snap(t)
	if string(got.config) != string(want.config) || got.tx || !got.active || s.restarts == restarts {
		t.Fatalf("после восстановления: конфигурация совпала=%v, журнал=%v, служба=%v, перезапусков +%d",
			string(got.config) == string(want.config), got.tx, got.active, s.restarts-restarts)
	}
	if ps, err := s.app.ProfileList(ctx(t)); err != nil || len(ps.Profiles) != 1 || ps.Profiles[0].Name != "phone" {
		t.Fatalf("профили после восстановления: %+v, %v", ps, err)
	}
	list, err := s.app.BackupList(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	last := list.Backups[len(list.Backups)-1]
	if !strings.HasSuffix(last.ID, "-restore") || last.Kind != "auto" {
		t.Fatalf("нет автоснимка восстановления: %+v", list.Backups)
	}
	arch, err := s.app.s.Backup.Read(ctx(t), last.ID)
	if err != nil || string(arch.State) != "испорчено" {
		t.Fatalf("автоснимок восстановления не хранит прежнее состояние: %q, %v", arch.State, err)
	}
}

// Отказы restore — до всякого изменения: чужой идентификатор, нет снимка, снимок повреждён,
// снимок без состояния.
func TestRestoreRefusals(t *testing.T) {
	s := installed(t)
	bad := "20261116T110000Z-install"
	if err := os.WriteFile(s.f.Path(backup.Dir+"/"+bad+".tar.gz"), []byte("не архив"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Снимок без состояния: снят, пока state.json не было.
	sp := s.f.Path(store.StatePath)
	if err := os.Rename(sp, sp+".keep"); err != nil {
		t.Fatal(err)
	}
	s.f.SetNow(s.f.Clock().Now().Add(-time.Hour))
	empty, err := s.app.s.Backup.Create(ctx(t), "empty", backup.Meta{XM: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(sp+".keep", sp); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		id   string
		want error
	}{
		"не по правилу": {"../state", ErrInput},
		"нет снимка":    {"20261116T100000Z-manual", ErrSnapshot},
		"повреждён":     {bad, ErrSnapshot},
		"без состояния": {empty.ID, ErrSnapshot},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			before := s.snap(t)
			if err := s.app.Restore(ctx(t), c.id); !errors.Is(err, c.want) {
				t.Fatalf("ждали %v, получено %v", c.want, err)
			}
			if got := s.snap(t); !got.equal(before) {
				t.Fatal("отказ изменил систему")
			}
		})
	}
}

// Ручные снимки хранятся отдельно от автоснимков: транзакции их не вытесняют.
func TestManualSnapshotsSurviveAutoPrune(t *testing.T) {
	s := installed(t)
	start := s.f.Clock().Now()
	s.f.SetNow(start.Add(time.Second))
	b, err := s.app.Backup(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range backup.AutoKeep + 1 {
		s.f.SetNow(start.Add(time.Duration(i+1) * time.Minute))
		if _, err := s.app.ProfileAdd(ctx(t), "p"+string(rune('a'+i)), ShareOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.app.s.Backup.Read(ctx(t), b.ID); err != nil {
		t.Fatalf("ручной снимок вытеснен автоснимками: %v", err)
	}
}

func TestBackupNeedsInstallAndRoot(t *testing.T) {
	s := newSys(t)
	if _, err := s.app.Backup(ctx(t)); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("backup без установки: %v", err)
	}
	s.f.SetEffective(platform.Owner{UID: 1000, GID: 1000})
	var pe *PreflightError
	for name, err := range map[string]error{
		"restore": s.app.Restore(ctx(t), "20261116T100000Z-manual"),
		"list":    func() error { _, err := s.app.BackupList(ctx(t)); return err }(),
	} {
		if !errors.As(err, &pe) || pe.Issues[0].Code != server.CodeNotRoot {
			t.Fatalf("%s не от root: %v", name, err)
		}
	}
}

// Провал контроля после восстановления поверх повреждённого состояния: откат возвращает
// испорченные байты как есть, журнал очищен.
func TestRestoreOverCorruptStateRollsBack(t *testing.T) {
	s := installed(t)
	s.f.SetNow(s.f.Clock().Now().Add(time.Minute))
	b, err := s.app.Backup(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.f.FS().WriteFile(store.StatePath, []byte("испорчено"), 0o600, platform.Root()); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	s.f.SetNow(s.f.Clock().Now().Add(time.Minute))
	s.nRestart, s.restartListens = 0, []bool{false}
	if err := s.app.Restore(ctx(t), b.ID); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("ждали ErrRolledBack: %v", err)
	}
	got := s.snap(t)
	if string(got.state) != "испорчено" || string(got.config) != string(before.config) || got.tx {
		t.Fatalf("откат: состояние %q, конфигурация совпала=%v, журнал=%v", got.state, string(got.config) == string(before.config), got.tx)
	}
}

// Снимок с другим портом не восстанавливается: правило UFW открыто для текущего.
func TestRestoreRefusesOtherPort(t *testing.T) {
	s := installed(t)
	// Снимок с другим портом собирается из состояния на диске и сразу возвращается обратно.
	orig, err := os.ReadFile(s.f.Path(store.StatePath))
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	other.Server.Port = port + 1
	if err := s.app.s.Store.Save(other); err != nil {
		t.Fatal(err)
	}
	s.f.SetNow(s.f.Clock().Now().Add(time.Minute))
	b, err := s.app.s.Backup.Create(ctx(t), backup.ManualReason, backup.Meta{XM: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.f.Path(store.StatePath), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	if err := s.app.Restore(ctx(t), b.ID); !errors.Is(err, ErrSnapshot) || !strings.Contains(err.Error(), "порт") {
		t.Fatalf("ждали отказ по порту: %v", err)
	}
	if !s.snap(t).equal(before) {
		t.Fatal("отказ изменил систему")
	}
}

// Без установки восстанавливать нечего: состояния нет — отказ, а не установка в обход install.
func TestRestoreNeedsInstall(t *testing.T) {
	s := installed(t)
	s.f.SetNow(s.f.Clock().Now().Add(time.Minute))
	b, err := s.app.Backup(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.f.Path(store.StatePath)); err != nil {
		t.Fatal(err)
	}
	if err := s.app.Restore(ctx(t), b.ID); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("ждали ErrNotInstalled: %v", err)
	}
}
