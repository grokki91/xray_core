package cli

import (
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/contract"
)

// restore без слова подтверждения ничего не вызывает; со словом или --yes — вызывает с id.
func TestRestoreNeedsConfirmation(t *testing.T) {
	const id = "20260101T000000Z-manual"
	f := &fakeApp{}
	if code, _, stderr := runInput(f, "нет\n", "restore", id); code != exitUsage || f.restored != "" || !strings.Contains(stderr, "ничего не изменено") {
		t.Fatalf("без подтверждения: код %d, restore(%q), stderr %q", code, f.restored, stderr)
	}
	if code, stdout, _ := runInput(f, "restore\n", "restore", id); code != exitOK || f.restored != id || !strings.Contains(stdout, "восстановлено") {
		t.Fatalf("со словом: код %d, restore(%q), stdout %q", code, f.restored, stdout)
	}
	f = &fakeApp{}
	if code, _, _ := runInput(f, "", "restore", "--yes", id); code != exitOK || f.restored != id {
		t.Fatalf("--yes: код %d, restore(%q)", code, f.restored)
	}
	if code, _, _ := runInput(&fakeApp{}, "", "restore"); code != exitUsage {
		t.Fatalf("без id: код %d", code)
	}
}

// --list показывает снимки и помечает повреждённый; без флага создаётся снимок.
func TestBackupListAndCreate(t *testing.T) {
	f := &fakeApp{backups: contract.Backups{Backups: []contract.BackupItem{
		{ID: "20260101T000000Z-manual", Created: 1767225600, Kind: "manual", XM: "0.1.0", Xray: "26.11.9", Valid: true},
		{ID: "20260101T010000Z-install", Created: 1767229200, Kind: "auto"},
		{ID: "20260101T020000Z-install", Created: 1767232800, Kind: "auto", XM: "0.1.0", Valid: true},
	}}}
	code, stdout, _ := runWith(f, "backup", "--list")
	if code != exitOK || !strings.Contains(stdout, "ручной  xm 0.1.0, Xray 26.11.9") || !strings.Contains(stdout, "повреждён") ||
		!strings.Contains(stdout, "Xray не установлен") {
		t.Fatalf("код %d, stdout %q", code, stdout)
	}
	if code, stdout, _ := runWith(&fakeApp{}, "backup", "--list"); code != exitOK || !strings.Contains(stdout, "Снимков нет") {
		t.Fatalf("пустой список: код %d, %q", code, stdout)
	}
	if code, stdout, _ := runWith(f, "backup", "--json"); code != exitOK || !strings.Contains(stdout, `"name": "backups"`) {
		t.Fatalf("создание --json: код %d, %q", code, stdout)
	}
}
