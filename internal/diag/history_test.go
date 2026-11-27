package diag

import (
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

func history(t *testing.T) History {
	t.Helper()
	fs := platform.NewFake(t.TempDir(), time.Time{}).FS()
	for _, d := range []string{"/var", "/var/lib", "/var/lib/xm", HistoryDir} {
		if err := fs.Mkdir(d, 0o700, platform.Root()); err != nil {
			t.Fatal(err)
		}
	}
	return History{FS: fs}
}

// Совпадение секунды не перезаписывает отчёт; сверх предела удаляются самые старые; чужие
// файлы каталога не трогаются.
func TestHistorySaveAndPrune(t *testing.T) {
	h := history(t)
	if err := h.FS.WriteFile(path.Join(HistoryDir, "note.txt"), []byte("x"), 0o600, platform.Root()); err != nil {
		t.Fatal(err)
	}
	save := func(base, doc string) string {
		t.Helper()
		id, err := h.Free(base)
		if err == nil {
			err = h.Save(id, []byte(doc))
		}
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := save("20260101T000000Z", `{"n":1}`)
	if second := save("20260101T000000Z", `{"n":2}`); first != "20260101T000000Z" || second != "20260101T000000Z-2" {
		t.Fatalf("имена %q %q", first, second)
	}
	if b, _ := h.FS.ReadFile(path.Join(HistoryDir, first+".json")); string(b) != `{"n":1}` {
		t.Fatalf("первый отчёт перезаписан: %s", b)
	}
	for i := 0; i < HistoryKeep; i++ {
		save(fmt.Sprintf("20260102T%06dZ", i), "{}")
	}
	ids, err := h.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != HistoryKeep || ids[0] != "20260102T000000Z" || ids[len(ids)-1] != fmt.Sprintf("20260102T%06dZ", HistoryKeep-1) {
		t.Fatalf("после хранения: %d, %s … %s", len(ids), ids[0], ids[len(ids)-1])
	}
	if _, err := h.FS.ReadFile(path.Join(HistoryDir, "note.txt")); err != nil {
		t.Fatalf("чужой файл удалён: %v", err)
	}
}

func TestHistoryOrderAndBadName(t *testing.T) {
	ids := []string{"20260101T000001Z", "20260101T000000Z-10", "20260101T000000Z-2", "20260101T000000Z"}
	sortIDs(ids)
	if got := strings.Join(ids, ","); got != "20260101T000000Z,20260101T000000Z-2,20260101T000000Z-10,20260101T000001Z" {
		t.Fatalf("порядок %s", got)
	}
	if _, err := history(t).Free("../x"); err == nil {
		t.Fatal("имя с путём принято")
	}
}
