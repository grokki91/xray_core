package diag

import (
	"cmp"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/grokki91/xray_core/internal/platform"
)

// HistoryDir — каталог истории отчётов (docs/architecture/data-model.md §1, §5).
const HistoryDir = "/var/lib/xm/diag"

// HistoryKeep — сколько отчётов хранится; превышение удаляет самые старые.
const HistoryKeep = 50

// reportID — имя отчёта: время прогона UTC и, при совпадении секунды, номер.
var reportID = regexp.MustCompile(`^\d{8}T\d{6}Z(-\d+)?$`)

// History — история отчётов: файл JSON на отчёт, уже прошедший редактор. Чужие файлы в
// каталоге не трогает.
type History struct{ FS platform.FS }

// Free — первое свободное имя отчёта: base, base-2, … (два прогона в одну секунду).
func (h History) Free(base string) (string, error) {
	if !reportID.MatchString(base) || strings.Contains(base, "-") {
		return "", fmt.Errorf("diag: неверное имя отчёта %q", base)
	}
	ids, err := h.List()
	if err != nil {
		return "", err
	}
	id := base
	for n := 2; slices.Contains(ids, id); n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	return id, nil
}

// Save записывает отчёт id и удаляет самые старые сверх HistoryKeep.
func (h History) Save(id string, doc []byte) error {
	if !reportID.MatchString(id) {
		return fmt.Errorf("diag: неверное имя отчёта %q", id)
	}
	if err := h.FS.WriteFile(path.Join(HistoryDir, id+".json"), doc, 0o600, platform.Root()); err != nil {
		return err
	}
	ids, err := h.List()
	if err != nil {
		return err
	}
	for ; len(ids) > HistoryKeep; ids = ids[1:] {
		if err := h.FS.Remove(path.Join(HistoryDir, ids[0]+".json")); err != nil {
			return fmt.Errorf("старый отчёт не удалён: %w", err)
		}
	}
	return nil
}

// List — имена отчётов от старого к новому; каталога нет — пусто.
func (h History) List() ([]string, error) {
	names, err := h.FS.ReadDir(HistoryDir)
	if errors.Is(err, platform.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, n := range names {
		if id, ok := strings.CutSuffix(n, ".json"); ok && reportID.MatchString(id) {
			ids = append(ids, id)
		}
	}
	// Имя начинается с времени: порядок имён — порядок времени; номер повтора — после основы.
	sortIDs(ids)
	return ids, nil
}

// sortIDs: base < base-2 < base-10 < следующая секунда.
func sortIDs(ids []string) {
	key := func(id string) (string, int) {
		b, n, _ := strings.Cut(id, "-")
		k, err := strconv.Atoi(n)
		if err != nil {
			k = 1
		}
		return b, k
	}
	slices.SortFunc(ids, func(x, y string) int {
		bx, kx := key(x)
		by, ky := key(y)
		return cmp.Or(strings.Compare(bx, by), cmp.Compare(kx, ky))
	})
}

// ErrNotFound — файла нет (platform.ErrNotFound): app проверяет им, что экспорт не заменит файл.
var ErrNotFound = platform.ErrNotFound

// Export записывает отчёт в файл владельца (`xm diag --export`): 0600, root. Допустимость
// пути — забота вызывающего (app: закрытый список каталогов, только новый файл).
func (h History) Export(file string, doc []byte) error {
	return h.FS.WriteFile(file, doc, 0o600, platform.Root())
}
