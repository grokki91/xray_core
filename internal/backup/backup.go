// Пакет backup — снимок состояния и конфигурации (tar.gz с манифестом SHA-256) и чтение снимка
// с проверкой. Запись файлов обратно — дело транзакции app: здесь только создать и вернуть
// проверенное содержимое; хранение автоснимков — Prune. Список и команды — фаза 5.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/store"
)

// Dir — каталог снимков; создаёт и закрывает правами security.EnsureBaseline.
const Dir = "/var/lib/xm/backups"

const (
	statePath = store.StatePath
	// Путь живёт в config.Path; менеджеры друг друга не импортируют (repository.md §3).
	configPath = "/usr/local/etc/xray/config.json"

	stateName    = "state.json"
	configName   = "config.json"
	manifestName = "manifest.json"

	manifestVersion = 1
	// AutoKeep — сколько последних автоснимков хранится (data-model.md §4).
	AutoKeep = 10
	// maxEntry — предел одной записи при чтении: защита от архива-бомбы. Состояние и
	// конфигурация — килобайты.
	maxEntry = 8 << 20
)

var (
	// ErrInput — причина, идентификатор или версия не по закрытому правилу.
	ErrInput = errors.New("недопустимый ввод снимка")
	// ErrExists — снимок с таким идентификатором уже есть; он не перезаписывается.
	ErrExists = errors.New("снимок уже есть")
	// ErrCorrupt — архив не прошёл проверку: структура, имена, размеры или суммы.
	ErrCorrupt = errors.New("снимок повреждён")
	// ErrNotFound — снимка с таким идентификатором нет.
	ErrNotFound = platform.ErrNotFound
)

var (
	reasonRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	idRe     = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[a-z0-9]+(-[a-z0-9]+)*$`)
	xmVerRe  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)
)

// Meta — версии, которые снимок записывает в манифест. Xray пуст, пока ядра нет.
type Meta struct {
	XM, Xray string
}

// Snapshot — созданный снимок.
type Snapshot struct {
	ID      string
	Created time.Time
}

// Manifest — manifest.json внутри снимка. В нём нет секретов: только версии и суммы.
type Manifest struct {
	Version     int               `json:"version"`
	Reason      string            `json:"reason"`
	Created     time.Time         `json:"created"`
	XM          string            `json:"xm"`
	Xray        string            `json:"xray"`
	StateSchema int               `json:"state_schema"`
	Files       map[string]string `json:"files"` // имя → SHA-256 в hex
}

// Archive — проверенное содержимое снимка. Файл, которого в снимке не было (чистая установка),
// — nil.
type Archive struct {
	Manifest Manifest
	State    []byte
	Config   []byte
}

// Manager — снимки на диске.
type Manager struct {
	p platform.Platform
}

func New(p platform.Platform) *Manager { return &Manager{p: p} }

// Create снимает state.json и config.json. Единственность идентификатора обеспечивает блокировка
// транзакции в app: проверка «снимка нет» и запись не атомарны. Идентификатор точен до секунды. Отсутствующий файл (ErrNotFound) — не ошибка:
// снимок чистой установки пуст; любая другая ошибка чтения прерывает снимок.
func (m *Manager) Create(ctx context.Context, reason string, meta Meta) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if !reasonRe.MatchString(reason) || len(reason) > 32 {
		return Snapshot{}, fmt.Errorf("%w: причина %q", ErrInput, reason)
	}
	if !xmVerRe.MatchString(meta.XM) || (meta.Xray != "" && !platform.ValidVersion(meta.Xray)) {
		return Snapshot{}, fmt.Errorf("%w: версии xm или Xray", ErrInput)
	}
	fsys := m.p.FS()
	files := map[string][]byte{}
	for name, path := range map[string]string{stateName: statePath, configName: configPath} {
		data, err := fsys.ReadFile(path)
		if errors.Is(err, platform.ErrNotFound) {
			continue
		}
		if err != nil {
			return Snapshot{}, fmt.Errorf("снимок: чтение %s: %w", path, err)
		}
		files[name] = data
	}
	var schema int
	if data, ok := files[stateName]; ok {
		var head struct {
			SchemaVersion int `json:"schema_version"`
		}
		// Повреждённое состояние снимается как есть: автоснимок и нужен, чтобы его вернуть.
		// Версия схемы тогда 0.
		if json.Unmarshal(data, &head) == nil {
			schema = head.SchemaVersion
		}
	}

	now := m.p.Clock().Now().UTC().Truncate(time.Second)
	id := now.Format("20060102T150405Z") + "-" + reason
	path := Dir + "/" + id + ".tar.gz"
	if _, err := fsys.ReadFile(path); err == nil {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrExists, id)
	} else if !errors.Is(err, platform.ErrNotFound) {
		return Snapshot{}, fmt.Errorf("снимок: проверка %s: %w", id, err)
	}

	mf := Manifest{Version: manifestVersion, Reason: reason, Created: now, XM: meta.XM, Xray: meta.Xray, StateSchema: schema, Files: map[string]string{}}
	for name, data := range files {
		mf.Files[name] = sum(data)
	}
	mdata, err := json.Marshal(mf)
	if err != nil {
		return Snapshot{}, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	// Порядок записей фиксирован: тот же вход даёт тот же архив.
	for _, e := range []struct {
		name string
		data []byte
	}{{stateName, files[stateName]}, {configName, files[configName]}, {manifestName, mdata}} {
		if _, ok := files[e.name]; !ok && e.name != manifestName {
			continue
		}
		h := &tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), ModTime: now, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			return Snapshot{}, err
		}
		if _, err := tw.Write(e.data); err != nil {
			return Snapshot{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Snapshot{}, err
	}
	if err := zw.Close(); err != nil {
		return Snapshot{}, err
	}
	if err := fsys.WriteFile(path, buf.Bytes(), 0o600, platform.Root()); err != nil {
		return Snapshot{}, fmt.Errorf("снимок: запись %s: %w", id, err)
	}
	return Snapshot{ID: id, Created: now}, nil
}

// Read читает снимок и проверяет его целиком: закрытый список имён без путей, предел размера
// записи, манифест, суммы. Недоверенное содержимое наружу не отдаётся.
func (m *Manager) Read(ctx context.Context, id string) (Archive, error) {
	if err := ctx.Err(); err != nil {
		return Archive{}, err
	}
	if !idRe.MatchString(id) {
		return Archive{}, fmt.Errorf("%w: идентификатор %q", ErrInput, id)
	}
	raw, err := m.p.FS().ReadFile(Dir + "/" + id + ".tar.gz")
	if err != nil {
		return Archive{}, fmt.Errorf("снимок %s: %w", id, err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return Archive{}, fmt.Errorf("%w: %s: не gzip", ErrCorrupt, id)
	}
	tr := tar.NewReader(zr)
	got := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Archive{}, fmt.Errorf("%w: %s: не tar", ErrCorrupt, id)
		}
		// Имя — одно из трёх, как есть: путь из архива никуда не подставляется.
		switch h.Name {
		case stateName, configName, manifestName:
		default:
			return Archive{}, fmt.Errorf("%w: %s: запись не из списка", ErrCorrupt, id)
		}
		if _, dup := got[h.Name]; dup || h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > maxEntry {
			return Archive{}, fmt.Errorf("%w: %s: запись %s", ErrCorrupt, id, h.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxEntry+1))
		if err != nil || len(data) > maxEntry {
			return Archive{}, fmt.Errorf("%w: %s: чтение записи %s", ErrCorrupt, id, h.Name)
		}
		got[h.Name] = data
	}

	var mf Manifest
	md, ok := got[manifestName]
	if !ok {
		return Archive{}, fmt.Errorf("%w: %s: нет манифеста", ErrCorrupt, id)
	}
	dec := json.NewDecoder(bytes.NewReader(md))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&mf); err != nil || mf.Version != manifestVersion {
		return Archive{}, fmt.Errorf("%w: %s: манифест", ErrCorrupt, id)
	}
	delete(got, manifestName)
	// Файлы манифеста и архива совпадают точно, суммы сверяются за постоянное время.
	if len(mf.Files) != len(got) {
		return Archive{}, fmt.Errorf("%w: %s: состав не по манифесту", ErrCorrupt, id)
	}
	for name, want := range mf.Files {
		data, ok := got[name]
		if !ok || subtle.ConstantTimeCompare([]byte(sum(data)), []byte(want)) != 1 {
			return Archive{}, fmt.Errorf("%w: %s: сумма %s", ErrCorrupt, id, name)
		}
	}
	return Archive{Manifest: mf, State: got[stateName], Config: got[configName]}, nil
}

// Prune удаляет снимки, кроме keep самых новых. Порядок — по идентификатору: он начинается с
// UTC-времени. Файлы каталога, не похожие на снимок, не трогаются. Вызывать только без
// незавершённой транзакции: её снимок нужен откату. Ручных снимков пока нет; с ними (фаза 5)
// Prune должен отбирать снимки по виду, иначе удалит и ручные.
func (m *Manager) Prune(ctx context.Context, keep int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keep < 1 {
		return fmt.Errorf("%w: keep %d", ErrInput, keep)
	}
	names, err := m.p.FS().ReadDir(Dir)
	if err != nil {
		return fmt.Errorf("снимки: %w", err)
	}
	var ids []string
	for _, n := range names {
		if id, ok := strings.CutSuffix(n, ".tar.gz"); ok && idRe.MatchString(id) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for len(ids) > keep {
		if err := m.p.FS().Remove(Dir + "/" + ids[0] + ".tar.gz"); err != nil {
			return fmt.Errorf("снимок %s: %w", ids[0], err)
		}
		ids = ids[1:]
	}
	return nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
