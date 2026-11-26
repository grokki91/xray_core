// Пакет core — бинарник Xray на диске: распаковка проверенного архива, проверка бинарника,
// каталоги версий и ссылка current, проверка конфигурации. Откуда берётся архив — дело update;
// что в конфигурации — дело config.
package core

import (
	"archive/zip"
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/grokki91/xray_core/internal/platform"
)

// Version — версия Xray вида N.N.N, как её называет `xray version`.
type Version string

// ParseVersion проверяет версию по правилу N.N.N (docs/security/policy.md §5); правило одно —
// platform.ValidVersion.
func ParseVersion(s string) (Version, error) {
	if !platform.ValidVersion(s) {
		return "", fmt.Errorf("версия %q не вида N.N.N", s)
	}
	return Version(s), nil
}

const (
	libDir      = "/usr/local/lib/xm"
	currentLink = platform.CoreDir + "/current"
	binary      = "xray"
)

// Пределы распаковки: в архиве релиза пять файлов, бинарник — десятки мегабайт.
const (
	maxEntries = 32
	maxBinary  = 128 << 20
)

var (
	// ErrArchive — архив отвергнут до записи на диск: путь вне каталога, лишний или
	// отсутствующий бинарник, превышение пределов.
	ErrArchive = errors.New("архив релиза отвергнут")
	// ErrBinary — бинарник не ELF под amd64 или не называет ожидаемую версию.
	ErrBinary = errors.New("бинарник Xray не прошёл проверку")
	// ErrStaged — версия уже выложена: Stage её не перезаписывает.
	ErrStaged = errors.New("версия уже выложена")
	// ErrNotStaged — бинарника версии нет на диске.
	ErrNotStaged = errors.New("версия не выложена")
	// ErrConfig — `xray run -test` отверг конфигурацию (код 23).
	ErrConfig = errors.New("xray отверг конфигурацию")
)

// Manager — версии Xray на диске.
type Manager struct {
	p platform.Platform
}

func New(p platform.Platform) *Manager { return &Manager{p: p} }

// Current возвращает активную версию; ссылки нет — пустая версия без ошибки.
func (m *Manager) Current(ctx context.Context) (Version, error) {
	target, err := m.p.FS().Readlink(currentLink)
	if errors.Is(err, platform.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("активная версия: %w", err)
	}
	v, err := ParseVersion(target)
	if err != nil {
		return "", fmt.Errorf("активная версия: ссылка current: %w", err)
	}
	return v, nil
}

// Stage распаковывает только xray в каталог версии v и проверяет его: ELF под amd64,
// `xray version` называет v. Предусловие: суммы архива сверены (update.Fetch) — Stage
// запускает бинарник. Активная версия не меняется; выложенная версия с другим содержимым —
// ErrStaged, с тем же — успех без записи.
func (m *Manager) Stage(ctx context.Context, v Version, archive []byte) error {
	if _, err := ParseVersion(string(v)); err != nil {
		return err
	}
	bin, err := extract(archive)
	if err != nil {
		return err
	}
	if err := checkELF(bin); err != nil {
		return err
	}
	dir := platform.CoreDir + "/" + string(v)
	for _, d := range []string{libDir, platform.CoreDir, dir} {
		if err := m.p.FS().Mkdir(d, 0o755, platform.Root()); err != nil {
			return fmt.Errorf("каталог версии: %w", err)
		}
	}
	file := dir + "/" + binary
	// Выложенная версия не перезаписывается: на неё может указывать current, а замена
	// бинарника — только транзакцией. Тот же проверенный архив повторно — не ошибка (повтор
	// установки после отката); другое содержимое — ErrStaged; ошибка чтения — отказ.
	switch have, err := m.p.FS().ReadFile(file); {
	case err == nil && bytes.Equal(have, bin):
		return nil
	case err == nil:
		return fmt.Errorf("версия %s: %w", v, ErrStaged)
	case !errors.Is(err, platform.ErrNotFound):
		return fmt.Errorf("версия %s: %w", v, err)
	}
	if err := m.p.FS().WriteFile(file, bin, 0o755, platform.Root()); err != nil {
		return fmt.Errorf("бинарник %s: %w", v, err)
	}
	if err := m.checkVersion(ctx, v); err != nil {
		// Не прошедший проверку бинарник на диске не остаётся.
		if rmErr := m.p.FS().Remove(file); rmErr != nil {
			return errors.Join(err, rmErr)
		}
		return err
	}
	return nil
}

// Activate атомарно переключает current на версию v, если её бинарник отвечает этой версией.
func (m *Manager) Activate(ctx context.Context, v Version) error {
	if _, err := ParseVersion(string(v)); err != nil {
		return err
	}
	if err := m.checkVersion(ctx, v); err != nil {
		return err
	}
	if err := m.p.FS().Symlink(currentLink, string(v)); err != nil {
		return fmt.Errorf("переключение на %s: %w", v, err)
	}
	return nil
}

// Validate проверяет конфигурацию бинарником версии v: `xray run -test -c <файл>`. Решение —
// по коду выхода; вывод Xray в ошибку не попадает: в нём бывают фрагменты конфигурации.
func (m *Manager) Validate(ctx context.Context, v Version, configPath string) error {
	if !path.IsAbs(configPath) || path.Clean(configPath) != configPath {
		return fmt.Errorf("конфигурация: путь %q не абсолютный или не очищенный", configPath)
	}
	res, err := m.run(ctx, v, "run", "-test", "-c", configPath)
	if err != nil {
		return err
	}
	switch res.ExitCode {
	case 0:
		return nil
	case 23:
		return fmt.Errorf("xray %s run -test: %w", v, ErrConfig)
	default:
		return fmt.Errorf("xray %s run -test: код %d", v, res.ExitCode)
	}
}

// StartClient запускает в фоне клиент самопроверки (ADR-0032): `xray run -c stdin:` действующей
// версией. Конфигурация клиента — секрет, поэтому только через stdin. Процесс живёт до конца
// срока ctx или Process.Stop; сокет клиента вызывающий удаляет сам. Версии нет — ошибка.
func (m *Manager) StartClient(ctx context.Context, cfg []byte) (platform.Process, error) {
	if len(cfg) == 0 {
		return nil, errors.New("конфигурация клиента пуста")
	}
	cur, err := m.Current(ctx)
	if err != nil {
		return nil, err
	}
	if cur == "" {
		return nil, errors.New("ядро не установлено")
	}
	p, err := m.p.Start(ctx, platform.Command{Program: binary, Version: string(cur), Args: []string{"run", "-c", "stdin:"}, Stdin: cfg})
	if err != nil {
		return nil, fmt.Errorf("xray %s run: %w", cur, err)
	}
	return p, nil
}

// ValidateCurrent проверяет конфигурацию действующей версией: контроль после изменения
// проверяет то, что запущено, а не то, что собирались запустить. Версии нет — ошибка.
func (m *Manager) ValidateCurrent(ctx context.Context, configPath string) error {
	cur, err := m.Current(ctx)
	if err != nil {
		return err
	}
	if cur == "" {
		return errors.New("ядро не установлено")
	}
	return m.Validate(ctx, cur, configPath)
}

// subcommands — закрытый список подкоманд Xray, которые запускает core.
var subcommands = map[string]bool{"version": true, "run": true}

func (m *Manager) run(ctx context.Context, v Version, sub string, args ...string) (platform.Result, error) {
	if !subcommands[sub] {
		return platform.Result{}, fmt.Errorf("подкоманда xray %q не из закрытого списка", sub)
	}
	res, err := m.p.Exec(ctx, platform.Command{Program: binary, Version: string(v), Args: append([]string{sub}, args...)})
	if errors.Is(err, platform.ErrNotFound) {
		return platform.Result{}, fmt.Errorf("xray %s %s: %w: %w", v, sub, ErrNotStaged, err)
	}
	if err != nil {
		return platform.Result{}, fmt.Errorf("xray %s %s: %w", v, sub, err)
	}
	return res, nil
}

// checkVersion — `xray version`: код 0, первая строка «Xray <версия> …»
// (docs/compatibility.md §2).
func (m *Manager) checkVersion(ctx context.Context, v Version) error {
	res, err := m.run(ctx, v, "version")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("xray %s version: код %d: %w", v, res.ExitCode, ErrBinary)
	}
	first, _, _ := strings.Cut(string(res.Stdout), "\n")
	f := strings.Fields(first)
	if len(f) < 2 || f[0] != "Xray" || f[1] != string(v) {
		return fmt.Errorf("xray %s version: ответ не называет эту версию: %w", v, ErrBinary)
	}
	return nil
}

// extract возвращает содержимое единственного файла xray в корне архива. Любой путь, который
// вышел бы из каталога назначения, отвергает архив целиком.
func extract(archive []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("%w: не zip: %v", ErrArchive, err)
	}
	if len(zr.File) > maxEntries {
		return nil, fmt.Errorf("%w: файлов больше %d", ErrArchive, maxEntries)
	}
	var found *zip.File
	for _, f := range zr.File {
		name := f.Name
		if name == "" || strings.Contains(name, `\`) || path.IsAbs(name) || path.Clean(name) != strings.TrimSuffix(name, "/") ||
			name == ".." || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("%w: путь %q вне каталога", ErrArchive, name)
		}
		if name != binary {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: %s повторяется", ErrArchive, binary)
		}
		if !f.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %s не обычный файл", ErrArchive, binary)
		}
		found = f
	}
	if found == nil {
		return nil, fmt.Errorf("%w: нет %s", ErrArchive, binary)
	}
	rc, err := found.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrArchive, err)
	}
	defer rc.Close()
	// Размер из заголовка не доверяется: читается не больше предела.
	bin, err := io.ReadAll(io.LimitReader(rc, maxBinary+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrArchive, err)
	}
	if len(bin) > maxBinary {
		return nil, fmt.Errorf("%w: %s больше %d байт", ErrArchive, binary, maxBinary)
	}
	return bin, nil
}

// checkELF — исполняемый ELF64 под x86-64 (docs/compatibility.md §1).
func checkELF(bin []byte) error {
	f, err := elf.NewFile(bytes.NewReader(bin))
	if err != nil {
		return fmt.Errorf("%w: не ELF", ErrBinary)
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
		return fmt.Errorf("%w: ELF %v %v %v, нужен исполняемый ELF64 x86-64", ErrBinary, f.Class, f.Machine, f.Type)
	}
	return nil
}

// Prune удаляет каталоги версий, кроме keep: после успешного обновления остаются активная и
// предыдущая (docs/operations/updates.md §4). Ссылка current и чужие имена не трогаются.
func (m *Manager) Prune(keep ...Version) error {
	names, err := m.p.FS().ReadDir(platform.CoreDir)
	if err != nil {
		return fmt.Errorf("версии: %w", err)
	}
	for _, n := range names {
		if !platform.ValidVersion(n) || slices.Contains(keep, Version(n)) {
			continue
		}
		if err := m.p.FS().RemoveTree(platform.CoreDir + "/" + n); err != nil {
			return fmt.Errorf("версия %s: %w", n, err)
		}
	}
	return nil
}
