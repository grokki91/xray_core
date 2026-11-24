package platform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// files — общая для обеих реализаций работа с файлами. root — префикс, под которым лежат пути
// (пусто у настоящей реализации, временный каталог у поддельной); chown — смена владельца
// открытого файла (настоящая выполняет её, поддельная записывает).
type files struct {
	root  string
	chown func(f *os.File, path string, o Owner) error
	// ownerOf — владелец существующего пути: у Real из inode, у Fake из записанных назначений.
	ownerOf func(path string, fi fs.FileInfo) Owner
	trace   func(op, path string)
}

func (x files) real(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%w: %q", ErrPath, path)
	}
	return x.root + path, nil
}

// noSymlinks проверяет, что ни один существующий элемент пути p не символическая ссылка.
// Элементы под root не проверяются: временный каталог теста — не предмет порта.
func (x files) noSymlinks(p string) error {
	cur := x.root
	for _, part := range strings.Split(strings.TrimPrefix(p, x.root), "/")[1:] {
		cur += "/" + part
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrSymlink, strings.TrimPrefix(cur, x.root))
		}
	}
	return nil
}

func (x files) ReadFile(path string) ([]byte, error) {
	x.trace("read", path)
	p, err := x.real(path)
	if err != nil {
		return nil, err
	}
	if err := x.noSymlinks(p); err != nil {
		return nil, err
	}
	// O_NONBLOCK: открытие FIFO не ждёт писателя; на обычный файл не влияет.
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("чтение %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("чтение %s: не обычный файл", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("чтение %s: %w", path, err)
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("чтение %s: больше %d байт", path, MaxFileSize)
	}
	return data, nil
}

// MaxFileSize — предел ReadFile. Задаёт его архив Xray в кэше (update): 16 754 078 байт у
// v26.11.9, предел — с запасом около четырёх раз. Состояние и конфигурация много меньше.
const MaxFileSize = 64 << 20

func (x files) WriteFile(path string, data []byte, perm fs.FileMode, owner Owner) (err error) {
	x.trace("write", path)
	p, err := x.real(path)
	if err != nil {
		return err
	}
	if err := x.noSymlinks(p); err != nil {
		return err
	}
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, ".xm-tmp-*") // создаётся с 0600: до chmod файл никому не виден
	if err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = x.chown(tmp, path, owner); err != nil {
		return fmt.Errorf("владелец %s: %w", path, err)
	}
	if err = tmp.Chmod(perm.Perm()); err != nil {
		return fmt.Errorf("права %s: %w", path, err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	if err = os.Rename(tmp.Name(), p); err != nil { // rename заменяет ссылку, а не её цель
		return fmt.Errorf("замена %s: %w", path, err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (x files) Mkdir(path string, perm fs.FileMode, owner Owner) error {
	x.trace("mkdir", path)
	p, err := x.real(path)
	if err != nil {
		return err
	}
	if err := x.noSymlinks(p); err != nil {
		return err
	}
	if err := os.Mkdir(p, 0o700); errors.Is(err, fs.ErrExist) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("каталог %s: на месте каталога другой файл", path)
		}
		// Чужие права не исправляются молча: приведение — дело манифеста (security).
		if fi.Mode().Perm() != perm.Perm() {
			return fmt.Errorf("каталог %s: права %v, нужны %v", path, fi.Mode().Perm(), perm.Perm())
		}
		if got := x.ownerOf(path, fi); got != owner {
			return fmt.Errorf("каталог %s: владелец %d:%d, нужен %d:%d", path, got.UID, got.GID, owner.UID, owner.GID)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("каталог %s: %w", path, err)
	}
	d, err := os.OpenFile(p, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := x.chown(d, path, owner); err != nil {
		return fmt.Errorf("владелец %s: %w", path, err)
	}
	if err := d.Chmod(perm.Perm()); err != nil {
		return fmt.Errorf("права %s: %w", path, err)
	}
	return syncDir(filepath.Dir(p))
}

// lockPoll — шаг ожидания занятой блокировки.
const lockPoll = 20 * time.Millisecond

func (x files) Lock(ctx context.Context, path string) (func(), error) {
	x.trace("lock", path)
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrDeadline
	}
	p, err := x.real(path)
	if err != nil {
		return nil, err
	}
	if err := x.noSymlinks(p); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("блокировка %s: %w", path, err)
	}
	// flock принадлежит открытому описанию файла: второе открытие того же файла — даже в этом
	// процессе — ждёт, как другой процесс.
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("блокировка %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("блокировка %s занята: %w", path, ctx.Err())
		case <-time.After(lockPoll):
		}
	}
	return func() { f.Close() }, nil // закрытие снимает flock
}

// checkBinary — бинарник xray по версии: обычный файл, без ссылок на пути (каталог версии,
// подменённый ссылкой, не уводит запуск от root на чужой файл). Общая проверка обеих реализаций.
func (x files) checkBinary(c Command, path string) error {
	if c.Program != xrayProgram {
		return nil
	}
	p := x.root + path
	if err := x.noSymlinks(p); err != nil {
		return err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("%s %s: нет бинарника: %w", c.Program, c.Version, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s %s: бинарник не обычный файл", c.Program, c.Version)
	}
	return nil
}

func (x files) Remove(path string) error {
	x.trace("remove", path)
	p, err := x.real(path)
	if err != nil {
		return err
	}
	if err := x.noSymlinks(p); err != nil {
		return err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("удаление %s: %w", path, err)
	}
	// Сокет Unix — след клиента самопроверки, убитого до того, как он его убрал (ADR-0032).
	if !fi.Mode().IsRegular() && fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("удаление %s: не обычный файл и не сокет", path)
	}
	if err := os.Remove(p); err != nil {
		return fmt.Errorf("удаление %s: %w", path, err)
	}
	return syncDir(filepath.Dir(p))
}

func (x files) RemoveTree(path string) error {
	x.trace("removetree", path)
	p, err := x.real(path)
	if err != nil {
		return err
	}
	if strings.Count(path, "/") < 2 {
		return fmt.Errorf("%w: удаление дерева %q", ErrPath, path)
	}
	if err := x.noSymlinks(p); err != nil {
		return err
	}
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	// os.RemoveAll удаляет ссылки внутри дерева как записи и по ним не переходит.
	if err := os.RemoveAll(p); err != nil {
		return fmt.Errorf("удаление %s: %w", path, err)
	}
	return syncDir(filepath.Dir(p))
}

func (x files) ReadDir(path string) ([]string, error) {
	x.trace("readdir", path)
	p, err := x.real(path)
	if err != nil {
		return nil, err
	}
	if err := x.noSymlinks(p); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(p)
	if err != nil {
		return nil, fmt.Errorf("каталог %s: %w", path, err)
	}
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Name()
	}
	return names, nil
}

// checkTarget — цель ссылки: одно имя в том же каталоге (ADR-0019).
func checkTarget(target string) error {
	if target == "" || target == "." || target == ".." || strings.Contains(target, "/") {
		return fmt.Errorf("%w: цель ссылки %q", ErrPath, target)
	}
	return nil
}

func (x files) Symlink(path, target string) (err error) {
	x.trace("symlink", path)
	if err := checkTarget(target); err != nil {
		return err
	}
	p, err := x.real(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	// Сама ссылка на месте path заменяется — проверяется только путь к ней.
	if err := x.noSymlinks(dir); err != nil {
		return err
	}
	if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
		return fmt.Errorf("ссылка %s: на месте ссылки каталог", path)
	}
	tmp, err := os.CreateTemp(dir, ".xm-tmp-*")
	if err != nil {
		return fmt.Errorf("ссылка %s: %w", path, err)
	}
	name := tmp.Name()
	tmp.Close()
	// Имя занято на мгновение пустым файлом 0600: так оно уникально; ссылка встаёт на его место.
	if err = os.Remove(name); err != nil {
		return fmt.Errorf("ссылка %s: %w", path, err)
	}
	if err = os.Symlink(target, name); err != nil {
		return fmt.Errorf("ссылка %s: %w", path, err)
	}
	if err = os.Rename(name, p); err != nil {
		os.Remove(name)
		return fmt.Errorf("замена %s: %w", path, err)
	}
	return syncDir(dir)
}

func (x files) Readlink(path string) (string, error) {
	x.trace("readlink", path)
	p, err := x.real(path)
	if err != nil {
		return "", err
	}
	if err := x.noSymlinks(filepath.Dir(p)); err != nil {
		return "", err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return "", fmt.Errorf("ссылка %s: %w", path, err)
	}
	if fi.Mode()&fs.ModeSymlink == 0 {
		return "", fmt.Errorf("ссылка %s: не символическая ссылка", path)
	}
	return os.Readlink(p)
}
