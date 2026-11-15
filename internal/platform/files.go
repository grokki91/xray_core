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
	trace func(op, path string)
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

// MaxFileSize — предел ReadFile: состояние и конфигурация много меньше; под него же подпадает
// архив Xray в кэше (update).
const MaxFileSize = 16 << 20

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
