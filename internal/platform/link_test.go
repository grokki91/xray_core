package platform

import (
	"errors"
	"os"
	"testing"
	"time"
)

// Обе реализации одинаково переключают ссылку и отвергают цель вне каталога.
func TestSymlinkAgree(t *testing.T) {
	for _, i := range impls(t) {
		t.Run(i.name, func(t *testing.T) {
			fsys := i.p.FS()
			dir := i.base + "/core"
			link := dir + "/current"
			if err := fsys.Mkdir(dir, 0o755, self()); err != nil {
				t.Fatal(err)
			}
			if _, err := fsys.Readlink(link); !errors.Is(err, ErrNotFound) {
				t.Errorf("Readlink отсутствующей: %v, нужен ErrNotFound", err)
			}
			for _, v := range []string{"26.10.31", "26.11.9"} {
				if err := fsys.Symlink(link, v); err != nil {
					t.Fatal(err)
				}
				if got, err := fsys.Readlink(link); err != nil || got != v {
					t.Fatalf("Readlink: %q, %v; нужно %q", got, err, v)
				}
			}
			if ents, _ := os.ReadDir(onDisk(i, dir)); len(ents) != 1 {
				t.Errorf("в каталоге остались временные файлы: %v", ents)
			}
			for _, bad := range []string{"", ".", "..", "../etc", "/etc", "a/b"} {
				if err := fsys.Symlink(link, bad); !errors.Is(err, ErrPath) {
					t.Errorf("цель %q: %v, нужен ErrPath", bad, err)
				}
			}
			if got, _ := fsys.Readlink(link); got != "26.11.9" {
				t.Errorf("отвергнутая цель изменила ссылку: %q", got)
			}
			// Ссылка на пути к ссылке и не-ссылка на месте ссылки.
			if err := os.Symlink(onDisk(i, dir), onDisk(i, i.base+"/via")); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Symlink(i.base+"/via/current", "x"); !errors.Is(err, ErrSymlink) {
				t.Errorf("Symlink через ссылку: %v, нужен ErrSymlink", err)
			}
			if _, err := fsys.Readlink(i.base + "/via/current"); !errors.Is(err, ErrSymlink) {
				t.Errorf("Readlink через ссылку: %v, нужен ErrSymlink", err)
			}
			if err := fsys.WriteFile(dir+"/file", nil, 0o600, self()); err != nil {
				t.Fatal(err)
			}
			if _, err := fsys.Readlink(dir + "/file"); err == nil {
				t.Error("Readlink обычного файла прошёл")
			}
			if err := fsys.Mkdir(dir+"/sub", 0o755, self()); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Symlink(dir+"/sub", "x"); err == nil {
				t.Error("ссылка заменила каталог")
			}
			// Чтение через current — по-прежнему отказ.
			if _, err := fsys.ReadFile(link + "/xray"); !errors.Is(err, ErrSymlink) {
				t.Errorf("ReadFile через current: %v, нужен ErrSymlink", err)
			}
		})
	}
}

// Xray запускается только по версии N.N.N; версия у других программ — отказ.
func TestExecVersioned(t *testing.T) {
	ctx := deadline(t, time.Second)
	for _, i := range impls(t) {
		t.Run(i.name, func(t *testing.T) {
			for _, c := range []Command{
				{Program: "xray"},
				{Program: "xray", Version: "../../bin/sh"},
				{Program: "xray", Version: "26.11"},
				{Program: "xray", Version: "v26.11.9"},
				{Program: "xray", Version: "26.11.9/"},
				{Program: "echo", Version: "26.11.9"},
			} {
				if _, err := i.p.Exec(ctx, c); !errors.Is(err, ErrProgram) {
					t.Errorf("%+v: %v, нужен ErrProgram", c, err)
				}
			}
			// Версии нет на диске: обе реализации отказывают одинаково, до запуска.
			if _, err := i.p.Exec(ctx, Command{Program: "xray", Version: "0.0.1"}); !errors.Is(err, ErrNotFound) {
				t.Errorf("невыложенная версия: %v, нужен ErrNotFound", err)
			}
		})
	}
	if p, err := xrayPath("26.11.9"); err != nil || p != "/usr/local/lib/xm/core/26.11.9/xray" {
		t.Errorf("путь xray: %q, %v", p, err)
	}
}

// Поддельная реализация запускает xray, только если файл версии есть: как настоящая.
func TestFakeExecNeedsBinary(t *testing.T) {
	f := newFake(t.TempDir(), time.Time{}, nil)
	f.Handle("xray", func(c Command) (Result, error) { return Result{Stdout: []byte(c.Version)}, nil })
	c := Command{Program: "xray", Version: "26.11.9", Args: []string{"version"}}
	if _, err := f.Exec(deadline(t, time.Second), c); err == nil {
		t.Fatal("xray без файла запущен")
	}
	dir := CoreDir + "/26.11.9"
	if err := os.MkdirAll(f.Path(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.Path(dir+"/xray"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := f.Exec(deadline(t, time.Second), c)
	if err != nil || string(res.Stdout) != "26.11.9" {
		t.Fatalf("xray: %+v, %v", res, err)
	}
	if calls := f.Calls(); calls[len(calls)-1].Version != "26.11.9" {
		t.Errorf("версия не записана: %+v", calls)
	}
}

// Remove удаляет только обычный файл и не идёт по ссылкам.
func TestRemoveAgree(t *testing.T) {
	for _, i := range impls(t) {
		t.Run(i.name, func(t *testing.T) {
			fsys := i.p.FS()
			dir := i.base + "/d"
			if err := fsys.Mkdir(dir, 0o755, self()); err != nil {
				t.Fatal(err)
			}
			if err := fsys.WriteFile(dir+"/f", []byte("x"), 0o600, self()); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Remove(dir + "/f"); err != nil {
				t.Fatal(err)
			}
			if _, err := fsys.ReadFile(dir + "/f"); !errors.Is(err, ErrNotFound) {
				t.Errorf("файл не удалён: %v", err)
			}
			if err := fsys.Remove(dir + "/f"); !errors.Is(err, ErrNotFound) {
				t.Errorf("удаление отсутствующего: %v, нужен ErrNotFound", err)
			}
			victim := t.TempDir() + "/victim"
			if err := os.WriteFile(victim, []byte("v"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, onDisk(i, dir+"/link")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), onDisk(i, dir+"/linkdir")); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{dir + "/link", dir + "/linkdir/x", dir} {
				if err := fsys.Remove(p); err == nil {
					t.Errorf("удалено %s", p)
				}
			}
			if _, err := os.Stat(victim); err != nil {
				t.Errorf("цель ссылки задета: %v", err)
			}
		})
	}
}

// Бинарник xray через ссылку на каталог версии не запускается.
func TestFakeExecRefusesSymlinkedBinary(t *testing.T) {
	f := newFake(t.TempDir(), time.Time{}, nil)
	f.Handle("xray", func(c Command) (Result, error) { return Result{}, nil })
	elsewhere := t.TempDir()
	if err := os.WriteFile(elsewhere+"/xray", []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.Path(CoreDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, f.Path(CoreDir+"/26.11.9")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Exec(deadline(t, time.Second), Command{Program: "xray", Version: "26.11.9"}); !errors.Is(err, ErrSymlink) {
		t.Errorf("запуск через ссылку: %v, нужен ErrSymlink", err)
	}
}
