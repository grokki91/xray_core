package platform

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// impl — реализация и префикс путей порта: у Real пути лежат во временном каталоге, у Fake
// временный каталог — её root, а пути — как на VPS.
type impl struct {
	name string
	p    Platform
	base string
}

// testPrograms — закрытый список для тестов: безопасные программы coreutils.
func testPrograms(t *testing.T) map[string]string {
	t.Helper()
	progs := map[string]string{}
	for _, n := range []string{"echo", "cat", "sleep", "env", "false"} {
		p := "/usr/bin/" + n
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("нет %s: %v", p, err)
		}
		progs[n] = p
	}
	return progs
}

func impls(t *testing.T) []impl {
	progs := testPrograms(t)
	return []impl{
		{"real", newReal(progs, http.DefaultTransport), t.TempDir()},
		{"fake", newFake(t.TempDir(), time.Time{}, progs), ""},
	}
}

// onDisk — где путь порта лежит на диске.
func onDisk(i impl, path string) string {
	if f, ok := i.p.(*Fake); ok {
		return f.Path(path)
	}
	return path
}

func self() Owner { return Owner{UID: os.Getuid(), GID: os.Getgid()} }

func deadline(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// Обе реализации одинаково ведут себя в том, на что опираются менеджеры.
func TestImplementationsAgree(t *testing.T) {
	for _, i := range impls(t) {
		t.Run(i.name, func(t *testing.T) {
			fsys := i.p.FS()
			dir := i.base + "/etc"
			file := dir + "/state.json"

			if err := fsys.WriteFile(file, []byte("x"), 0o600, self()); err == nil {
				t.Error("запись в несуществующий каталог прошла")
			}
			if err := fsys.Mkdir(dir, 0o700, self()); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Mkdir(dir, 0o700, self()); err != nil {
				t.Errorf("повторный Mkdir: %v", err)
			}
			if err := fsys.Mkdir(dir, 0o755, self()); err == nil {
				t.Error("существующий каталог с другими правами принят")
			}
			assertPerm(t, onDisk(i, dir), 0o700|fs.ModeDir)

			for _, data := range []string{"old", "new"} {
				if err := fsys.WriteFile(file, []byte(data), 0o640, self()); err != nil {
					t.Fatal(err)
				}
				got, err := fsys.ReadFile(file)
				if err != nil || string(got) != data {
					t.Fatalf("прочитано %q, %v; нужно %q", got, err, data)
				}
			}
			assertPerm(t, onDisk(i, file), 0o640)
			if ents, _ := os.ReadDir(onDisk(i, dir)); len(ents) != 1 {
				t.Errorf("в каталоге остались временные файлы: %v", ents)
			}
			if _, err := fsys.ReadFile(dir + "/missing"); !errors.Is(err, ErrNotFound) {
				t.Errorf("чтение отсутствующего: %v, нужен ErrNotFound", err)
			}
			// FIFO на месте файла: отказ, а не вечное ожидание писателя.
			if err := syscall.Mkfifo(onDisk(i, dir+"/fifo"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := fsys.ReadFile(dir + "/fifo"); err == nil {
				t.Error("FIFO прочитан как файл")
			}
			if err := fsys.Remove(dir + "/fifo"); err == nil {
				t.Error("Remove удалил FIFO")
			}
			if err := os.Remove(onDisk(i, dir+"/fifo")); err != nil {
				t.Fatal(err)
			}
			// Сокет Unix — след убитого клиента самопроверки: Remove его удаляет (ADR-0032).
			sock := dir + "/s.sock"
			ln, err := net.Listen("unix", onDisk(i, sock))
			if err != nil {
				t.Fatal(err)
			}
			ln.(*net.UnixListener).SetUnlinkOnClose(false)
			ln.Close()
			if err := fsys.Remove(sock); err != nil {
				t.Errorf("Remove сокета: %v", err)
			}
			if _, err := os.Lstat(onDisk(i, sock)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("сокет не удалён: %v", err)
			}
			if err := fsys.Remove(sock); !errors.Is(err, ErrNotFound) {
				t.Errorf("Remove отсутствующего: %v, нужен ErrNotFound", err)
			}

			for _, bad := range []string{"etc/state.json", i.base + "/etc/../etc/state.json", i.base + "/etc/"} {
				if _, err := fsys.ReadFile(bad); !errors.Is(err, ErrPath) {
					t.Errorf("ReadFile(%q): %v, нужен ErrPath", bad, err)
				}
				if err := fsys.WriteFile(bad, nil, 0o600, self()); !errors.Is(err, ErrPath) {
					t.Errorf("WriteFile(%q): %v, нужен ErrPath", bad, err)
				}
			}

			// Ссылка на месте файла и ссылка-каталог на пути: ни чтения, ни записи, цель цела.
			outside := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(outside, []byte("victim"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, onDisk(i, dir+"/link")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Dir(outside), onDisk(i, dir+"/linkdir")); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{dir + "/link", dir + "/linkdir/victim"} {
				if _, err := fsys.ReadFile(p); !errors.Is(err, ErrSymlink) {
					t.Errorf("ReadFile(%s): %v, нужен ErrSymlink", p, err)
				}
				if err := fsys.WriteFile(p, []byte("pwned"), 0o600, self()); !errors.Is(err, ErrSymlink) {
					t.Errorf("WriteFile(%s): %v, нужен ErrSymlink", p, err)
				}
			}
			if _, err := fsys.ReadDir(dir + "/linkdir"); !errors.Is(err, ErrSymlink) {
				t.Errorf("ReadDir через ссылку: %v, нужен ErrSymlink", err)
			}
			if _, err := fsys.ReadDir(dir + "/missing"); !errors.Is(err, ErrNotFound) {
				t.Errorf("ReadDir отсутствующего: %v, нужен ErrNotFound", err)
			}
			if names, err := fsys.ReadDir(dir); err != nil || !slices.Equal(names, []string{"link", "linkdir", "state.json"}) {
				t.Errorf("ReadDir: %v %v", names, err)
			}
			if err := fsys.Mkdir(dir+"/linkdir/sub", 0o700, self()); !errors.Is(err, ErrSymlink) {
				t.Errorf("Mkdir через ссылку: %v, нужен ErrSymlink", err)
			}
			if got, _ := os.ReadFile(outside); string(got) != "victim" {
				t.Errorf("цель ссылки изменена: %q", got)
			}

			lock := dir + "/lock"
			if _, err := fsys.Lock(context.Background(), lock); !errors.Is(err, ErrDeadline) {
				t.Errorf("Lock без срока: %v, нужен ErrDeadline", err)
			}
			unlock, err := fsys.Lock(deadline(t, time.Second), lock)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fsys.Lock(deadline(t, 100*time.Millisecond), lock); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("занятая блокировка: %v, нужен DeadlineExceeded", err)
			}
			unlock()
			unlock2, err := fsys.Lock(deadline(t, time.Second), lock)
			if err != nil {
				t.Fatalf("блокировка после снятия: %v", err)
			}
			unlock2()
			assertPerm(t, onDisk(i, lock), 0o600)

			if _, err := i.p.Exec(deadline(t, time.Second), Command{Program: "sh", Args: []string{"-c", "id"}}); !errors.Is(err, ErrProgram) {
				t.Errorf("программа вне списка: %v, нужен ErrProgram", err)
			}
			if _, err := i.p.Exec(context.Background(), Command{Program: "echo"}); !errors.Is(err, ErrDeadline) {
				t.Errorf("Exec без срока: %v, нужен ErrDeadline", err)
			}
		})
	}
}

func assertPerm(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != want {
		t.Errorf("%s: права %v, нужны %v", path, fi.Mode(), want)
	}
}

func TestRealExec(t *testing.T) {
	r := newReal(testPrograms(t), http.DefaultTransport)
	ctx := deadline(t, 5*time.Second)

	// Метасимволы оболочки — просто аргументы: оболочки нет.
	args := []string{"$(id)", ";", "`whoami`", "a b"}
	res, err := r.Exec(ctx, Command{Program: "echo", Args: args})
	if err != nil || res.ExitCode != 0 || string(res.Stdout) != strings.Join(args, " ")+"\n" {
		t.Errorf("echo: %+v, %v", res, err)
	}

	res, err = r.Exec(ctx, Command{Program: "cat", Stdin: []byte("через stdin")})
	if err != nil || string(res.Stdout) != "через stdin" {
		t.Errorf("cat: %q, %v", res.Stdout, err)
	}

	res, err = r.Exec(ctx, Command{Program: "false"})
	if err != nil || res.ExitCode != 1 {
		t.Errorf("false: %+v, %v; ненулевой код — не ошибка", res, err)
	}

	t.Setenv("XM_TEST_SECRET", "leak")
	res, err = r.Exec(ctx, Command{Program: "env"})
	// Значения окружения в сообщение не попадают: в нём могут быть данные машины CI.
	if got := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n"); err != nil || !slices.Equal(got, childEnv) {
		t.Errorf("процесс получил %d переменных окружения (%v), нужно только %q", len(got), err, childEnv)
	}

	if _, err := r.Exec(ctx, Command{Program: "cat", Stdin: make([]byte, MaxOutput+1)}); err == nil {
		t.Error("вывод сверх предела принят")
	}

	start := time.Now()
	_, err = r.Exec(deadline(t, 200*time.Millisecond), Command{Program: "sleep", Args: []string{"10"}})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Errorf("срок не соблюдён: %v за %v", err, time.Since(start))
	}
}

func TestFakeRecordsCallsAndOwners(t *testing.T) {
	f := newFake(t.TempDir(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), testPrograms(t))
	f.Handle("echo", func(c Command) (Result, error) {
		return Result{Stdout: []byte(strings.Join(c.Args, " "))}, nil
	})
	res, err := f.Exec(deadline(t, time.Second), Command{Program: "echo", Args: []string{"hi"}})
	if err != nil || !bytes.Equal(res.Stdout, []byte("hi")) {
		t.Fatalf("обработчик: %+v, %v", res, err)
	}
	if _, err := f.Exec(deadline(t, time.Second), Command{Program: "cat"}); err == nil {
		t.Error("программа без обработчика ответила")
	}
	if err := f.FS().Mkdir("/etc", 0o700, Root()); err != nil {
		t.Fatal(err)
	}
	if err := f.FS().WriteFile("/etc/state.json", nil, 0o600, Owner{UID: 0, GID: 7}); err != nil {
		t.Fatal(err)
	}
	if o, ok := f.Owner("/etc/state.json"); !ok || o != (Owner{UID: 0, GID: 7}) {
		t.Errorf("владелец не записан: %+v %v", o, ok)
	}
	want := []Call{{Op: "exec", Path: "echo", Args: []string{"hi"}}, {Op: "exec", Path: "cat"}, {Op: "mkdir", Path: "/etc"}, {Op: "write", Path: "/etc/state.json"}}
	got := f.Calls()
	if len(got) != len(want) {
		t.Fatalf("вызовы %+v, нужны %+v", got, want)
	}
	for k := range want {
		if got[k].Op != want[k].Op || got[k].Path != want[k].Path || !slices.Equal(got[k].Args, want[k].Args) {
			t.Errorf("вызов %d: %+v, нужен %+v", k, got[k], want[k])
		}
	}
	if now := f.Clock().Now(); !now.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("часы: %v", now)
	}
}

// RunUnderRoot запускает настоящий файл программы из корня подделки (стенд L3): тот же путь
// запуска, что у Real, абсолютные пути в аргументах — под корнем.
func TestFakeRunUnderRoot(t *testing.T) {
	root := t.TempDir()
	f := NewFake(root, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	echo, err := os.ReadFile("/usr/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	dir := root + CoreDir + "/1.2.3"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/xray", echo, 0o755); err != nil {
		t.Fatal(err)
	}
	f.RunUnderRoot("xray")
	c := Command{Program: "xray", Version: "1.2.3", Args: []string{"run", "-c", "/etc/xm/x.json", "a/b"}}
	res, err := f.Exec(deadline(t, 5*time.Second), c)
	if want := "run -c " + root + "/etc/xm/x.json a/b\n"; err != nil || res.ExitCode != 0 || string(res.Stdout) != want {
		t.Errorf("запуск: %q, %v; нужно %q", res.Stdout, err, want)
	}
	calls := f.Calls()
	if last := calls[len(calls)-1]; last.Op != "exec" || !slices.Equal(last.Args, c.Args) {
		t.Errorf("записан вызов %+v, нужны аргументы как на VPS %q", last, c.Args)
	}
	if _, err := f.Exec(deadline(t, 5*time.Second), Command{Program: "xray", Version: "1.2.3", Args: []string{"/../../x"}}); !errors.Is(err, ErrPath) {
		t.Errorf("путь из корня: %v, нужно ErrPath", err)
	}
	if _, err := f.Exec(deadline(t, 5*time.Second), Command{Program: "xray", Version: "1.2.4"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("версия без бинарника: %v, нужно ErrNotFound", err)
	}
}
