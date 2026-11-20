package core

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

const v1, v2 Version = "26.10.31", "26.11.9"

type entry struct {
	name string
	data []byte
	mode fs.FileMode
}

func zipOf(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		mode := e.mode
		if mode == 0 {
			mode = 0o755
		}
		h.SetMode(mode)
		fw, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// elfBin — настоящий ELF64 x86-64: исполняемый файл самого теста (только на amd64).
func elfBin(t *testing.T) []byte {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("образец ELF x86-64 — исполняемый файл теста; нужен хост amd64")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// release — архив как у upstream: бинарник и сопутствующие файлы.
func release(t *testing.T, bin []byte) []byte {
	return zipOf(t, entry{name: "LICENSE", data: []byte("license")}, entry{name: "xray", data: bin},
		entry{name: "geoip.dat", data: []byte("geo")})
}

// env — поддельная машина с /usr/local/lib; xray отвечает своей версией, если reply не задан.
func env(t *testing.T) (*platform.Fake, *Manager, *func(platform.Command) (platform.Result, error)) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(root+"/usr/local/lib", 0o755); err != nil {
		t.Fatal(err)
	}
	f := platform.NewFake(root, time.Time{})
	reply := func(c platform.Command) (platform.Result, error) {
		if c.Args[0] == "version" {
			return platform.Result{Stdout: []byte("Xray " + c.Version + " (Xray, Penetrates Everything.) abc123 (go1.27.4 linux/amd64)\nA unified platform\n")}, nil
		}
		return platform.Result{Stdout: []byte("Configuration OK.\n")}, nil
	}
	f.Handle("xray", func(c platform.Command) (platform.Result, error) { return reply(c) })
	return f, New(f), &reply
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestStageActivate(t *testing.T) {
	f, m, _ := env(t)
	bin := elfBin(t)
	if cur, err := m.Current(ctx(t)); err != nil || cur != "" {
		t.Fatalf("до установки: %q, %v", cur, err)
	}
	for _, v := range []Version{v1, v2} {
		if err := m.Stage(ctx(t), v, release(t, bin)); err != nil {
			t.Fatal(err)
		}
		p := f.Path(platform.CoreDir + "/" + string(v) + "/xray")
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, bin) {
			t.Fatalf("бинарник %s не записан: %v", v, err)
		}
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o755 {
			t.Errorf("права %v", fi.Mode().Perm())
		}
		if o, _ := f.Owner(platform.CoreDir + "/" + string(v) + "/xray"); o != platform.Root() {
			t.Errorf("владелец %+v", o)
		}
		if _, err := os.Stat(f.Path(platform.CoreDir + "/" + string(v) + "/geoip.dat")); !errors.Is(err, fs.ErrNotExist) {
			t.Error("распакован не только xray")
		}
	}
	if cur, _ := m.Current(ctx(t)); cur != "" {
		t.Errorf("Stage переключил версию: %q", cur)
	}
	for _, v := range []Version{v1, v2, v1} {
		if err := m.Activate(ctx(t), v); err != nil {
			t.Fatal(err)
		}
		if cur, err := m.Current(ctx(t)); err != nil || cur != v {
			t.Fatalf("активная %q, %v; нужна %s", cur, err, v)
		}
	}
	var execs []platform.Call
	for _, c := range f.Calls() {
		if c.Op == "exec" {
			execs = append(execs, c)
		}
	}
	if len(execs) == 0 || execs[0].Version != string(v1) || execs[0].Args[0] != "version" {
		t.Errorf("вызовы xray: %+v", execs)
	}
}

// Испорченный или вредный архив отвергается до записи на диск.
func TestStageRejectsArchive(t *testing.T) {
	bin := elfBin(t)
	arm := bytes.Clone(bin)
	arm[18], arm[19] = 183, 0 // e_machine = EM_AARCH64
	big := make([]byte, maxBinary+1)
	many := []entry{{name: "xray", data: bin}}
	for i := 0; i < maxEntries; i++ {
		many = append(many, entry{name: "f" + strings.Repeat("x", i), data: nil})
	}
	cases := []struct {
		name string
		zip  []byte
		want error
	}{
		{"не zip", []byte("PK не архив"), ErrArchive},
		{"выход вверх", zipOf(t, entry{name: "../evil", data: bin}, entry{name: "xray", data: bin}), ErrArchive},
		{"выход через подкаталог", zipOf(t, entry{name: "a/../../evil", data: bin}, entry{name: "xray", data: bin}), ErrArchive},
		{"абсолютный путь", zipOf(t, entry{name: "/etc/cron.d/x", data: bin}, entry{name: "xray", data: bin}), ErrArchive},
		{"обратная косая", zipOf(t, entry{name: `..\evil`, data: bin}, entry{name: "xray", data: bin}), ErrArchive},
		{"нет xray", zipOf(t, entry{name: "LICENSE", data: bin}), ErrArchive},
		{"xray в подкаталоге", zipOf(t, entry{name: "bin/xray", data: bin}), ErrArchive},
		{"xray дважды", zipOf(t, entry{name: "xray", data: bin}, entry{name: "xray", data: bin}), ErrArchive},
		{"xray — ссылка", zipOf(t, entry{name: "xray", data: []byte("/bin/sh"), mode: fs.ModeSymlink | 0o777}), ErrArchive},
		{"файлов сверх предела", zipOf(t, many...), ErrArchive},
		{"xray сверх предела", zipOf(t, entry{name: "xray", data: big}), ErrArchive},
		{"не ELF", release(t, []byte("#!/bin/sh\nid\n")), ErrBinary},
		{"чужая архитектура", release(t, arm), ErrBinary},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, m, _ := env(t)
			if err := m.Stage(ctx(t), v2, c.zip); !errors.Is(err, c.want) {
				t.Fatalf("ошибка %v, нужна %v", err, c.want)
			}
			if _, err := os.Stat(f.Path("/usr/local/lib/xm")); !errors.Is(err, fs.ErrNotExist) {
				t.Error("отвергнутый архив оставил файлы")
			}
			for _, call := range f.Calls() {
				if call.Op == "exec" {
					t.Errorf("отвергнутый бинарник запущен: %+v", call)
				}
			}
		})
	}
}

// Бинарник, который не называет ожидаемую версию, не становится активным.
func TestStageRejectsWrongVersion(t *testing.T) {
	replies := map[string]platform.Result{
		"другая версия": {Stdout: []byte("Xray 26.9.9 (Xray, Penetrates Everything.)\n")},
		"не Xray":       {Stdout: []byte("V2Ray 26.11.9\n")},
		"пусто":         {},
		"код 1":         {ExitCode: 1, Stdout: []byte("Xray 26.11.9\n")},
	}
	for name, res := range replies {
		t.Run(name, func(t *testing.T) {
			f, m, reply := env(t)
			*reply = func(platform.Command) (platform.Result, error) { return res, nil }
			if err := m.Stage(ctx(t), v2, release(t, elfBin(t))); !errors.Is(err, ErrBinary) {
				t.Errorf("Stage: %v, нужен ErrBinary", err)
			}
			// Бинарник удалён: активировать нечего.
			if err := m.Activate(ctx(t), v2); !errors.Is(err, platform.ErrNotFound) {
				t.Errorf("Activate: %v, нужен ErrNotFound", err)
			}
			if cur, _ := m.Current(ctx(t)); cur != "" {
				t.Errorf("активна %q", cur)
			}
			if _, err := os.Stat(f.Path(platform.CoreDir + "/" + string(v2) + "/xray")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("непроверенный бинарник остался: %v", err)
			}
		})
	}
}

// Выложенная и активная версия не перезаписывается повторным Stage — даже исправным архивом.
func TestStageKeepsStaged(t *testing.T) {
	f, m, reply := env(t)
	bin := elfBin(t)
	if err := m.Stage(ctx(t), v1, release(t, bin)); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(ctx(t), v1); err != nil {
		t.Fatal(err)
	}
	other := append(bytes.Clone(bin), "другая сборка"...)
	*reply = func(platform.Command) (platform.Result, error) {
		return platform.Result{Stdout: []byte("Xray 26.9.9\n")}, nil
	}
	if err := m.Stage(ctx(t), v1, release(t, other)); !errors.Is(err, ErrStaged) {
		t.Errorf("Stage с другим содержимым: %v, нужен ErrStaged", err)
	}
	// Тот же проверенный архив — повтор установки после отката: не ошибка, запись не нужна.
	if err := m.Stage(ctx(t), v1, release(t, bin)); err != nil {
		t.Errorf("повторный Stage того же архива: %v", err)
	}
	if got, _ := os.ReadFile(f.Path(platform.CoreDir + "/" + string(v1) + "/xray")); !bytes.Equal(got, bin) {
		t.Error("бинарник активной версии подменён")
	}
	if cur, _ := m.Current(ctx(t)); cur != v1 {
		t.Errorf("активна %q", cur)
	}
}

func TestActivateRequiresStaged(t *testing.T) {
	f, m, _ := env(t)
	if err := m.Stage(ctx(t), v1, release(t, elfBin(t))); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(ctx(t), v1); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(ctx(t), v2); err == nil {
		t.Error("невыложенная версия активирована")
	}
	for _, bad := range []Version{"", "../../bin", "26.11"} {
		if err := m.Activate(ctx(t), bad); err == nil {
			t.Errorf("версия %q принята", bad)
		}
		if err := m.Stage(ctx(t), bad, release(t, elfBin(t))); err == nil {
			t.Errorf("Stage версии %q принят", bad)
		}
	}
	if cur, _ := m.Current(ctx(t)); cur != v1 {
		t.Errorf("активна %q, нужна %s", cur, v1)
	}
	// Испорченная ссылка: ошибка, а не «не установлено».
	if err := f.FS().Symlink(platform.CoreDir+"/current", "evil"); err != nil {
		t.Fatal(err)
	}
	if cur, err := m.Current(ctx(t)); err == nil {
		t.Errorf("ссылка на %q принята как %q", "evil", cur)
	}
}

func TestValidate(t *testing.T) {
	_, m, reply := env(t)
	if err := m.Stage(ctx(t), v2, release(t, elfBin(t))); err != nil {
		t.Fatal(err)
	}
	const cfg = "/usr/local/etc/xray/config.json"
	var got platform.Command
	const canary = "canary-private-key-fragment"
	codes := map[int]error{0: nil, 23: ErrConfig, 2: errors.New("любая")}
	for code, want := range codes {
		*reply = func(c platform.Command) (platform.Result, error) {
			got = c
			return platform.Result{ExitCode: code, Stdout: []byte("Failed to start: " + canary)}, nil
		}
		err := m.Validate(ctx(t), v2, cfg)
		switch {
		case want == nil && err != nil, want != nil && err == nil:
			t.Errorf("код %d: %v", code, err)
		case want == ErrConfig && !errors.Is(err, ErrConfig):
			t.Errorf("код 23: %v, нужен ErrConfig", err)
		case err != nil && strings.Contains(err.Error(), canary):
			t.Errorf("вывод Xray попал в ошибку: %v", err)
		}
	}
	if got.Version != string(v2) || strings.Join(got.Args, " ") != "run -test -c "+cfg {
		t.Errorf("запуск %+v", got)
	}
	for _, bad := range []string{"config.json", "/etc/../etc/x.json", "/etc/x/"} {
		if err := m.Validate(ctx(t), v2, bad); err == nil {
			t.Errorf("путь %q принят", bad)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for _, ok := range []string{"26.11.9", "1.8.24"} {
		if _, err := ParseVersion(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "v26.11.9", "26.11", "26.11.9-rc1", "26.11.9\n", "../26.11.9"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("%q принята", bad)
		}
	}
}

// Подкоманды вне закрытого списка не запускаются: x25519 и uuid создают секреты, а это дело security.
func TestSubcommandsClosed(t *testing.T) {
	f, m, _ := env(t)
	if err := m.Stage(ctx(t), v2, release(t, elfBin(t))); err != nil {
		t.Fatal(err)
	}
	before := len(f.Calls())
	for _, sub := range []string{"x25519", "uuid", "api", ""} {
		if _, err := m.run(ctx(t), v2, sub); err == nil {
			t.Errorf("подкоманда %q запущена", sub)
		}
	}
	if len(f.Calls()) != before {
		t.Errorf("были запуски: %+v", f.Calls()[before:])
	}
}

func TestValidateCurrent(t *testing.T) {
	_, m, reply := env(t)
	const cfg = "/usr/local/etc/xray/config.json"
	if err := m.ValidateCurrent(ctx(t), cfg); err == nil {
		t.Fatal("без активной версии проверка прошла")
	}
	if err := m.Stage(ctx(t), v1, release(t, elfBin(t))); err != nil {
		t.Fatal(err)
	}
	if err := m.Stage(ctx(t), v2, release(t, elfBin(t))); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(ctx(t), v2); err != nil {
		t.Fatal(err)
	}
	var got platform.Command
	*reply = func(c platform.Command) (platform.Result, error) {
		got = c
		return platform.Result{ExitCode: 23}, nil
	}
	if err := m.ValidateCurrent(ctx(t), cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("err = %v, нужен ErrConfig", err)
	}
	if got.Version != string(v2) {
		t.Fatalf("проверка не действующей версией: %q", got.Version)
	}
}

// StartClient запускает действующую версию в фоне: `run -c stdin:`, конфигурация — только
// через stdin (в ней секрет), не аргументом (ADR-0032).
func TestStartClient(t *testing.T) {
	f, m, _ := env(t)
	var got platform.Command
	f.HandleStart("xray", func(c platform.Command) error { got = c; return nil })
	cfg := []byte(`{"secret":"x"}`)
	if _, err := m.StartClient(ctx(t), cfg); err == nil {
		t.Fatal("без активной версии клиент запущен")
	}
	if err := m.Stage(ctx(t), v2, release(t, elfBin(t))); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(ctx(t), v2); err != nil {
		t.Fatal(err)
	}
	p, err := m.StartClient(ctx(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if got.Version != string(v2) || strings.Join(got.Args, " ") != "run -c stdin:" || !bytes.Equal(got.Stdin, cfg) {
		t.Fatalf("команда %+v", got)
	}
	for _, a := range got.Args {
		if strings.Contains(a, "secret") {
			t.Fatalf("конфигурация в аргументах: %q", a)
		}
	}
	if _, err := m.StartClient(ctx(t), nil); err == nil {
		t.Error("пустая конфигурация принята")
	}
}
