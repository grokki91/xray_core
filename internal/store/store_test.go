package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

func fakeStore(t *testing.T) (*Store, *platform.Fake) {
	t.Helper()
	f := platform.NewFake(t.TempDir(), time.Time{})
	if err := f.FS().Mkdir("/etc", 0o755, platform.Root()); err != nil {
		t.Fatal(err)
	}
	if err := f.FS().Mkdir("/etc/xm", 0o700, platform.Root()); err != nil {
		t.Fatal(err)
	}
	if err := f.FS().Mkdir("/run", 0o755, platform.Root()); err != nil {
		t.Fatal(err)
	}
	return New(f.FS()), f
}

func golden(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/state-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func put(t *testing.T, f *platform.Fake, data []byte) {
	t.Helper()
	if err := f.FS().WriteFile(StatePath, data, 0o600, platform.Root()); err != nil {
		t.Fatal(err)
	}
}

// Загрузка и запись без изменений дают побайтно тот же файл, с правами 0600 и владельцем root.
func TestRoundTrip(t *testing.T) {
	s, f := fakeStore(t)
	want := golden(t)
	put(t, f, want)
	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Profiles[0].Name != "phone" || st.Server.Port != 443 || st.Inbounds[0].Reality.ShortIDs[0] != "0123456789abcdef" {
		t.Fatalf("разобрано неверно: %+v", st)
	}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	got, _ := f.FS().ReadFile(StatePath)
	if !bytes.Equal(got, want) {
		t.Fatalf("после Save файл иной:\n%s", got)
	}
	fi, err := os.Stat(f.Path(StatePath))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("права %v, %v; нужны 0600", fi.Mode().Perm(), err)
	}
	if o, ok := f.Owner(StatePath); !ok || o != platform.Root() {
		t.Errorf("владелец %+v, нужен root", o)
	}
}

func TestLoadRejects(t *testing.T) {
	cur := string(golden(t))
	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"нет файла", "", ErrNoState},
		{"не JSON", "{", ErrSchema},
		{"нет schema_version", `{"server":{}}`, ErrSchema},
		{"новее сборки", `{"schema_version":2}`, ErrNewerSchema},
		{"старее без миграции", `{"schema_version":0}`, ErrSchema},
		{"неизвестное поле", strings.Replace(cur, `"server"`, `"bogus":1,"server"`, 1), ErrSchema},
		{"данные после документа", cur + "{}", ErrSchema},
		{"неверный тип", strings.Replace(cur, `"port": 443`, `"port": "443"`, 1), ErrSchema},
		{"только версия", `{"schema_version":1}`, ErrSchema},
		{"null вместо списка", strings.Replace(cur, `"short_ids": [
          "0123456789abcdef"
        ]`, `"short_ids": null`, 1), ErrSchema},
		{"null вместо объекта", strings.Replace(cur, `"params": {
        "path": "/example"
      }`, `"params": null`, 1), ErrSchema},
		{"ключ в другом регистре", strings.Replace(cur, `"private_key"`, `"Private_Key"`, 1), ErrSchema},
		{"повтор ключа", strings.Replace(cur, `"port": 443`, `"port": 443, "port": 443`, 1), ErrSchema},
		{"нет поля", strings.Replace(cur, `"hold": false`, `"hold_x": false`, 1), ErrSchema},
		{"пропущено поле", strings.Replace(cur, `,
    "hold": false`, ``, 1), ErrSchema},
		{"порт вне диапазона", strings.Replace(cur, `"port": 443`, `"port": 0`, 1), ErrSchema},
		{"пустой ключ", strings.Replace(cur, `"private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, `"private_key": ""`, 1), ErrSchema},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, f := fakeStore(t)
			if tc.doc != "" {
				put(t, f, []byte(tc.doc))
			}
			if _, err := s.Load(); !errors.Is(err, tc.want) {
				t.Fatalf("ошибка %v, нужна %v", err, tc.want)
			}
		})
	}
}

func TestSaveRejectsForeignSchema(t *testing.T) {
	s, f := fakeStore(t)
	if err := s.Save(State{SchemaVersion: 0}); !errors.Is(err, ErrSchema) {
		t.Fatalf("Save с чужой версией: %v", err)
	}
	if _, err := f.FS().ReadFile(StatePath); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("файл записан: %v", err)
	}
}

// Механизм миграций: старый файл → Load → Save → новый файл. Схема «версии 2» здесь
// условная: в версии 1 порт лежал в корне документа, в версии 2 — в server.port.
func TestMigrationOldFileToNewFile(t *testing.T) {
	s, f := fakeStore(t)
	s.current = 2
	s.migrations = map[int]migration{1: func(doc map[string]any) (map[string]any, error) {
		server, _ := doc["server"].(map[string]any)
		if server == nil {
			return nil, fmt.Errorf("нет server")
		}
		server["port"] = doc["port"]
		delete(doc, "port")
		return doc, nil
	}}
	want := strings.Replace(string(golden(t)), `"schema_version": 1`, `"schema_version": 2`, 1)
	old := strings.Replace(string(golden(t)), `    "port": 443`+"\n", "", 1)
	old = strings.Replace(old, `      "domain": ""`+"\n    },", `      "domain": ""`+"\n    }", 1)
	old = strings.Replace(old, `"schema_version": 1,`, `"schema_version": 1, "port": 443,`, 1)
	put(t, f, []byte(old))

	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	got, _ := f.FS().ReadFile(StatePath)
	if string(got) != want {
		t.Fatalf("после миграции:\n%s", got)
	}
}

func TestLock(t *testing.T) {
	s, f := fakeStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := s.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err := New(f.FS()).Lock(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("вторая блокировка: %v, нужно ожидание до срока", err)
	}
	unlock()
	unlock2, err := New(f.FS()).Lock(ctx)
	if err != nil {
		t.Fatalf("блокировка после снятия: %v", err)
	}
	unlock2()
	if fi, err := os.Stat(f.Path(runDir)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("каталог блокировки: %v, %v; нужны 0700", fi.Mode().Perm(), err)
	}
}
