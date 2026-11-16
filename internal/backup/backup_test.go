package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

var now = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// Значения собраны во время теста: в исходниках секретоподобных строк нет.
func canary() (state, config []byte) {
	secret := strings.Repeat("Q", 8) + "-canary-" + strings.Repeat("7", 8)
	return []byte(`{"schema_version":1,"k":"` + secret + `"}`), []byte(`{"log":{},"k":"` + secret + `"}`)
}

func env(t *testing.T) (*platform.Fake, *Manager) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"/etc/xm", "/usr/local/etc/xray", "/var/lib/xm"} {
		if err := os.MkdirAll(root+d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f := platform.NewFake(root, now)
	if err := f.FS().Mkdir(Dir, 0o700, platform.Root()); err != nil {
		t.Fatal(err)
	}
	return f, New(f)
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func put(t *testing.T, f *platform.Fake, path string, data []byte) {
	t.Helper()
	if err := f.FS().WriteFile(path, data, 0o600, platform.Root()); err != nil {
		t.Fatal(err)
	}
}

var meta = Meta{XM: "0.1.0", Xray: "26.11.9"}

func TestCreateReadRoundTrip(t *testing.T) {
	f, m := env(t)
	st, cfg := canary()
	put(t, f, statePath, st)
	put(t, f, configPath, cfg)

	s, err := m.Create(ctx(t), "before-install", meta)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "20260102T030405Z-before-install" {
		t.Fatalf("ID = %q", s.ID)
	}
	// Снимок содержит секреты: права 0600, владелец root (docs/architecture/data-model.md §1).
	info, err := os.Stat(f.Path(Dir + "/" + s.ID + ".tar.gz"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("файл снимка: %v %v", info, err)
	}
	if o, _ := f.Owner(Dir + "/" + s.ID + ".tar.gz"); o != platform.Root() {
		t.Fatalf("владелец %v", o)
	}

	a, err := m.Read(ctx(t), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.State, st) || !bytes.Equal(a.Config, cfg) {
		t.Fatal("содержимое после возврата не совпало с исходным")
	}
	if a.Manifest.XM != "0.1.0" || a.Manifest.Xray != "26.11.9" || a.Manifest.Reason != "before-install" {
		t.Fatalf("манифест: %+v", a.Manifest)
	}
}

// Возврат — это «снимок → порча → восстановление» из docs/testing.md §3.
func TestRestoreAfterCorruption(t *testing.T) {
	f, m := env(t)
	st, cfg := canary()
	put(t, f, statePath, st)
	put(t, f, configPath, cfg)
	s, err := m.Create(ctx(t), "auto", meta)
	if err != nil {
		t.Fatal(err)
	}
	put(t, f, statePath, []byte("испорчено"))
	a, err := m.Read(ctx(t), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.State, st) {
		t.Fatal("снимок не вернул исходное состояние")
	}
}

func TestCreateAbsentFiles(t *testing.T) {
	_, m := env(t)
	s, err := m.Create(ctx(t), "auto", meta)
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Read(ctx(t), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != nil || a.Config != nil {
		t.Fatal("снимок пустой установки должен вернуть отсутствие файлов, а не пустые файлы")
	}
}

func TestCreateBadInput(t *testing.T) {
	f, m := env(t)
	put(t, f, statePath, []byte("{}"))
	for _, reason := range []string{"", "../x", "A", "a b", "a/b", strings.Repeat("a", 33)} {
		if _, err := m.Create(ctx(t), reason, meta); !errors.Is(err, ErrInput) {
			t.Errorf("причина %q: %v", reason, err)
		}
	}
	for _, mt := range []Meta{{XM: "", Xray: "26.11.9"}, {XM: "0.1.0", Xray: "latest"}, {XM: "a b", Xray: ""}} {
		if _, err := m.Create(ctx(t), "auto", mt); !errors.Is(err, ErrInput) {
			t.Errorf("версии %+v: %v", mt, err)
		}
	}
}

func TestCreateNoOverwrite(t *testing.T) {
	f, m := env(t)
	put(t, f, statePath, []byte("{}"))
	if _, err := m.Create(ctx(t), "auto", meta); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(ctx(t), "auto", meta); !errors.Is(err, ErrExists) {
		t.Fatalf("повтор в ту же секунду: %v", err)
	}
}

func TestCreateReadFailurePropagates(t *testing.T) {
	f, m := env(t)
	// Каталог на месте state.json: чтение — не «файла нет», а ошибка; пустым снимком её не прикрыть.
	if err := os.Mkdir(f.Path(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(ctx(t), "auto", meta); err == nil {
		t.Fatal("ошибка чтения state.json проглочена")
	}
}

type tarEntry struct {
	name string
	data []byte
}

// craft пишет снимок вручную — так строятся испорченные архивы.
func craft(t *testing.T, f *platform.Fake, id string, entries ...tarEntry) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	put(t, f, Dir+"/"+id+".tar.gz", buf.Bytes())
}

func manifestOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	m := Manifest{Version: 1, Reason: "auto", XM: "0.1.0", Xray: "26.11.9", Files: map[string]string{}}
	for n, d := range files {
		m.Files[n] = sum(d)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const goodID = "20260102T030405Z-auto"

func TestReadRejectsBadArchives(t *testing.T) {
	st := []byte(`{"a":1}`)
	good := manifestOf(t, map[string][]byte{"state.json": st})
	big := bytes.Repeat([]byte("x"), maxEntry+1)

	cases := []struct {
		name    string
		entries []tarEntry
	}{
		{"сумма не совпала", []tarEntry{{"state.json", []byte(`{"a":2}`)}, {"manifest.json", good}}},
		{"файла из манифеста нет", []tarEntry{{"manifest.json", good}}},
		{"файл не из манифеста", []tarEntry{{"state.json", st}, {"config.json", []byte("{}")}, {"manifest.json", good}}},
		{"нет манифеста", []tarEntry{{"state.json", st}}},
		{"выход пути", []tarEntry{{"../state.json", st}, {"manifest.json", good}}},
		{"абсолютный путь", []tarEntry{{"/etc/xm/state.json", st}, {"manifest.json", good}}},
		{"чужое имя", []tarEntry{{"evil", st}, {"manifest.json", good}}},
		{"лишняя запись с выходом пути", []tarEntry{{"state.json", st}, {"../evil", st}, {"manifest.json", good}}},
		{"лишняя запись с абсолютным путём", []tarEntry{{"state.json", st}, {"/etc/evil", st}, {"manifest.json", good}}},
		{"лишняя запись с чужим именем", []tarEntry{{"state.json", st}, {"evil", st}, {"manifest.json", good}}},
		{"повтор записи", []tarEntry{{"state.json", st}, {"state.json", st}, {"manifest.json", good}}},
		{"запись больше предела", []tarEntry{{"state.json", big}, {"manifest.json", good}}},
		{"манифест не JSON", []tarEntry{{"state.json", st}, {"manifest.json", []byte("не json")}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, m := env(t)
			craft(t, f, goodID, c.entries...)
			if _, err := m.Read(ctx(t), goodID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("ожидалась ErrCorrupt, получено %v", err)
			}
		})
	}

	t.Run("не gzip", func(t *testing.T) {
		f, m := env(t)
		put(t, f, Dir+"/"+goodID+".tar.gz", []byte("не архив"))
		if _, err := m.Read(ctx(t), goodID); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("получено %v", err)
		}
	})
	t.Run("снимка нет", func(t *testing.T) {
		_, m := env(t)
		if _, err := m.Read(ctx(t), goodID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("получено %v", err)
		}
	})
	t.Run("исправный, собранный вручную", func(t *testing.T) {
		f, m := env(t)
		craft(t, f, goodID, tarEntry{"state.json", st}, tarEntry{"manifest.json", good})
		if _, err := m.Read(ctx(t), goodID); err != nil {
			t.Fatal(err)
		}
	})
}

func TestReadRejectsBadID(t *testing.T) {
	_, m := env(t)
	for _, id := range []string{"", "../x", "/etc/passwd", goodID + "/..", "20260102T030405Z-A", "x"} {
		if _, err := m.Read(ctx(t), id); !errors.Is(err, ErrInput) {
			t.Errorf("идентификатор %q: %v", id, err)
		}
	}
}

// Секрет не должен попадать в текст ошибки при порче снимка.
func TestErrorsDoNotLeakContent(t *testing.T) {
	f, m := env(t)
	st, _ := canary()
	craft(t, f, goodID, tarEntry{"state.json", st}, tarEntry{"manifest.json", manifestOf(t, map[string][]byte{"state.json": []byte("другое")})})
	_, err := m.Read(ctx(t), goodID)
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if strings.Contains(err.Error(), "canary") {
		t.Fatalf("ошибка содержит данные снимка: %v", err)
	}
}
