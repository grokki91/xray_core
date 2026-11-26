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
	typ  byte // 0 — обычный файл
}

// craft пишет снимок вручную — так строятся испорченные архивы.
func craft(t *testing.T, f *platform.Fake, id string, entries ...tarEntry) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		typ, size, link := e.typ, int64(len(e.data)), ""
		if typ == 0 {
			typ = tar.TypeReg
		}
		if typ != tar.TypeReg {
			size, link = 0, "target"
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: size, Typeflag: typ, Linkname: link}); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
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
		{"сумма не совпала", []tarEntry{{name: "state.json", data: []byte(`{"a":2}`)}, {name: "manifest.json", data: good}}},
		{"файла из манифеста нет", []tarEntry{{name: "manifest.json", data: good}}},
		{"файл не из манифеста", []tarEntry{{name: "state.json", data: st}, {name: "config.json", data: []byte("{}")}, {name: "manifest.json", data: good}}},
		{"нет манифеста", []tarEntry{{name: "state.json", data: st}}},
		{"выход пути", []tarEntry{{name: "../state.json", data: st}, {name: "manifest.json", data: good}}},
		{"абсолютный путь", []tarEntry{{name: "/etc/xm/state.json", data: st}, {name: "manifest.json", data: good}}},
		{"чужое имя", []tarEntry{{name: "evil", data: st}, {name: "manifest.json", data: good}}},
		{"лишняя запись с выходом пути", []tarEntry{{name: "state.json", data: st}, {name: "../evil", data: st}, {name: "manifest.json", data: good}}},
		{"лишняя запись с абсолютным путём", []tarEntry{{name: "state.json", data: st}, {name: "/etc/evil", data: st}, {name: "manifest.json", data: good}}},
		{"лишняя запись с чужим именем", []tarEntry{{name: "state.json", data: st}, {name: "evil", data: st}, {name: "manifest.json", data: good}}},
		{"state.json — симлинк", []tarEntry{{name: "state.json", typ: tar.TypeSymlink}, {name: "manifest.json", data: manifestOf(t, map[string][]byte{"state.json": nil})}}},
		{"state.json — жёсткая ссылка", []tarEntry{{name: "state.json", typ: tar.TypeLink}, {name: "manifest.json", data: manifestOf(t, map[string][]byte{"state.json": nil})}}},
		{"state.json — каталог", []tarEntry{{name: "state.json", typ: tar.TypeDir}, {name: "manifest.json", data: manifestOf(t, map[string][]byte{"state.json": nil})}}},
		{"манифест с неизвестным полем", []tarEntry{{name: "state.json", data: st}, {name: "manifest.json", data: []byte(`{"version":1,"reason":"auto","xm":"0.1.0","xray":"","state_schema":0,"files":{"state.json":"` + sum(st) + `"},"extra":1}`)}}},
		{"версия манифеста не 1", []tarEntry{{name: "manifest.json", data: []byte(`{"version":2,"reason":"auto","xm":"0.1.0","xray":"","state_schema":0,"files":{}}`)}}},
		{"манифест перечисляет себя", []tarEntry{{name: "manifest.json", data: []byte(`{"version":1,"reason":"auto","xm":"0.1.0","xray":"","state_schema":0,"files":{"manifest.json":"00"}}`)}}},
		{"повтор записи", []tarEntry{{name: "state.json", data: st}, {name: "state.json", data: st}, {name: "manifest.json", data: good}}},
		{"запись больше предела", []tarEntry{{name: "state.json", data: big}, {name: "manifest.json", data: good}}},
		{"манифест не JSON", []tarEntry{{name: "state.json", data: st}, {name: "manifest.json", data: []byte("не json")}}},
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
		craft(t, f, goodID, tarEntry{name: "state.json", data: st}, tarEntry{name: "manifest.json", data: good})
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
	craft(t, f, goodID, tarEntry{name: "state.json", data: st}, tarEntry{name: "manifest.json", data: manifestOf(t, map[string][]byte{"state.json": []byte("другое")})})
	_, err := m.Read(ctx(t), goodID)
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if strings.Contains(err.Error(), "canary") {
		t.Fatalf("ошибка содержит данные снимка: %v", err)
	}
}

func TestCreateCorruptStateIsSnapshotted(t *testing.T) {
	f, m := env(t)
	bad := []byte("не json " + strings.Repeat("Q", 8) + "-canary")
	put(t, f, statePath, bad)
	s, err := m.Create(ctx(t), "auto", Meta{XM: "0.1.0"})
	if err != nil {
		t.Fatalf("повреждённое состояние должно сниматься: %v", err)
	}
	a, err := m.Read(ctx(t), s.ID)
	if err != nil || !bytes.Equal(a.State, bad) || a.Manifest.StateSchema != 0 || a.Manifest.Xray != "" {
		t.Fatalf("%v %+v", err, a.Manifest)
	}
}

func TestEmptyFileDiffersFromAbsent(t *testing.T) {
	f, m := env(t)
	put(t, f, statePath, []byte{})
	s, err := m.Create(ctx(t), "auto", meta)
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Read(ctx(t), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.State == nil || len(a.State) != 0 || a.Config != nil {
		t.Fatalf("state=%v config=%v", a.State, a.Config)
	}
}

func TestCancelledContext(t *testing.T) {
	_, m := env(t)
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Create(c, "auto", meta); !errors.Is(err, context.Canceled) {
		t.Errorf("Create: %v", err)
	}
	if _, err := m.Read(c, goodID); !errors.Is(err, context.Canceled) {
		t.Errorf("Read: %v", err)
	}
}

// Prune оставляет keep самых новых снимков; чужие файлы каталога не трогает.
func TestPruneKeepsNewest(t *testing.T) {
	f, m := env(t)
	var ids []string
	for i := range 12 {
		f.SetNow(now.Add(time.Duration(i) * time.Minute))
		s, err := m.Create(ctx(t), "install", meta)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s.ID)
	}
	put(t, f, Dir+"/notes.txt", []byte("x"))
	if err := m.Prune(ctx(t), Auto, 10); err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		_, err := m.Read(ctx(t), id)
		if keep := i >= 2; keep != (err == nil) {
			t.Errorf("снимок %s: оставлен=%v, ошибка %v", id, keep, err)
		}
	}
	if _, err := f.FS().ReadFile(Dir + "/notes.txt"); err != nil {
		t.Errorf("чужой файл удалён: %v", err)
	}
	if err := m.Prune(ctx(t), Auto, 0); !errors.Is(err, ErrInput) {
		t.Errorf("keep=0: %v, нужен ErrInput", err)
	}
}

// Хранение по виду: удаление старых автоснимков не трогает ручные, и наоборот.
func TestPruneByKind(t *testing.T) {
	f, m := env(t)
	var manual []string
	for i := range 4 {
		f.SetNow(now.Add(time.Duration(i) * time.Minute))
		s, err := m.Create(ctx(t), ManualReason, meta)
		if err != nil {
			t.Fatal(err)
		}
		manual = append(manual, s.ID)
		if _, err := m.Create(ctx(t), "install", meta); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Prune(ctx(t), Auto, 1); err != nil {
		t.Fatal(err)
	}
	list, err := m.List(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	autos := 0
	for _, e := range list {
		if e.Kind == Manual {
			got = append(got, e.ID)
		} else {
			autos++
		}
	}
	if autos != 1 || strings.Join(got, ",") != strings.Join(manual, ",") {
		t.Fatalf("после Prune(Auto, 1): авто %d, ручные %v", autos, got)
	}
	if err := m.Prune(ctx(t), Manual, 2); err != nil {
		t.Fatal(err)
	}
	if list, _ = m.List(ctx(t)); len(list) != 3 || list[0].ID != manual[2] {
		t.Fatalf("после Prune(Manual, 2): %+v", list)
	}
}

// List показывает повреждённый снимок с причиной, а целый — с манифестом.
func TestListMarksCorrupt(t *testing.T) {
	f, m := env(t)
	s, err := m.Create(ctx(t), ManualReason, meta)
	if err != nil {
		t.Fatal(err)
	}
	put(t, f, Dir+"/20260102T030406Z-install.tar.gz", []byte("не архив"))
	list, err := m.List(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != s.ID || list[0].Corrupt != nil || list[0].Manifest.XM != meta.XM || list[0].Kind != Manual {
		t.Fatalf("целый снимок: %+v", list)
	}
	if !errors.Is(list[1].Corrupt, ErrCorrupt) || list[1].Kind != Auto || !list[1].Created.Equal(now.Add(time.Second)) {
		t.Fatalf("повреждённый снимок: %+v", list[1])
	}
}
