package compat

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

// docRow — строка первой таблицы docs/compatibility.md §3.
type docRow struct{ name, core, reality, status string }

// readDocClients разбирает первую таблицу раздела «## 3. Клиенты».
func readDocClients(t *testing.T) []docRow {
	t.Helper()
	f, err := os.Open("../../../docs/compatibility.md")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows []docRow
	inSection, inTable := false, false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "## ") {
			if inSection {
				break
			}
			inSection = line == "## 3. Клиенты"
			continue
		}
		if !inSection {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if !inTable {
			inTable = true
			if len(cells) < 5 || cells[0] != "Клиент" || cells[1] != "Ядро" || cells[2] != "Подключение по REALITY" || cells[4] != "Статус и источник" {
				t.Fatalf("заголовок таблицы клиентов изменился: %q", line)
			}
			continue
		}
		if strings.HasPrefix(cells[0], "---") {
			continue
		}
		rows = append(rows, docRow{name: cells[0], core: cells[1], reality: cells[2], status: strings.ReplaceAll(cells[4], "`", "")})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("таблица клиентов в docs/compatibility.md §3 не найдена")
	}
	return rows
}

var versionRe = regexp.MustCompile(`v\d+\.\d+\.\d+`)

// versions — номера вида vN.N.N в тексте.
func versions(s string) []string { return versionRe.FindAllString(s, -1) }

// verdict — «да» или «нет» в начале ячейки «Подключение по REALITY».
func verdict(t *testing.T, cell string) bool {
	t.Helper()
	s := strings.TrimLeft(cell, "*")
	switch {
	case strings.HasPrefix(s, "да"):
		return true
	case strings.HasPrefix(s, "нет"):
		return false
	}
	t.Fatalf("ячейка REALITY без «да»/«нет»: %q", cell)
	return false
}

func TestTableMatchesCompatibilityDoc(t *testing.T) {
	doc := readDocClients(t)
	data := map[string]ClientSupport{}
	for _, r := range table() {
		if r.Preset != PresetRealityXHTTP {
			continue
		}
		if _, dup := data[r.Name]; dup {
			t.Errorf("клиент %q в данных дважды", r.Name)
		}
		data[r.Name] = r
	}
	seen := map[string]bool{}
	for _, d := range doc {
		seen[d.name] = true
		r, ok := data[d.name]
		if !ok {
			t.Errorf("клиента %q из docs/compatibility.md §3 нет в данных", d.name)
			continue
		}
		if r.Core != d.core {
			t.Errorf("%s: ядро %q в данных, %q в документе", d.name, r.Core, d.core)
		}
		if r.Source != d.status {
			t.Errorf("%s: источник %q в данных, %q в документе", d.name, r.Source, d.status)
		}
		if w := verdict(t, d.reality); r.Works != w {
			t.Errorf("%s: работает=%v в данных, в документе %q", d.name, r.Works, d.reality)
		}
		// Версия ядра в условии есть в колонке REALITY документа: условие не придумано в коде.
		for _, v := range versions(r.Condition) {
			found := false
			for _, o := range doc {
				found = found || strings.Contains(o.reality, v)
			}
			if !found {
				t.Errorf("%s: версии %s из условия нет в docs/compatibility.md §3", d.name, v)
			}
		}
	}
	for name := range data {
		if !seen[name] {
			t.Errorf("клиента %q из данных нет в docs/compatibility.md §3", name)
		}
	}
}

func TestTableRowsComplete(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range table() {
		if r.Client == "" || r.Name == "" || r.Core == "" || r.Preset == "" || r.Checked == "" || r.Source == "" {
			t.Errorf("%q: пустое обязательное поле", r.Client)
		}
		if !r.Works && r.Reason == "" {
			t.Errorf("%q: несовместимость без причины", r.Client)
		}
		key := r.Client + "/" + r.Preset
		if ids[key] {
			t.Errorf("%s: пара клиент × пресет дважды", key)
		}
		ids[key] = true
	}
}

func TestCheck(t *testing.T) {
	for _, c := range []string{"v2rayn", "v2rayng", "hiddify-5"} {
		if err := Check(c, PresetRealityXHTTP); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}

	err := Check("hiddify-4", PresetRealityXHTTP)
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("hiddify-4: %v, нужна ErrIncompatible", err)
	}
	for _, want := range []string{"X25519MLKEM768"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("hiddify-4: в ошибке %q нет %q", err, want)
		}
	}

	err = Check("sing-box", PresetRealityXHTTP)
	if !errors.Is(err, ErrIncompatible) || !strings.Contains(err.Error(), "X25519MLKEM768") {
		t.Errorf("sing-box: %v, нужна ErrIncompatible с причиной", err)
	}

	for _, c := range [][2]string{{"nekobox", PresetRealityXHTTP}, {"v2rayn", "reality-vision"}, {"", ""}} {
		if err := Check(c[0], c[1]); !errors.Is(err, ErrUnknown) {
			t.Errorf("Check(%q, %q) = %v, нужна ErrUnknown", c[0], c[1], err)
		}
	}
}

func TestClients(t *testing.T) {
	got := Clients(PresetRealityXHTTP, "26.11.9")
	if len(got) != 5 {
		t.Fatalf("строк %d, нужно 5", len(got))
	}
	got[0].Reason = "изменено"
	if Clients(PresetRealityXHTTP, "26.11.9")[0].Reason == "изменено" {
		t.Error("Clients отдаёт общие данные, а не копию")
	}
	if len(Clients(PresetRealityXHTTP, "26.9.9")) != 5 {
		t.Error("граница 26.9.9 не включена")
	}
	for _, c := range []struct{ preset, core string }{
		{"reality-vision", "26.11.9"},
		{PresetRealityXHTTP, "26.9.8"}, // таблица верна для сервера начиная с 26.9.9
		{PresetRealityXHTTP, "25.12.31"},
		{PresetRealityXHTTP, "v26.11.9"},
		{PresetRealityXHTTP, ""},
	} {
		if got := Clients(c.preset, c.core); got != nil {
			t.Errorf("Clients(%q, %q) = %d строк, нужно nil", c.preset, c.core, len(got))
		}
	}
}
