package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

func runAs(version string, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, Env{Stdout: &out, Stderr: &errOut, Version: version, Clock: fixedClock{}, Redact: func(s string) string { return s }})
	return code, out.String(), errOut.String()
}

func run(args ...string) (code int, stdout, stderr string) { return runAs("1.2.3", args...) }

func TestVersion(t *testing.T) {
	code, stdout, stderr := run("version")
	if code != exitOK || stdout != "xm 1.2.3\n" || stderr != "" {
		t.Fatalf("version: код %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestHelpListsEveryCommand(t *testing.T) {
	code, stdout, stderr := run("help")
	if code != exitOK || stderr != "" {
		t.Fatalf("help: код %d, stderr %q", code, stderr)
	}
	for _, c := range commands() {
		if listed := strings.Contains(stdout, "\n  "+c.name+" "); listed == c.hidden {
			t.Errorf("команда %q: в справке %v, служебная %v:\n%s", c.name, listed, c.hidden, stdout)
		}
	}
}

// README и руководство владельца называют каждую команду из справки и не называют служебные:
// документ владельца не отстаёт от CLI (критерий MVP 12, docs/roadmap.md §4).
func TestOwnerDocsListEveryCommand(t *testing.T) {
	for _, doc := range []string{"../../README.md", "../../docs/guide/usage.md"} {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range commands() {
			// «xm stop», «xm start|stop|restart», «xm version|help».
			re := regexp.MustCompile(`(?m)xm (?:[a-z-]+\|)*` + regexp.QuoteMeta(c.name) + "(?:[\\s|`\\]]|$)")
			if named := re.Match(b); named == c.hidden {
				t.Errorf("%s: команда %q названа %v, служебная %v", doc, c.name, named, c.hidden)
			}
		}
	}
}

func TestUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string // фрагменты stderr
	}{
		{"без команды", nil, []string{"Использование: xm <команда>"}},
		{"неизвестная команда", []string{"frobnicate"}, []string{"«frobnicate»", "xm help"}},
		{"лишний аргумент", []string{"version", "extra"}, []string{"«extra»", "xm help"}},
		{"неизвестный флаг", []string{"version", "--bogus"}, []string{"неизвестный флаг «-bogus»"}},
		{"аргумент у help", []string{"help", "version"}, []string{"«version»"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := run(tc.args...)
			if code != exitUsage {
				t.Errorf("код %d, нужен %d", code, exitUsage)
			}
			if stdout != "" {
				t.Errorf("stdout должен быть пуст: %q", stdout)
			}
			for _, w := range tc.want {
				if !strings.Contains(stderr, w) {
					t.Errorf("в stderr нет %q: %q", w, stderr)
				}
			}
		})
	}
}

// Справка, запрошенная флагом, — результат команды: stdout и код 0.
func TestCommandHelpFlag(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		code, stdout, stderr := run("version", flag)
		if code != exitOK || stderr != "" || !strings.Contains(stdout, "Использование: xm version") {
			t.Fatalf("version %s: код %d, stdout %q, stderr %q", flag, code, stdout, stderr)
		}
	}
}

// Введённые имена команд и флагов возвращаются в stderr; управляющая последовательность в них
// не должна дойти до терминала.
func TestInputIsEscaped(t *testing.T) {
	for _, args := range [][]string{
		{"\x1b[2Jboom"},
		{"version", "\x1b[2Jboom"},
		{"version", "--\x1b[2Jboom"},
		{"version", "-\x1b[2Jboom=1"},
	} {
		code, _, stderr := run(args...)
		if code != exitUsage || strings.ContainsRune(stderr, 0x1b) || !strings.Contains(stderr, `\x1b[2Jboom`) {
			t.Errorf("%q: код %d, ввод не экранирован: %q", args, code, stderr)
		}
	}
}

// Вывод xm version --json побайтно совпадает с эталоном схемы version.
func TestVersionJSONMatchesGolden(t *testing.T) {
	want, err := os.ReadFile("../contract/testdata/version.json")
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runAs("0.1.0", "version", "--json")
	if code != exitOK || stderr != "" || stdout != string(want) {
		t.Fatalf("version --json: код %d, stderr %q, stdout:\n%s", code, stderr, stdout)
	}
}

// С --json ошибка аргументов — ровно один документ error в stdout и код 2.
func TestUsageErrorJSON(t *testing.T) {
	cases := []struct {
		args []string
		code string
	}{
		{[]string{"frobnicate", "--json"}, codeUnknownCommand},
		{[]string{"version", "--json", "extra"}, codeBadArguments},
		{[]string{"version", "--json", "--bogus"}, codeBadArguments},
		{[]string{"help", "--json"}, codeBadArguments},
		{[]string{"version", "--bogus", "--json"}, codeBadArguments},
		{[]string{"version", "extra", "--json"}, codeBadArguments},
	}
	for _, tc := range cases {
		code, stdout, stderr := run(tc.args...)
		var doc struct {
			Schema struct{ Name string }
			Error  struct{ Code, Message, Hint string }
		}
		dec := json.NewDecoder(strings.NewReader(stdout))
		if err := dec.Decode(&doc); err != nil {
			t.Errorf("%q: stdout не JSON: %v: %q", tc.args, err, stdout)
			continue
		}
		if dec.More() {
			t.Errorf("%q: в stdout больше одного документа: %q", tc.args, stdout)
		}
		if code != exitUsage || doc.Schema.Name != "error" || doc.Error.Code != tc.code || stderr == "" {
			t.Errorf("%q: код %d, документ %+v, stderr %q", tc.args, code, doc, stderr)
		}
	}
}
