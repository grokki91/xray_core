package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut, "1.2.3")
	return code, out.String(), errOut.String()
}

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
		if !strings.Contains(stdout, "\n  "+c.name+" ") {
			t.Errorf("в справке нет команды %q:\n%s", c.name, stdout)
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
		{"неизвестный флаг", []string{"version", "--bogus"}, []string{"bogus"}},
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
