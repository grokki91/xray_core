package logging

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/redact"
	"github.com/grokki91/xray_core/internal/redact/redacttest"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func read(t *testing.T, m *Manager, q Query) string {
	t.Helper()
	rc, err := m.XrayLog(ctx(t), q)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Записи journald выходят строками «время источник: сообщение»: секреты заменены редактором,
// управляющие символы — «?», двоичное сообщение не показывается.
func TestXrayLogRedactsAndCleans(t *testing.T) {
	c := redacttest.New(t)
	m, f, r := newManager(t, 0)
	r.Register(redact.UUID, c.UUID)
	in := `{"__REALTIME_TIMESTAMP":"1767225600000000","SYSLOG_IDENTIFIER":"xray","MESSAGE":"accepted ` + c.UUID + ` from ` + c.IPv4 + `"}` + "\n" +
		`{"__REALTIME_TIMESTAMP":"1767225601000000","SYSLOG_IDENTIFIER":"xm","MESSAGE":"esc \u001b[31m red\nnext\u202e"}` + "\n" +
		"not json\n" +
		`{"__REALTIME_TIMESTAMP":"1767225602000000","MESSAGE":[1,2,3]}` + "\n"
	f.HandleStream(platform.Journalctl, func(platform.Command) (io.Reader, error) { return strings.NewReader(in), nil })
	out := read(t, m, Query{})
	for _, v := range c.All() {
		if strings.Contains(out, v) {
			t.Errorf("в выводе значение %q:\n%s", v, out)
		}
	}
	want := []string{
		"2026-01-01T00:00:01Z xm: esc ?[31m red?next?",
		"[нечитаемая запись]",
		"2026-01-01T00:00:02Z xray: [двоичное сообщение]",
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "2026-01-01T00:00:00Z xray: accepted ") || !slices.Equal(lines[1:], want) {
		t.Errorf("вывод:\n%s", out)
	}
}

// Аргументы journalctl строятся только из проверенного: юнит Xray или идентификатор xm, без
// --since — последние записи, --since переводится в абсолютное время UTC.
func TestXrayLogArgs(t *testing.T) {
	m, f, _ := newManager(t, 0)
	f.HandleStream(platform.Journalctl, func(platform.Command) (io.Reader, error) { return strings.NewReader(""), nil })
	read(t, m, Query{})
	read(t, m, Query{Since: "2h", Follow: true})
	read(t, m, Query{Since: "2025-12-30"})
	base := []string{"--no-pager", "--quiet", "--output=json", "--output-fields=__REALTIME_TIMESTAMP,SYSLOG_IDENTIFIER,MESSAGE"}
	match := []string{"_SYSTEMD_UNIT=xray.service", "+", "SYSLOG_IDENTIFIER=xm"}
	want := [][]string{
		slices.Concat(base, []string{"--lines=200"}, match),
		slices.Concat(base, []string{"--since=2025-12-31 22:00:00 UTC", "--follow"}, match),
		slices.Concat(base, []string{"--since=2025-12-30 00:00:00 UTC"}, match),
	}
	calls := f.Calls()
	if len(calls) != 3 {
		t.Fatalf("вызовы %+v", calls)
	}
	for i, c := range calls {
		if c.Op != "stream" || c.Path != platform.Journalctl || !slices.Equal(c.Args, want[i]) {
			t.Errorf("вызов %d: %+v", i, c)
		}
	}
}

func TestXrayLogRejectsSince(t *testing.T) {
	m, f, _ := newManager(t, 0)
	for _, s := range []string{"0h", "10000d", "2h ago", "-1h", "--follow", "2025-13-01", "yesterday", "1w"} {
		if _, err := m.XrayLog(ctx(t), Query{Since: s}); !errors.Is(err, ErrSince) {
			t.Errorf("%q: %v, нужно ErrSince", s, err)
		}
	}
	if len(f.Calls()) != 0 {
		t.Errorf("journalctl запущен при неверном вводе: %+v", f.Calls())
	}
}
