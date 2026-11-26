package logging

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/grokki91/xray_core/internal/platform"
)

// ErrSince — значение --since не по правилу.
var ErrSince = errors.New("время --since: нужно N m|h|d (1–9999) или дата ГГГГ-ММ-ДД")

// defaultLines — сколько последних записей показать без --since.
const defaultLines = "200"

// maxLine — предел одной записи journalctl -o json; длиннее — ошибка, а не обрезка молча.
const maxLine = 1 << 20

var sinceAgo = regexp.MustCompile(`^([1-9][0-9]{0,3})([mhd])$`)

// Query — что читать из журнала: с какого момента и следить ли за новыми записями.
type Query struct {
	Since  string // пусто — последние defaultLines записей
	Follow bool
}

// since переводит --since в абсолютное время UTC для journalctl: аргумент процесса строится
// только из проверенных чисел, ввод владельца в него не попадает.
func since(s string, now time.Time) (string, error) {
	const layout = "2006-01-02 15:04:05 UTC"
	if m := sinceAgo.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		unit := map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
		return now.UTC().Add(-time.Duration(n) * unit).Format(layout), nil
	}
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		return "", ErrSince
	}
	return d.Format(layout), nil
}

// XrayLog читает journald: записи юнита Xray и идентификатора xm, по одной на строку
// «время UTC источник: сообщение». Строки журнала — недоверенные: управляющие символы
// заменяются, каждая строка проходит редактор. Close останавливает journalctl.
func (m *Manager) XrayLog(ctx context.Context, q Query) (io.ReadCloser, error) {
	args := []string{"--no-pager", "--quiet", "--output=json",
		"--output-fields=__REALTIME_TIMESTAMP,SYSLOG_IDENTIFIER,MESSAGE"}
	if q.Since == "" {
		args = append(args, "--lines="+defaultLines)
	} else {
		s, err := since(q.Since, m.now())
		if err != nil {
			return nil, err
		}
		args = append(args, "--since="+s)
	}
	if q.Follow {
		args = append(args, "--follow")
	}
	args = append(args, "_SYSTEMD_UNIT="+platform.ServiceUnit, "+", "SYSLOG_IDENTIFIER="+platform.JournalIdentifier)
	src, err := m.p.Stream(ctx, platform.Command{Program: platform.Journalctl, Args: args})
	if err != nil {
		return nil, fmt.Errorf("журнал: %w", err)
	}
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(m.copyLines(pw, src))
	}()
	return &lines{pr: pr, src: src}, nil
}

// lines — отредактированный поток; Close останавливает и источник, и разбор.
type lines struct {
	pr  *io.PipeReader
	src io.Closer
}

func (l *lines) Read(p []byte) (int, error) { return l.pr.Read(p) }

func (l *lines) Close() error {
	l.src.Close()
	return l.pr.Close()
}

func (m *Manager) copyLines(w io.Writer, src io.Reader) error {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		line, err := entry(sc.Bytes())
		if err != nil { // чужая запись не обрывает просмотр, в том числе -f
			line = "[нечитаемая запись]"
		}
		if _, err := io.WriteString(w, m.r.Text(line)+"\n"); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("журнал: %w", err)
	}
	return nil
}

// entry — одна запись journalctl -o json в строку. MESSAGE не строкой (двоичные данные
// journald отдаёт массивом байтов) не показывается.
func entry(b []byte) (string, error) {
	var e struct {
		At      string          `json:"__REALTIME_TIMESTAMP"`
		Source  json.RawMessage `json:"SYSLOG_IDENTIFIER"`
		Message json.RawMessage `json:"MESSAGE"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return "", fmt.Errorf("журнал: запись не JSON: %w", err)
	}
	us, err := strconv.ParseInt(e.At, 10, 64)
	if err != nil {
		return "", fmt.Errorf("журнал: время записи %w", err)
	}
	source, msg := text(e.Source), "[двоичное сообщение]"
	if s, ok := str(e.Message); ok {
		msg = s
	}
	if source == "" {
		source = "xray"
	}
	return time.UnixMicro(us).UTC().Format(time.RFC3339) + " " + clean(source) + ": " + clean(msg), nil
}

func str(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func text(raw json.RawMessage) string {
	s, _ := str(raw)
	return s
}

// clean заменяет управляющие символы и символы формата (bidi, невидимые): строка журнала не должна управлять терминалом.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, s)
}
