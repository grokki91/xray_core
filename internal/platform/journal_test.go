package platform

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncodeJournal(t *testing.T) {
	got := string(encodeJournal(PriInfo, "hello"))
	want := "SYSLOG_IDENTIFIER=xm\nPRIORITY=6\nMESSAGE=hello\n"
	if got != want {
		t.Errorf("однострочное: %q, нужно %q", got, want)
	}
	b := encodeJournal(PriErr, "a\nb")
	wantBin := append([]byte("SYSLOG_IDENTIFIER=xm\nPRIORITY=3\nMESSAGE\n"), 3, 0, 0, 0, 0, 0, 0, 0)
	wantBin = append(wantBin, "a\nb\n"...)
	if !bytes.Equal(b, wantBin) {
		t.Errorf("с переводом строки: %q, нужно %q", b, wantBin)
	}
	long := encodeJournal(PriInfo, strings.Repeat("я", maxJournalMessage))
	if len(long) > maxJournalMessage+64 || !strings.HasSuffix(string(long), "\n") {
		t.Errorf("длинное сообщение не обрезано: %d байт", len(long))
	}
}

func TestRealJournalSendsDatagram(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "journal.sock")
	l, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	j := realJournal{sock}
	if err := j.Write(deadline(t, time.Second), PriWarning, "msg"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_ = l.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(buf[:n]), "SYSLOG_IDENTIFIER=xm\nPRIORITY=4\nMESSAGE=msg\n"; got != want {
		t.Errorf("датаграмма %q, нужно %q", got, want)
	}
}

func TestRealJournalNoSocket(t *testing.T) {
	j := realJournal{filepath.Join(t.TempDir(), "none.sock")}
	if err := j.Write(deadline(t, time.Second), PriInfo, "x"); err == nil {
		t.Error("нет сокета — нужна ошибка, а не молчание")
	}
}

// Обе реализации требуют срок у контекста.
func TestJournalNeedsDeadline(t *testing.T) {
	for name, j := range map[string]Journal{
		"real": realJournal{"/nonexistent"},
		"fake": NewFake(t.TempDir(), time.Time{}).Journal(),
	} {
		if err := j.Write(context.Background(), PriInfo, "x"); !errors.Is(err, ErrDeadline) {
			t.Errorf("%s: %v, нужно ErrDeadline", name, err)
		}
	}
}

func TestFakeJournalRecords(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f := NewFake(t.TempDir(), now)
	if err := f.Journal().Write(deadline(t, time.Second), PriErr, "boom"); err != nil {
		t.Fatal(err)
	}
	got := f.Journaled()
	if len(got) != 1 || got[0].Priority != PriErr || got[0].Message != "boom" || !got[0].At.Equal(now) {
		t.Errorf("записи: %+v", got)
	}
}
