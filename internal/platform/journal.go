package platform

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Priority — приоритет записи по syslog.
type Priority int

// Приоритеты, которые использует журнал xm.
const (
	PriErr     Priority = 3
	PriWarning Priority = 4
	PriInfo    Priority = 6
	PriDebug   Priority = 7
)

// JournalIdentifier — SYSLOG_IDENTIFIER записей xm; задаёт platform (ADR-0022).
const JournalIdentifier = "xm"

// maxJournalMessage — предел сообщения в байтах; длиннее обрезается.
const maxJournalMessage = 4096

// journalSocket — сокет journald.
const journalSocket = "/run/systemd/journal/socket"

// Journal — запись в journald. Контекст обязан нести срок.
type Journal interface {
	Write(ctx context.Context, p Priority, message string) error
}

// encodeJournal строит датаграмму родного протокола journald. Значение с переводом строки
// передаётся двоичной формой: имя, «\n», длина (8 байт, little endian), данные, «\n».
func encodeJournal(p Priority, message string) []byte {
	if len(message) > maxJournalMessage {
		message = strings.ToValidUTF8(message[:maxJournalMessage], "")
	}
	var b []byte
	b = append(b, "SYSLOG_IDENTIFIER="+JournalIdentifier+"\n"...)
	b = append(b, fmt.Sprintf("PRIORITY=%d\n", int(p))...)
	if strings.Contains(message, "\n") {
		b = append(b, "MESSAGE\n"...)
		b = binary.LittleEndian.AppendUint64(b, uint64(len(message)))
		b = append(b, message...)
		return append(b, '\n')
	}
	return append(b, "MESSAGE="+message+"\n"...)
}

type realJournal struct{ socket string }

func (j realJournal) Write(ctx context.Context, p Priority, message string) error {
	dl, ok := ctx.Deadline()
	if !ok {
		return ErrDeadline
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	conn, err := (&net.Dialer{Deadline: dl}).DialContext(ctx, "unixgram", j.socket)
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(dl)
	if _, err := conn.Write(encodeJournal(p, message)); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	return nil
}

// JournalEntry — запись, принятая поддельным журналом.
type JournalEntry struct {
	Priority Priority
	Message  string
	At       time.Time
}

type fakeJournal struct {
	mu      sync.Mutex
	f       *Fake
	entries []JournalEntry
}

func (j *fakeJournal) Write(ctx context.Context, p Priority, message string) error {
	if _, ok := ctx.Deadline(); !ok {
		return ErrDeadline
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	if len(message) > maxJournalMessage {
		message = strings.ToValidUTF8(message[:maxJournalMessage], "")
	}
	at := j.f.Clock().Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, JournalEntry{p, message, at})
	return nil
}

// Journal возвращает поддельный журнал: записи доступны через Journaled.
func (f *Fake) Journal() Journal { return f.journal }

// Journaled возвращает принятые поддельным журналом записи по порядку.
func (f *Fake) Journaled() []JournalEntry {
	f.journal.mu.Lock()
	defer f.journal.mu.Unlock()
	return append([]JournalEntry(nil), f.journal.entries...)
}

// Journal возвращает запись в journald.
func (r *Real) Journal() Journal { return realJournal{journalSocket} }
