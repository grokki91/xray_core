package platform

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Stream отдаёт stdout потоком; ненулевой код — ErrExit в конце чтения; без срока — ErrDeadline;
// программа вне закрытого списка — ErrProgram.
func TestRealStream(t *testing.T) {
	r := newReal(testPrograms(t), http.DefaultTransport)
	if _, err := r.Stream(context.Background(), Command{Program: "echo"}); !errors.Is(err, ErrDeadline) {
		t.Errorf("без срока: %v", err)
	}
	if _, err := r.Stream(deadline(t, 5*time.Second), Command{Program: "sh"}); !errors.Is(err, ErrProgram) {
		t.Errorf("вне списка: %v", err)
	}
	s, err := r.Stream(deadline(t, 5*time.Second), Command{Program: "echo", Args: []string{"a b"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(s)
	if err != nil || string(b) != "a b\n" {
		t.Errorf("вывод %q, ошибка %v", b, err)
	}
	s.Close()
	s, err = r.Stream(deadline(t, 5*time.Second), Command{Program: "false"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(s); !errors.Is(err, ErrExit) {
		t.Errorf("ненулевой код: %v, нужно ErrExit", err)
	}
	s.Close()
}

// Close завершает процесс, который сам не кончается (journalctl -f), и не ждёт срока.
func TestRealStreamClose(t *testing.T) {
	r := newReal(testPrograms(t), http.DefaultTransport)
	s, err := r.Stream(deadline(t, time.Minute), Command{Program: "sleep", Args: []string{"60"}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s.Close()
	s.Close()
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close ждал %v", d)
	}
}

func TestFakeStream(t *testing.T) {
	f := newFake(t.TempDir(), time.Time{}, testPrograms(t))
	if _, err := f.Stream(deadline(t, time.Second), Command{Program: "echo"}); err == nil {
		t.Error("без HandleStream — нужна ошибка")
	}
	f.HandleStream("echo", func(Command) (io.Reader, error) { return strings.NewReader("x\n"), nil })
	if _, err := f.Stream(context.Background(), Command{Program: "echo"}); !errors.Is(err, ErrDeadline) {
		t.Errorf("без срока: %v", err)
	}
	s, err := f.Stream(deadline(t, time.Second), Command{Program: "echo", Args: []string{"-n"}})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(s); string(b) != "x\n" {
		t.Errorf("вывод %q", b)
	}
	if c := f.Calls(); len(c) != 2 || c[1].Op != "stream" || c[1].Args[0] != "-n" {
		t.Errorf("вызовы %+v", c)
	}
}
