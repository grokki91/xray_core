package platform

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// startImpls — реализации с программами sleep и cat; у подделки настоящие файлы лежат под её
// корнем и запускаются RunUnderRoot.
func startImpls(t *testing.T) []impl {
	t.Helper()
	progs := testPrograms(t)
	fake := newFake(t.TempDir(), time.Time{}, progs)
	for _, n := range []string{"sleep", "cat"} {
		b, err := os.ReadFile(progs[n])
		if err != nil {
			t.Fatal(err)
		}
		dst := fake.Path(progs[n])
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o755); err != nil {
			t.Fatal(err)
		}
		fake.RunUnderRoot(n)
	}
	return []impl{{"real", newReal(progs, http.DefaultTransport), ""}, {"fake", fake, ""}}
}

func closed(p Process) bool {
	select {
	case <-p.Done():
		return true
	default:
		return false
	}
}

func waitDone(t *testing.T, p Process, d time.Duration) {
	t.Helper()
	select {
	case <-p.Done():
	case <-time.After(d):
		t.Fatal("процесс не завершился")
	}
}

// Start запускает процесс в фоне: срок обязателен, Stop завершает группу и повторяем, срок
// контекста и конец ввода завершают процесс сами.
func TestStart(t *testing.T) {
	for _, i := range startImpls(t) {
		t.Run(i.name, func(t *testing.T) {
			if _, err := i.p.Start(context.Background(), Command{Program: "sleep", Args: []string{"10"}}); !errors.Is(err, ErrDeadline) {
				t.Errorf("без срока: %v, нужно ErrDeadline", err)
			}
			if _, err := i.p.Start(deadline(t, 5*time.Second), Command{Program: "nope"}); !errors.Is(err, ErrProgram) {
				t.Errorf("чужая программа: %v, нужно ErrProgram", err)
			}

			p, err := i.p.Start(deadline(t, 30*time.Second), Command{Program: "sleep", Args: []string{"30"}})
			if err != nil {
				t.Fatal(err)
			}
			if closed(p) {
				t.Fatal("процесс завершился сразу")
			}
			start := time.Now()
			p.Stop()
			p.Stop() // повтор безопасен
			if !closed(p) || time.Since(start) > 3*time.Second {
				t.Errorf("Stop не завершил процесс за %v", time.Since(start))
			}

			// Срок контекста завершает процесс без Stop.
			p, err = i.p.Start(deadline(t, 200*time.Millisecond), Command{Program: "sleep", Args: []string{"30"}})
			if err != nil {
				t.Fatal(err)
			}
			waitDone(t, p, 3*time.Second)

			// Stdin доходит до процесса: cat выходит сам, получив конец ввода.
			p, err = i.p.Start(deadline(t, 30*time.Second), Command{Program: "cat", Stdin: []byte("конфигурация")})
			if err != nil {
				t.Fatal(err)
			}
			waitDone(t, p, 3*time.Second)
			p.Stop()
		})
	}
}

// Start без RunUnderRoot у подделки — ошибка теста, а не молчаливый успех; запуск записывается.
func TestFakeStartNeedsRunUnderRoot(t *testing.T) {
	f := newFake(t.TempDir(), time.Time{}, testPrograms(t))
	if _, err := f.Start(deadline(t, time.Second), Command{Program: "sleep", Args: []string{"1"}}); err == nil {
		t.Error("процесс без RunUnderRoot запущен")
	}
}
