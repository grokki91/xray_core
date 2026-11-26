package platform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"sync"
	"syscall"
)

// Journalctl — программа чтения journald (logging, ADR-0044); только чтение.
const Journalctl = "journalctl"

// ErrExit — потоковый процесс завершился с ненулевым кодом.
var ErrExit = errors.New("ненулевой код выхода")

// Stream запускает программу из закрытого списка по правилам Exec и отдаёт её stdout потоком.
// stderr отбрасывается. Чтение до конца ждёт выхода процесса: ненулевой код — ошибка ErrExit
// вместо io.EOF. Close убивает группу процессов и ждёт выхода; повторный вызов безопасен.
func (r *Real) Stream(ctx context.Context, c Command) (io.ReadCloser, error) {
	path, err := checkCommand(ctx, r.programs, c)
	if err != nil {
		return nil, err
	}
	if err := r.files.checkBinary(c, path); err != nil {
		return nil, err
	}
	return streamProcess(ctx, path, c)
}

func streamProcess(ctx context.Context, path string, c Command) (io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, path, c.Args...)
	cmd.Env = childEnv
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Program, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: %w", c.Program, err)
	}
	return &stream{cmd: cmd, out: out, name: c.Program, ctx: ctx}, nil
}

type stream struct {
	cmd  *exec.Cmd
	out  io.Reader
	name string
	ctx  context.Context
	once sync.Once
	err  error
}

func (s *stream) Read(p []byte) (int, error) {
	n, err := s.out.Read(p)
	if err == io.EOF {
		if werr := s.wait(); werr != nil {
			return n, werr
		}
	}
	return n, err
}

// wait ждёт выхода один раз: и конец чтения, и Close приходят сюда.
func (s *stream) wait() error {
	s.once.Do(func() {
		err := s.cmd.Wait()
		var exitErr *exec.ExitError
		switch {
		case s.ctx.Err() != nil:
			s.err = fmt.Errorf("%s: %w", s.name, s.ctx.Err())
		case errors.As(err, &exitErr):
			s.err = fmt.Errorf("%s: %w %d", s.name, ErrExit, exitErr.ExitCode())
		case err != nil:
			s.err = fmt.Errorf("%s: %w", s.name, err)
		}
	})
	return s.err
}

func (s *stream) Close() error {
	if s.cmd.ProcessState == nil {
		syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
	}
	s.wait()
	return nil
}

// HandleStream задаёт поток программы для Stream подделки: h возвращает stdout целиком или
// блокирующий читатель; ошибка h — ошибка Stream.
func (f *Fake) HandleStream(program string, h func(Command) (io.Reader, error)) {
	if _, ok := f.programs[program]; !ok {
		panic(fmt.Sprintf("platform.Fake: программы %q нет в закрытом списке", program)) // ошибка теста
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.streams[program] = h
}

// Stream подделки проверяет те же предусловия, что Real, записывает вызов (op stream) и отдаёт
// поток обработчика HandleStream.
func (f *Fake) Stream(ctx context.Context, c Command) (io.ReadCloser, error) {
	path, err := checkCommand(ctx, f.programs, c)
	if err != nil {
		return nil, err
	}
	if err := f.files.checkBinary(c, path); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.calls = append(f.calls, Call{Op: "stream", Path: c.Program, Args: slices.Clone(c.Args)})
	h := f.streams[c.Program]
	f.mu.Unlock()
	if h == nil {
		return nil, fmt.Errorf("platform.Fake: нет потока для %q", c.Program)
	}
	r, err := h(c)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(r), nil
}
