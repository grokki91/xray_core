package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// programs — закрытый список программ: имя → абсолютный путь. Пополняется вместе с первым
// потребителем (systemctl, xray — фаза 2).
func programs() map[string]string { return map[string]string{} }

// childEnv — окружение процесса: ничего от родителя, секретов через окружение не передаём.
var childEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// waitDelay — сколько ждать закрытия вывода после завершения процесса по сроку.
const waitDelay = time.Second

// Real — настоящая реализация.
type Real struct {
	programs map[string]string
	files    files
}

// New возвращает настоящую реализацию.
func New() *Real { return newReal(programs()) }

func newReal(progs map[string]string) *Real {
	return &Real{programs: progs, files: files{
		chown: func(f *os.File, _ string, o Owner) error { return f.Chown(o.UID, o.GID) },
		trace: func(string, string) {},
	}}
}

func (r *Real) FS() FS { return r.files }

func (r *Real) Clock() Clock { return realClock{} }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (r *Real) Exec(ctx context.Context, c Command) (Result, error) {
	path, err := checkCommand(ctx, r.programs, c)
	if err != nil {
		return Result{}, err
	}
	cmd := exec.CommandContext(ctx, path, c.Args...)
	cmd.Env = childEnv
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(c.Stdin)
	stdout, stderr := &limited{}, &limited{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Своя группа процессов: по сроку завершаются и потомки программы, а не только она.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	err = cmd.Run()
	if stdout.over || stderr.over {
		return Result{}, fmt.Errorf("%s: вывод больше %d байт", c.Program, MaxOutput)
	}
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("%s: %w", c.Program, ctx.Err())
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return Result{ExitCode: exitErr.ExitCode(), Stdout: stdout.b.Bytes(), Stderr: stderr.b.Bytes()}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", c.Program, err)
	}
	return Result{Stdout: stdout.b.Bytes(), Stderr: stderr.b.Bytes()}, nil
}

// MaxOutput — предел каждого из stdout и stderr процесса.
const MaxOutput = 16 << 20

// limited копит вывод до MaxOutput; сверх предела отказывает в записи, и процесс получает
// ошибку записи в канал.
type limited struct {
	b    bytes.Buffer
	over bool
}

func (l *limited) Write(p []byte) (int, error) {
	if l.b.Len()+len(p) > MaxOutput {
		l.over = true
		return 0, errors.New("предел вывода")
	}
	return l.b.Write(p)
}

// checkCommand — общие для обеих реализаций предусловия запуска; возвращает путь программы.
func checkCommand(ctx context.Context, progs map[string]string, c Command) (string, error) {
	path, ok := progs[c.Program]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrProgram, c.Program)
	}
	if _, ok := ctx.Deadline(); !ok {
		return "", ErrDeadline
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%s: %w", c.Program, err)
	}
	return path, nil
}
