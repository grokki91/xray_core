package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"time"
)

// programs — закрытый список программ: имя → абсолютный путь. Пополняется вместе с первым
// потребителем.
func programs() map[string]string {
	return map[string]string{useradd: "/usr/sbin/useradd", systemctl: "/usr/bin/systemctl"}
}

// childEnv — окружение процесса: ничего от родителя, секретов через окружение не передаём.
var childEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// waitDelay — сколько ждать закрытия вывода после завершения процесса по сроку.
const waitDelay = time.Second

// Real — настоящая реализация.
type Real struct {
	programs map[string]string
	files    files
	net      realNet
}

// New возвращает настоящую реализацию.
func New() *Real { return newReal(programs(), http.DefaultTransport) }

// newReal принимает транспорт HTTP: тесты подставляют свой с доверием к локальному серверу.
func newReal(progs map[string]string, transport http.RoundTripper) *Real {
	return &Real{programs: progs, net: realNet{transport}, files: files{
		chown: func(f *os.File, _ string, o Owner) error { return f.Chown(o.UID, o.GID) },
		ownerOf: func(_ string, fi fs.FileInfo) Owner {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				return Owner{UID: int(st.Uid), GID: int(st.Gid)}
			}
			return Owner{UID: -1, GID: -1}
		},
		trace: func(string, string) {},
	}}
}

func (r *Real) FS() FS { return r.files }

func (r *Real) Net() Net { return r.net }

func (r *Real) Users() Users { return realUsers{r} }

func (r *Real) Clock() Clock { return realClock{} }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Real) Exec(ctx context.Context, c Command) (Result, error) {
	path, err := checkCommand(ctx, r.programs, c)
	if err != nil {
		return Result{}, err
	}
	if err := r.files.checkBinary(c, path); err != nil {
		return Result{}, err
	}
	return runProcess(ctx, path, c.Program, c.Args, c.Stdin)
}

func (r *Real) Start(ctx context.Context, c Command) (Process, error) {
	path, err := checkCommand(ctx, r.programs, c)
	if err != nil {
		return nil, err
	}
	if err := r.files.checkBinary(c, path); err != nil {
		return nil, err
	}
	return startProcess(ctx, path, c.Program, c.Args, c.Stdin)
}

// proc — фоновый процесс.
type proc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *proc) Done() <-chan struct{} { return p.done }

func (p *proc) Stop() {
	select {
	case <-p.done: // уже завершён: pid мог уйти другому процессу
		return
	default:
	}
	syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	<-p.done
}

// startProcess запускает файл path в фоне теми же правилами, что runProcess; вывод
// отбрасывается: процесс самопроверки не должен копить его и писать куда-либо.
func startProcess(ctx context.Context, path, name string, args []string, stdin []byte) (Process, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = childEnv
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	p := &proc{cmd: cmd, done: make(chan struct{})}
	go func() {
		cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// runProcess запускает файл path без оболочки: окружение childEnv, каталог «/», своя группа
// процессов, предел вывода. Общий путь Real.Exec и Fake.RunUnderRoot.
func runProcess(ctx context.Context, path, name string, args []string, stdin []byte) (Result, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = childEnv
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(stdin)
	stdout, stderr := &limited{}, &limited{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Своя группа процессов: по сроку завершаются и потомки программы, а не только она.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	err := cmd.Run()
	if stdout.over || stderr.over {
		return Result{}, fmt.Errorf("%s: вывод больше %d байт", name, MaxOutput)
	}
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return Result{ExitCode: exitErr.ExitCode(), Stdout: stdout.b.Bytes(), Stderr: stderr.b.Bytes()}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", name, err)
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

// xrayProgram — программа, путь которой строится из версии (ADR-0019).
const xrayProgram = "xray"

var versionRe = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`)

// ValidVersion — единственное правило версии Xray N.N.N (docs/security/policy.md §5): по нему
// строится путь программы, поэтому его используют и core, и update.
func ValidVersion(v string) bool { return versionRe.MatchString(v) }

// xrayPath — путь бинарника Xray версии v; версия не N.N.N — ErrProgram.
func xrayPath(v string) (string, error) {
	if !ValidVersion(v) {
		return "", fmt.Errorf("%w: xray версии %q", ErrProgram, v)
	}
	return CoreDir + "/" + v + "/" + xrayProgram, nil
}

// checkCommand — общие для обеих реализаций предусловия запуска; возвращает путь программы.
func checkCommand(ctx context.Context, progs map[string]string, c Command) (string, error) {
	var path string
	if c.Program == xrayProgram {
		p, err := xrayPath(c.Version)
		if err != nil {
			return "", err
		}
		path = p
	} else {
		p, ok := progs[c.Program]
		if !ok || c.Version != "" {
			return "", fmt.Errorf("%w: %q", ErrProgram, c.Program)
		}
		path = p
	}
	if _, ok := ctx.Deadline(); !ok {
		return "", ErrDeadline
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%s: %w", c.Program, err)
	}
	return path, nil
}
