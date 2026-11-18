package platform

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Fake — поддельная реализация для тестов: файлы — под временным каталогом root, владельцы
// записываются, а не меняются (root не нужен), процессы отвечают обработчиками или запускаются
// файлом под root (RunUnderRoot), все вызовы записываются, сеть отвечает заданными телами и
// перенаправлениями. Правила путей, ссылок, блокировок, запуска и адресов — те же, что у Real.
type Fake struct {
	programs map[string]string
	files    files

	mu        sync.Mutex
	now       time.Time
	calls     []Call
	owners    map[string]Owner
	handlers  map[string]func(Command) (Result, error)
	underRoot map[string]bool
	routes    map[string]fakeRoute
	users     map[string]Owner
	effective Owner
	journal   *fakeJournal
	listening map[int]bool
}

// Call — записанный вызов: операция и путь, имя пользователя или программа с аргументами.
type Call struct {
	Op      string // read, write, mkdir, symlink, readlink, lock, exec, get, user
	Path    string // путь файла, имя программы или адрес
	Version string // версия xray
	Args    []string
	Auth    bool // get: у первого запроса был токен
}

// NewFake возвращает поддельную реализацию с файлами под root и часами, стоящими на now.
func NewFake(root string, now time.Time) *Fake { return newFake(root, now, programs()) }

func newFake(root string, now time.Time, progs map[string]string) *Fake {
	f := &Fake{programs: progs, now: now, owners: map[string]Owner{}, handlers: map[string]func(Command) (Result, error){}, underRoot: map[string]bool{}, routes: map[string]fakeRoute{}, users: map[string]Owner{}, listening: map[int]bool{}}
	f.journal = &fakeJournal{f: f}
	f.files = files{root: root, chown: f.recordOwner, ownerOf: f.ownerOf, trace: f.trace}
	return f
}

func (f *Fake) recordOwner(_ *os.File, path string, o Owner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owners[path] = o
	return nil
}

// ownerOf — владелец пути у подделки: назначенный Mkdir или WriteFile, иначе root.
func (f *Fake) ownerOf(path string, _ fs.FileInfo) Owner {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.owners[path]
}

func (f *Fake) trace(op, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Op: op, Path: path})
}

func (f *Fake) FS() FS { return f.files }

func (f *Fake) Net() Net { return fakeNet{f} }

// Serve задаёт тело ответа 200 на адрес.
func (f *Fake) Serve(url string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[url] = fakeRoute{body: slices.Clone(body)}
}

// Redirect задаёт перенаправление с адреса from на to.
func (f *Fake) Redirect(from, to string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[from] = fakeRoute{location: to}
}

// SetListening задаёт, слушает ли «хост» порт.
func (f *Fake) SetListening(port int, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listening[port] = on
}

func (f *Fake) Users() Users { return fakeUsers{f} }

func (f *Fake) Clock() Clock { return fakeClock{f} }

type fakeClock struct{ f *Fake }

func (c fakeClock) Now() time.Time {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	return c.f.now
}

// Sleep у подделки не ждёт: часы сдвигаются на d.
func (c fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.now = c.f.now.Add(d)
	return nil
}

// SetNow переводит часы.
func (f *Fake) SetNow(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}

// Handle задаёт ответ программы из закрытого списка.
func (f *Fake) Handle(program string, h func(Command) (Result, error)) {
	if _, ok := f.programs[program]; !ok && program != xrayProgram {
		panic(fmt.Sprintf("platform.Fake: программы %q нет в закрытом списке", program)) // ошибка теста
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[program] = h
	delete(f.underRoot, program)
}

// RunUnderRoot велит запускать программу настоящим файлом её пути под root — так стенд L3
// исполняет настоящий бинарник Xray без root на машине теста. Запуск — тот же, что у Real
// (окружение, группа процессов, пределы); аргумент, начинающийся с «/», получает префикс root:
// пути на VPS у подделки лежат под ним; неочищенный путь — ErrPath. Заменяет обработчик Handle.
func (f *Fake) RunUnderRoot(program string) {
	if _, ok := f.programs[program]; !ok && program != xrayProgram {
		panic(fmt.Sprintf("platform.Fake: программы %q нет в закрытом списке", program)) // ошибка теста
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.underRoot[program] = true
	delete(f.handlers, program)
}

func (f *Fake) Exec(ctx context.Context, c Command) (Result, error) {
	path, err := checkCommand(ctx, f.programs, c)
	if err != nil {
		return Result{}, err
	}
	if err := f.files.checkBinary(c, path); err != nil {
		return Result{}, err
	}
	f.mu.Lock()
	f.calls = append(f.calls, Call{Op: "exec", Path: c.Program, Version: c.Version, Args: slices.Clone(c.Args)})
	h, underRoot := f.handlers[c.Program], f.underRoot[c.Program]
	f.mu.Unlock()
	if underRoot {
		args := make([]string, len(c.Args))
		for i, a := range c.Args {
			if strings.HasPrefix(a, "/") {
				// Путь — по правилу FS: абсолютный и очищенный, иначе «/../x» ушёл бы из root.
				p, err := f.files.real(a)
				if err != nil {
					return Result{}, err
				}
				a = p
			}
			args[i] = a
		}
		return runProcess(ctx, f.files.root+path, c.Program, args, c.Stdin)
	}
	if h == nil {
		return Result{}, fmt.Errorf("platform.Fake: нет ответа для %q", c.Program)
	}
	return h(c)
}

// Calls возвращает записанные вызовы по порядку.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// Owner возвращает владельца, назначенного пути последней записью или созданием.
func (f *Fake) Owner(path string) (Owner, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.owners[path]
	return o, ok
}

// Path возвращает расположение пути на диске (для проверок в тестах).
func (f *Fake) Path(path string) string { return f.files.root + path }
