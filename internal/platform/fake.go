package platform

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"
)

// Fake — поддельная реализация для тестов: файлы — под временным каталогом root, владельцы
// записываются, а не меняются (root не нужен), процессы отвечают обработчиками, все вызовы
// записываются. Правила путей, ссылок, блокировок и запуска — те же, что у Real.
type Fake struct {
	programs map[string]string
	files    files

	mu       sync.Mutex
	now      time.Time
	calls    []Call
	owners   map[string]Owner
	handlers map[string]func(Command) (Result, error)
}

// Call — записанный вызов: операция и путь или программа с аргументами.
type Call struct {
	Op   string // read, write, mkdir, lock, exec
	Path string // путь файла или имя программы
	Args []string
}

// NewFake возвращает поддельную реализацию с файлами под root и часами, стоящими на now.
func NewFake(root string, now time.Time) *Fake { return newFake(root, now, programs()) }

func newFake(root string, now time.Time, progs map[string]string) *Fake {
	f := &Fake{programs: progs, now: now, owners: map[string]Owner{}, handlers: map[string]func(Command) (Result, error){}}
	f.files = files{root: root, chown: f.recordOwner, trace: f.trace}
	return f
}

func (f *Fake) recordOwner(_ *os.File, path string, o Owner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owners[path] = o
	return nil
}

func (f *Fake) trace(op, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Op: op, Path: path})
}

func (f *Fake) FS() FS { return f.files }

func (f *Fake) Clock() Clock { return fakeClock{f} }

type fakeClock struct{ f *Fake }

func (c fakeClock) Now() time.Time {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	return c.f.now
}

// SetNow переводит часы.
func (f *Fake) SetNow(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}

// Handle задаёт ответ программы из закрытого списка.
func (f *Fake) Handle(program string, h func(Command) (Result, error)) {
	if _, ok := f.programs[program]; !ok {
		panic(fmt.Sprintf("platform.Fake: программы %q нет в закрытом списке", program)) // ошибка теста
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[program] = h
}

func (f *Fake) Exec(ctx context.Context, c Command) (Result, error) {
	if _, err := checkCommand(ctx, f.programs, c); err != nil {
		return Result{}, err
	}
	f.mu.Lock()
	f.calls = append(f.calls, Call{Op: "exec", Path: c.Program, Args: slices.Clone(c.Args)})
	h := f.handlers[c.Program]
	f.mu.Unlock()
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
