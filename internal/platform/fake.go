package platform

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
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
	starters  map[string]func(Command) error
	streams   map[string]func(Command) (io.Reader, error)
	users     map[string]Owner
	effective Owner
	journal   *fakeJournal
	listening map[int]bool
	families  map[int]Families
	connect   map[netip.AddrPort]error
	addrs     []IfAddr
	tls       map[string]fakeTLS
	usage     map[string]DiskUsage
	defRoutes Families
}

// Call — записанный вызов: операция и путь, имя пользователя или программа с аргументами.
type Call struct {
	Op      string // read, write, mkdir, symlink, readlink, lock, exec, start, stream, get, tls, user
	Path    string // путь файла, имя программы или адрес
	Version string // версия xray
	Args    []string
	Auth    bool   // get: у первого запроса был токен
	Proxy   string // get: сокет прокси
}

// NewFake возвращает поддельную реализацию с файлами под root и часами, стоящими на now.
func NewFake(root string, now time.Time) *Fake { return newFake(root, now, programs()) }

func newFake(root string, now time.Time, progs map[string]string) *Fake {
	f := &Fake{programs: progs, now: now, owners: map[string]Owner{}, handlers: map[string]func(Command) (Result, error){}, underRoot: map[string]bool{}, routes: map[string]fakeRoute{}, starters: map[string]func(Command) error{}, streams: map[string]func(Command) (io.Reader, error){}, users: map[string]Owner{}, listening: map[int]bool{}, families: map[int]Families{}, connect: map[netip.AddrPort]error{}, tls: map[string]fakeTLS{}, usage: map[string]DiskUsage{}}
	f.journal = &fakeJournal{f: f}
	f.files = files{root: root, chown: f.recordOwner, ownerOf: f.ownerOf, trace: f.trace, statfs: f.statfs}
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

// ServeStatus задаёт ответ с кодом status и телом на адрес.
func (f *Fake) ServeStatus(url string, status int, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[url] = fakeRoute{body: slices.Clone(body), status: status}
}

// ServeVia задаёт ответ на адрес только для запроса через Proxy; прямой запрос видит Serve.
// Без ServeVia запрос через прокси видит тот же ответ, что и прямой.
func (f *Fake) ServeVia(url string, status int, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[viaKey(url)] = fakeRoute{body: slices.Clone(body), status: status}
}

// Redirect задаёт перенаправление с адреса from на to.
func (f *Fake) Redirect(from, to string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[from] = fakeRoute{location: to}
}

// SetAddrs задаёт адреса интерфейсов «хоста».
func (f *Fake) SetAddrs(a []IfAddr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs = slices.Clone(a)
}

// SetListening задаёт, слушает ли «хост» порт.
func (f *Fake) SetListening(port int, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listening[port] = on
}

// SetFamilies задаёт семейства, на которых «хост» слушает порт.
func (f *Fake) SetFamilies(port int, fam Families) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.families[port] = fam
}

// SetDefaultRoutes задаёт, по каким семействам у «хоста» есть маршрут по умолчанию.
func (f *Fake) SetDefaultRoutes(fam Families) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.defRoutes = fam
}

// SetUsage задаёт место файловой системы для пути; Usage на не заданном пути — ErrNotFound.
func (f *Fake) SetUsage(path string, u DiskUsage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usage[path] = u
}

func (f *Fake) statfs(_, path string) (DiskUsage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.usage[path]
	if !ok {
		return DiskUsage{}, fmt.Errorf("место %s: %w", path, ErrNotFound)
	}
	return u, nil
}

// SetConnect задаёт исход соединения с addr: nil — установлено. Не заданный узел — ошибка.
func (f *Fake) SetConnect(addr netip.AddrPort, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connect[addr] = err
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
	delete(f.starters, program)
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
		args, err := f.rootArgs(c.Args)
		if err != nil {
			return Result{}, err
		}
		return runProcess(ctx, f.files.root+path, c.Program, args, c.Stdin)
	}
	if h == nil {
		return Result{}, fmt.Errorf("platform.Fake: нет ответа для %q", c.Program)
	}
	return h(c)
}

// rootArgs — аргументы запуска под root: аргумент с ведущим «/» получает префикс root. Путь — по
// правилу FS: абсолютный и очищенный, иначе «/../x» ушёл бы из root.
func (f *Fake) rootArgs(in []string) ([]string, error) {
	args := make([]string, len(in))
	for i, a := range in {
		if strings.HasPrefix(a, "/") {
			p, err := f.files.real(a)
			if err != nil {
				return nil, err
			}
			a = p
		}
		args[i] = a
	}
	return args, nil
}

// HandleStart велит Start подделки не запускать файл, а вызвать h: процесс живёт до Stop или
// конца срока контекста. Ошибка h — ошибка Start. Заменяет RunUnderRoot для программы.
func (f *Fake) HandleStart(program string, h func(Command) error) {
	if _, ok := f.programs[program]; !ok && program != xrayProgram {
		panic(fmt.Sprintf("platform.Fake: программы %q нет в закрытом списке", program)) // ошибка теста
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starters[program] = h
	delete(f.underRoot, program)
}

// fakeProc — процесс без файла: завершается по Stop или по сроку контекста.
type fakeProc struct {
	done chan struct{}
	once sync.Once
}

func (p *fakeProc) Done() <-chan struct{} { return p.done }
func (p *fakeProc) Stop()                 { p.once.Do(func() { close(p.done) }) }

// Start запускает в фоне настоящий файл программы под root, как RunUnderRoot; без RunUnderRoot —
// ошибка: у фонового процесса нет обработчика.
func (f *Fake) Start(ctx context.Context, c Command) (Process, error) {
	path, err := checkCommand(ctx, f.programs, c)
	if err != nil {
		return nil, err
	}
	if err := f.files.checkBinary(c, path); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.calls = append(f.calls, Call{Op: "start", Path: c.Program, Version: c.Version, Args: slices.Clone(c.Args)})
	underRoot, handler := f.underRoot[c.Program], f.starters[c.Program]
	f.mu.Unlock()
	if handler != nil {
		if err := handler(c); err != nil {
			return nil, err
		}
		p := &fakeProc{done: make(chan struct{})}
		go func() {
			select {
			case <-ctx.Done():
				p.Stop()
			case <-p.done:
			}
		}()
		return p, nil
	}
	if !underRoot {
		return nil, fmt.Errorf("platform.Fake: Start %q без RunUnderRoot и HandleStart", c.Program)
	}
	args, err := f.rootArgs(c.Args)
	if err != nil {
		return nil, err
	}
	return startProcess(ctx, f.files.root+path, c.Program, args, c.Stdin)
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
