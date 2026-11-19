// Пакет platform — порт к системе и единственное место побочных эффектов: процессы, файлы,
// часы, загрузка по HTTPS (дальше — systemd, пользователи, остальная сеть). Две реализации: настоящая (New) и поддельная
// (NewFake) для тестов уровня L2; общий тест проверяет, что они ведут себя одинаково.
package platform

import (
	"context"
	"errors"
	"io/fs"
	"time"
)

// Platform — порт целиком.
type Platform interface {
	// Exec запускает программу из закрытого списка без оболочки. Ненулевой код выхода — не
	// ошибка: он в Result.ExitCode. Контекст обязан нести срок.
	Exec(ctx context.Context, c Command) (Result, error)
	// Start запускает программу из закрытого списка в фоне — правила Exec: без оболочки, свои
	// группа процессов и окружение, срок в контексте обязателен; вывод отбрасывается, Stdin
	// подаётся целиком и закрывается. Процесс завершается по сроку контекста или Process.Stop.
	Start(ctx context.Context, c Command) (Process, error)
	FS() FS
	Net() Net
	Users() Users
	Systemd() Systemd
	Journal() Journal
	Clock() Clock
}

// Command — запуск программы. Program — имя из закрытого списка, а не путь; ввод владельца —
// только отдельным элементом Args; секрет — только через Stdin. Version — только у xray: путь
// строится из неё (ADR-0019).
type Command struct {
	Program string
	Version string
	Args    []string
	Stdin   []byte
}

// Process — запущенный в фоне процесс.
type Process interface {
	// Done закрывается, когда процесс завершился — сам, по сроку контекста или по Stop.
	Done() <-chan struct{}
	// Stop завершает группу процессов и ждёт выхода; повторный вызов безопасен.
	Stop()
}

// CoreDir — каталог версий Xray: <CoreDir>/<версия>/xray и ссылка <CoreDir>/current
// (docs/architecture/data-model.md §1).
const CoreDir = "/usr/local/lib/xm/core"

// Result — итог завершившегося процесса.
type Result struct {
	ExitCode       int
	Stdout, Stderr []byte
}

// FS — файлы. Пути только абсолютные и очищенные; символические ссылки на пути не допускаются.
type FS interface {
	ReadFile(path string) ([]byte, error)
	// WriteFile пишет атомарно: временный файл в том же каталоге сразу с правами perm и
	// владельцем owner, fsync, rename, fsync каталога. Читатель видит старый или новый файл.
	WriteFile(path string, data []byte, perm fs.FileMode, owner Owner) error
	// Mkdir создаёт каталог с правами и владельцем; существующий каталог не меняет.
	Mkdir(path string, perm fs.FileMode, owner Owner) error
	// Remove удаляет обычный файл; ссылка на пути или на месте файла, каталог — ошибка.
	Remove(path string) error
	// ReadDir возвращает имена записей каталога по возрастанию; нет каталога — ErrNotFound.
	ReadDir(path string) ([]string, error)
	// Symlink атомарно ставит на path ссылку на target: временная ссылка в том же каталоге и
	// rename. target — одно имя в том же каталоге (без «/», не «.» и «..»), иначе ErrPath;
	// каталог на месте path не заменяется.
	Symlink(path, target string) error
	// Readlink возвращает цель ссылки path; не ссылка — ошибка, нет файла — ErrNotFound.
	Readlink(path string) (string, error)
	// Lock берёт межпроцессную исключительную блокировку файла path (создаёт его с 0600) и ждёт
	// её до конца срока ctx.
	Lock(ctx context.Context, path string) (unlock func(), err error)
}

// Users — системные пользователи; xm создаёт только ServiceUser.
type Users interface {
	// Ensure возвращает владельца пользователя name; нет такого — создаёт системного без
	// оболочки и домашнего каталога (группа с тем же именем). Допустимо только ServiceUser,
	// иначе ErrName. Контекст обязан нести срок.
	Ensure(ctx context.Context, name string) (Owner, error)
	// Effective — владелец процесса xm (эффективные uid и gid): по нему server проверяет root.
	Effective() Owner
}

// Owner — числовые идентификаторы владельца. Имена разрешает Users.
type Owner struct {
	UID, GID int
}

// Root — владелец root:root.
func Root() Owner { return Owner{} }

// Net — сеть. Пока только загрузка по HTTPS (update); интерфейсы, маршруты и сокеты — с первым
// потребителем (фаза 4).
type Net interface {
	// Get возвращает тело ответа 200 на GET. Адрес и каждое перенаправление — только https и
	// узел (с портом, если он есть в адресе) из r.Hosts, иначе ErrURL; тело больше r.Max —
	// ErrTooLarge; не больше 5 перенаправлений; прокси — из окружения (HTTPS_PROXY), как у
	// http.DefaultTransport: список сверяется с узлом назначения, TLS — до него; контекст
	// обязан нести срок. Непустой r.Token — заголовок Authorization: Bearer только у первого
	// запроса. Непустой r.Proxy — путь сокета Unix с HTTP-прокси (CONNECT): запрос идёт через
	// него, окружение не действует; путь не абсолютный или не очищенный — ErrPath. Ответ с кодом,
	// не равным r.Status (по умолчанию 200), — ошибка.
	Get(ctx context.Context, r Request) ([]byte, error)
	// Listening сообщает, слушает ли хост TCP-порт на любом адресе (IPv4 или IPv6): по таблицам
	// сокетов ядра, без соединения. Новых портов не открывает.
	Listening(ctx context.Context, port int) (bool, error)
}

// Request — загрузка: адрес, закрытый список узлов потребителя и предел тела в байтах.
// Token — токен Bearer: уходит только в первый запрос, в перенаправления — нет (ADR-0031);
// формат проверяет потребитель. Proxy и Status — ADR-0032.
type Request struct {
	URL    string
	Hosts  []string
	Max    int64
	Token  string
	Proxy  string
	Status int
}

// Clock — время.
type Clock interface {
	Now() time.Time
	// Sleep ждёт d или конца ctx; при отмене возвращает ошибку контекста.
	Sleep(ctx context.Context, d time.Duration) error
}

var (
	ErrProgram  = errors.New("программа не из закрытого списка")
	ErrURL      = errors.New("адрес не https или узел не из закрытого списка")
	ErrTooLarge = errors.New("тело ответа больше предела")
	ErrDeadline = errors.New("у операции нет срока: контекст без дедлайна")
	ErrPath     = errors.New("путь не абсолютный или не очищенный")
	ErrSymlink  = errors.New("на пути символическая ссылка")
	ErrName     = errors.New("недопустимое имя пользователя")
	ErrNotFound = fs.ErrNotExist
)
