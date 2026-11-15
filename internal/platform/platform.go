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

// Platform — порт целиком. Systemd и Users добавляются с первым потребителем (фазы 2 и 4).
type Platform interface {
	// Exec запускает программу из закрытого списка без оболочки. Ненулевой код выхода — не
	// ошибка: он в Result.ExitCode. Контекст обязан нести срок.
	Exec(ctx context.Context, c Command) (Result, error)
	FS() FS
	Net() Net
	Clock() Clock
}

// Command — запуск программы. Program — имя из закрытого списка, а не путь; ввод владельца —
// только отдельным элементом Args; секрет — только через Stdin.
type Command struct {
	Program string
	Args    []string
	Stdin   []byte
}

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
	// Lock берёт межпроцессную исключительную блокировку файла path (создаёт его с 0600) и ждёт
	// её до конца срока ctx.
	Lock(ctx context.Context, path string) (unlock func(), err error)
}

// Owner — числовые идентификаторы владельца. Имена разрешает Users (фаза 4).
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
	// обязан нести срок.
	Get(ctx context.Context, r Request) ([]byte, error)
}

// Request — загрузка: адрес, закрытый список узлов потребителя и предел тела в байтах.
type Request struct {
	URL   string
	Hosts []string
	Max   int64
}

// Clock — время.
type Clock interface {
	Now() time.Time
}

var (
	ErrProgram  = errors.New("программа не из закрытого списка")
	ErrURL      = errors.New("адрес не https или узел не из закрытого списка")
	ErrTooLarge = errors.New("тело ответа больше предела")
	ErrDeadline = errors.New("у операции нет срока: контекст без дедлайна")
	ErrPath     = errors.New("путь не абсолютный или не очищенный")
	ErrSymlink  = errors.New("на пути символическая ссылка")
	ErrNotFound = fs.ErrNotExist
)
