# Компоненты

У каждого компонента одна ответственность, узкий интерфейс и свои данные. Интерфейсы ниже —
эскиз на Go для согласования границ; точные сигнатуры уточняются в фазе реализации, изменение
границы — через ADR. Пути пакетов — относительно `internal/`.

Общие правила:

- Менеджер не импортирует другой менеджер. Нужное от соседа он объявляет у себя интерфейсом
  потребителя; связывает `cmd/xm`.
- Менеджер не запускает процессы и не трогает систему сам — только через `platform`.
- Менеджер не пишет в stdout и не решает, как показать результат: возвращает данные и ошибки.
- Состояние меняется только внутри транзакции `app` ([ADR-0005](../adr/0005-transactions-and-rollback.md)).

## Содержание

Основание: [platform](#platform) · [store](#store) · [redact](#redact) · [contract](#contract)
Менеджеры: [core](#core) · [config](#config) · [profile](#profile) · [server](#server) ·
[network](#network) · [dns](#dns) · [security](#security) · [diag](#diag) · [logging](#logging) ·
[update](#update) · [backup](#backup) · [monitor](#monitor)
Прикладной слой: [app](#app) · Интерфейсы: [cli](#cli) · [api](#api) · [webui](#webui) · [bridge](#bridge)

---

## Основание

### platform

Единственное место побочных эффектов: запуск процессов, файлы, systemd, пользователи, сокеты, часы.

```go
type Platform interface {
    Exec(ctx context.Context, name string, args ...string) (Result, error) // без оболочки
    FS() FS            // чтение, атомарная запись (temp + fsync + rename), права, владельцы
    Systemd() Systemd  // юниты: установить, включить, start/stop/restart, состояние
    Net() Net          // интерфейсы, маршруты, слушающие сокеты, исходящие соединения
    Users() Users      // системный пользователь службы
    Clock() Clock
}
```

- Команды — массивом аргументов, без `sh -c`; имя программы — из закрытого списка.
- Есть две реализации: настоящая и поддельная (каталог во временной папке, записанные вызовы) —
  на ней идут тесты уровня L2 ([testing.md](../testing.md)).
- Фаза 1; `Systemd`, `Users`, `Net` — вместе с первым потребителем (фазы 2 и 4).

### store

Состояние `state.json`: загрузка, проверка схемы, миграции, атомарная запись, межпроцессная блокировка.

```go
type Store interface {
    Load() (State, error)
    Save(State) error                    // только внутри транзакции
    Lock(ctx context.Context) (unlock func(), err error)
}
```

- Структура состояния и права — [data-model.md](data-model.md). Фаза 1.

### redact

Редактор чувствительных данных: реестр точных значений (ключи, UUID, адреса сервера из
состояния) плюс шаблоны (IP, UUID, ключи, URI-ссылки).

```go
type Redactor interface {
    Register(kind Kind, value string)   // точное значение → метка вида «<uuid:1>»
    Text(s string) string
    JSON(v any) any
}
```

- Замена стабильна в пределах отчёта: одинаковое значение → одинаковая метка, чтобы отчёт
  оставался читаемым. Политика — [secrets.md](../security/secrets.md). Фаза 1.

### contract

Типы всех машинных выводов (CLI `--json`, HTTP API, мост) и общий конверт со схемой. Только
данные, без логики; импортируется всеми слоями. Правила версионирования — [interfaces.md](interfaces.md) §2. Фаза 1.

---

## Менеджеры

### core

Upstream-бинарник Xray на диске. Не знает, откуда берутся релизы (это `update`), и не знает
содержимого конфигурации (это `config`).

```go
type Manager interface {
    Current(ctx context.Context) (Version, error)       // активная версия; пусто — не установлено
    Stage(ctx context.Context, v Version, zip io.Reader) error // распаковать в каталог версии, проверить бинарник
    Activate(ctx context.Context, v Version) error      // атомарно переключить ссылку current
    Previous() (Version, bool)
    Prune(keep int) error
    Validate(ctx context.Context, configPath string) error // xray run -test
    Tool(ctx context.Context, sub Subcommand, args ...string) ([]byte, error) // закрытый список подкоманд
}
```

- Данные: `/usr/local/lib/xm/core/<версия>/xray`, ссылка `current`; хранятся две версии.
- Распаковка защищена от выхода из каталога; проверяется, что бинарник — ELF нужной архитектуры
  и `xray version` отвечает ожидаемой версией. Фаза 2.

### config

Строит конфигурацию Xray из состояния. Детерминированно: одно состояние → побайтно один файл.

```go
type Manager interface {
    Render(st State) (Rendered, error)
    Write(ctx context.Context, r Rendered) error  // атомарно, права по манифесту
    Drift(ctx context.Context) (bool, error)      // файл на диске ≠ последнему применённому
}

type Preset interface {  // каталог пресетов: config/preset
    ID() string                                   // например "reality-xhttp"
    Inbound(p Params) (json.RawMessage, error)
    Requires() Requirements                       // минимальная версия Xray, порт, нужна ли цель
}
```

- Собирает разделы: `log` (от `logging`), `dns` (от `dns`), `inbounds` (пресет + клиенты от
  `profile`), `outbounds`, `routing` (в том числе запрет частных и петлевых адресов назначения,
  [policy.md](../security/policy.md) §4).
- Ручная правка файла — дрейф: `status` показывает его, следующее применение сохраняет
  изменённый файл в снимок и перезаписывает.
- Проверка — `core.Validate` перед записью. Набор полей сверяется с upstream по скилу
  `xray-upstream`. Фаза 2.

### profile

Клиентские профили и всё, что отдаётся клиентам.

```go
type Manager interface {
    Create(name string) (Profile, error)   // имя проверяется, учётные данные — от security
    List() []Profile
    Get(name string) (Profile, error)
    Delete(name string) error
}

type Exporter interface {  // profile/export — единственное место форматов клиентов
    Format() string                        // "uri", "qr", "sing-box"
    Export(p Profile, e Endpoint) (Artifact, error)
}

type Compat interface {    // profile/compat — таблица данных с датой и источником
    Clients(presetID string, core Version) []ClientSupport
}
```

- Имя профиля: `[a-z0-9][a-z0-9_-]{0,31}`; оно же — метка в URI.
- `Endpoint` — адрес (IPv4, IPv6 в скобках, домен), порт и параметры пресета; один профиль
  экспортируется для каждого адреса сервера.
- Экспорт под пресет, который клиент не поддерживает, — ошибка с причиной из таблицы
  совместимости, а не «приблизительная» ссылка. Фаза 3.

### server

Узел как целое: годится ли машина и как управлять службой.

```go
type Manager interface {
    Preflight(ctx context.Context) (HostFacts, []Issue) // ОС, архитектура, ресурсы, systemd, время, чужая установка
    InstallUnit(ctx context.Context, spec UnitSpec) error
    RemoveUnit(ctx context.Context) error
    Service() Service                                    // Start, Stop, Restart, Status
}
```

- Чужая установка — `xray.service` или конфигурация Xray без метки `xm`: остановка с объяснением.
- Расширение «несколько VPS»: реестр узлов (алиас SSH, без учётных данных) и исполнитель,
  вызывающий на узле тот же `xm … --json`. Фаза 2; реестр — после MVP.

### network

Сетевые факты и проверки. Только читает.

```go
type Manager interface {
    Facts(ctx context.Context) (NetFacts, error) // адреса и маршруты IPv4/IPv6, внешний адрес, состояние фаервола
    PortFree(ctx context.Context, port int) (bool, Holder, error)
    ProbeTarget(ctx context.Context, host string) (TargetReport, error) // TLS 1.3, h2, X25519MLKEM768, сертификат
    Outbound(ctx context.Context, family Family) (Reachability, error)
}
```

- Внешний адрес: сначала по интерфейсам; за NAT — запрос к адресу из закрытого документированного
  списка; всегда переопределяется флагом `--address`.
- Стратегия выбора REALITY-цели — открытый вопрос Q3. Фаза 4.

### dns

Раздел `dns` конфигурации Xray и проверка резолвинга на сервере. Системный резолвер не меняет.

```go
type Manager interface {
    Plan(n NetFacts) DNSSettings                 // DoH-серверы, стратегия IPv4/IPv6
    Check(ctx context.Context) []Observation     // системный резолвер, DoH, расхождение ответов
}
```

- Запросы клиентов на `:53` внутри тоннеля отвечает встроенный DNS Xray через DoH. Фаза 4
  (`Plan`); `Check` — после MVP.

### security

Ключи, права, изоляция службы, аудит. Единственный источник случайных секретов.

```go
type Manager interface {
    NewRealityKeys(ctx context.Context) (RealityKeys, error)
    NewClientID() (string, error)
    NewShortID() (string, error)
    EnsureBaseline(ctx context.Context) error    // пользователь xray, владельцы и права по манифесту
    UnitHardening() []UnitOption                 // директивы изоляции systemd
    Audit(ctx context.Context) []Observation     // SSH, фаервол, права, обновления ОС — только чтение
}
```

- Манифест прав — одна таблица ([data-model.md](data-model.md) §1); `EnsureBaseline` приводит к
  ней, `Audit` сверяет.
- Изменение SSH и фаервола (`xm harden`) — отдельная команда с защитой от потери доступа,
  после MVP, отдельный ADR (вопрос Q7). Фаза 2 (ключи, права); аудит и усиление — после MVP.

### diag

Движок диагностики: реестр проверок, сбор наблюдений, анализ, отчёт, история.

```go
type Check interface {
    ID() string         // "xray.service.active", "net.v6.outbound", …
    Category() string   // xray | reach | ipv4 | ipv6 | dns | tls | conn | route | ssh | change | filter
    Run(ctx context.Context, env Env) []Observation
}

type Vantage interface { // точка наблюдения: сейчас local; позже probe (внешний узел), client
    ID() string
    Collect(ctx context.Context, sel Selector) ([]Observation, error)
}

type Engine interface {
    Run(ctx context.Context, sel Selector) (Report, error)
    History(limit int) []ReportMeta
    Import(obs []Observation) error  // наблюдения другой точки, тот же формат
}
```

- Анализ — правила «наблюдения → вывод» с классом `fact | probable | hypothesis`; модель и
  каталог проверок — [diagnostics.md](../operations/diagnostics.md).
- Отчёт всегда проходит `redact` перед сохранением и экспортом. Фаза 5 (минимум); полностью — после MVP.

### logging

Журнал самого `xm`, доступ к журналу Xray, раздел `log` конфигурации Xray.

```go
type Manager interface {
    Logger() *slog.Logger                              // всегда поверх redact
    XrayLog(ctx context.Context, q Query) (io.ReadCloser, error) // journald
    Settings() LogSettings                             // уровень; журнал доступа Xray выключен
}
```

- Хранилище — journald: без собственных файлов и ротации. Журнал доступа Xray выключен: в нём
  адреса клиентов. Фаза 2; `XrayLog` — фаза 5.

### update

Откуда брать релизы и что именно обновлять. Само переключение версии — транзакция `app`.

```go
type Source interface {  // единственная реализация: релизы GitHub XTLS/Xray-core
    Latest(ctx context.Context, ch Channel) (Release, error)
    Fetch(ctx context.Context, r Release, arch Arch) (zip io.ReadCloser, d Digests, err error)
}

type Manager interface {
    Check(ctx context.Context) (Available, error)       // есть ли новее, входит ли в проверенный диапазон
    Plan(ctx context.Context, target Version) (Plan, error)
}
```

- Проверка целостности, диапазон проверенных версий, откат — [updates.md](../operations/updates.md).
- Тем же механизмом обновляется сам `xm` (источник — релизы этого репозитория). Фаза 2 (установка),
  5 (обновление и откат).

### backup

Снимки состояния и восстановление.

```go
type Manager interface {
    Create(ctx context.Context, reason string) (Snapshot, error) // tar.gz + манифест SHA-256
    List() []Snapshot
    Verify(id string) error
    Read(id string) (Archive, error)   // с защитой от выхода путей из каталога
    Prune(p Policy) error
}
```

- В снимке: `state.json`, конфигурация Xray, версии `xm` и Xray, версия схемы. Снимок содержит
  секреты: права `0600`, каталог `0700`, за пределы VPS — только осознанной командой владельца.
- Автоснимок перед каждой транзакцией; хранение — [data-model.md](data-model.md) §4. Фаза 2
  (снимок и возврат для транзакции), 5 (команды, хранение, проверка).

### monitor

Периодические замеры и хронология. Работает разовым процессом по systemd-таймеру.

```go
type Manager interface {
    Sample(ctx context.Context) (Sample, error) // служба, ресурсы, счётчики трафика, итог лёгких проверок
    Append(Sample) error                        // ограниченный журнал JSONL
    Query(from, to time.Time) []Sample
    Transitions(from, to time.Time) []Transition // «было доступно → стало недоступно»
}
```

- Счётчики трафика — через подкоманду `xray api statsquery` к API на петле; включён только
  StatsService, учёт адресов клиентов не включается. После MVP.

---

## Прикладной слой

### app

Сценарии использования и транзакции. Единственный слой, который знает порядок шагов.

```go
type App interface {
    Install(ctx context.Context, o InstallOptions) (InstallResult, error)
    Uninstall(ctx context.Context, purge bool) error
    Status(ctx context.Context) (Status, error)
    Service(ctx context.Context, a Action) error            // start | stop | restart
    ProfileAdd(ctx context.Context, name string) (ProfileView, error)
    ProfileList(ctx context.Context) ([]ProfileSummary, error)
    ProfileShow(ctx context.Context, name string) (ProfileView, error)
    ProfileRemove(ctx context.Context, name string) error
    UpdateCheck(ctx context.Context) (UpdateInfo, error)
    Update(ctx context.Context, o UpdateOptions) (UpdateResult, error)
    Diagnose(ctx context.Context, sel Selector) (Report, error)
    Logs(ctx context.Context, q Query) (io.ReadCloser, error)
    BackupCreate(ctx context.Context) (Snapshot, error)
    BackupList(ctx context.Context) ([]Snapshot, error)
    Restore(ctx context.Context, id string) error
}
```

- Транзакция: блокировка → снимок → изменение → проверка → запись → перезапуск → контроль →
  фиксация или откат; незавершённая транзакция откатывается при следующем запуске.
- Возвращает типы `contract`; о терминале и HTTP не знает. Фаза 2 и далее.

---

## Интерфейсы

Адаптеры без логики: разобрать ввод, проверить его, вызвать `app`, показать результат.

### cli

Команды, флаги, вывод человеку или `--json`, коды выхода. Таблица команд —
[interfaces.md](interfaces.md) §1. Фаза 1 (каркас).

### api

Локальный HTTP API для Web UI: `/api/v1`, разовый токен → сессия, проверка `Host` и `Origin`.
Эндпоинты — [interfaces.md](interfaces.md) §3. После MVP.

### webui

Раздаёт встроенные статические файлы из `web/`. Логики нет. Требования к интерфейсу —
[interfaces.md](interfaces.md) §4. После MVP.

### bridge

Группа команд только для чтения для внешних инструментов (`xray_client`, внешние узлы): факты
сервера и наблюдения диагностики без секретов. Интерфейс — [interfaces.md](interfaces.md) §5.
После MVP, после анализа `xray_client`.
