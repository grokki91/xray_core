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
    Exec(ctx context.Context, c Command) (Result, error) // Command{Program, Args, Stdin}; без оболочки
    FS() FS            // ReadFile, WriteFile (temp + fchown + fchmod + fsync + rename), Mkdir, Remove, Symlink, Readlink, Lock (flock)
    Systemd() Systemd  // только xray.service: Running, Reload, Enable/Disable, Start/Stop/Restart, Status
    Net() Net          // Get по HTTPS, Listening — порт слушается (фаза 2); интерфейсы, маршруты — фаза 4
    Users() Users      // системный пользователь службы; Effective — владелец процесса xm
    Journal() Journal  // запись в journald, идентификатор xm (ADR-0022)
    Clock() Clock
}
```

- Команды — массивом аргументов, без `sh -c`; имя программы — из закрытого списка (имя → абсолютный
  путь; пополняется с первым потребителем); `xray` — только с `Command.Version` вида `N.N.N`, путь
  `CoreDir/<версия>/xray` строит `platform` ([ADR-0019](../adr/0019-versioned-xray-exec-and-current-link.md)); окружение процесса — только `PATH` и `LC_ALL=C`;
  ненулевой код выхода — не ошибка, а `Result.ExitCode`.
- Срок обязателен: `Exec` и `Lock` без дедлайна в контексте — ошибка `ErrDeadline`. Процесс
  запускается в своей группе: по сроку завершается вся группа. Вывод — не больше `MaxOutput`.
- `ReadFile` читает только обычный файл не больше `MaxFileSize` (64 МиБ: его задаёт архив Xray в кэше
  `update`, общий предел выбран владельцем 2026-11-16 вместо отдельного); `Mkdir` на существующем
  каталоге с другими правами или владельцем — ошибка, а не молчаливое исправление.
- Пути — только абсолютные и очищенные; символическая ссылка в любом элементе пути — ошибка
  `ErrSymlink`, кроме последнего элемента у `Symlink` (заменяется атомарно, цель — одно имя в том
  же каталоге) и `Readlink` (ADR-0019); `Remove` удаляет только обычный файл; бинарник `xray`
  запускается, только если путь к нему без ссылок и файл обычный (иначе `ErrSymlink`, `ErrNotFound`); файл создаётся сразу с правами и владельцем, без окна с чужими правами.
- Две реализации: настоящая (`New`) и поддельная (`NewFake`: файлы под временным каталогом,
  владельцы записываются, процессы отвечают обработчиками, вызовы записываются) — на ней идут
  тесты уровня L2 ([testing.md](../testing.md)). Работа с файлами у них общая, поэтому правила
  путей, ссылок и блокировок совпадают; общий тест это проверяет. Поддельная реализация лежит в
  самом пакете: подпакет `platform/fake` не мог бы импортировать `platform` по таблице слоёв;
  вызов `NewFake` вне `_test.go` запрещает тест границ. `Fake.RunUnderRoot(program)` запускает
  настоящий файл программы под корнем подделки путём `Real.Exec`, аргументы с ведущим `/` — под
  корнем ([ADR-0020](../adr/0020-l3-stand.md)).
- `platform/xraytest` — стенд L3, только для `_test.go`: `Versions()` (границы проверенного
  диапазона) и `Archive(t, get, версия)` — архив Xray с закреплённой SHA-256, кэш по версии;
  `get` — `Net.Get` настоящей реализации.
- `Net.Get(ctx, Request{URL, Hosts, Max})` — тело ответа 200: адрес и каждое перенаправление —
  только `https` и узел из закрытого списка потребителя (`Hosts`, точное совпадение с портом),
  иначе `ErrURL`; без учётных данных в адресе; не больше 5 перенаправлений; тело больше `Max` —
  `ErrTooLarge`; в ошибке — только узел, без параметров адреса; прокси — из окружения
  (`HTTPS_PROXY`), список сверяется с узлом назначения; срок обязателен. Поддельная сеть отвечает заданными телами и перенаправлениями
  (`Serve`, `Redirect`) по тем же правилам.
- `Net.Listening(ctx, port)` — слушает ли хост TCP-порт: строки `LISTEN` в `/proc/net/tcp` и `tcp6`
  (нет `tcp6` на хосте без IPv6 — не ошибка); соединений не открывает. `Clock.Sleep(ctx, d)` — ожидание
  до конца `ctx`; у подделки сдвигает часы ([ADR-0023](../adr/0023-transaction-control-and-rollback-scope.md)).
- `Users.Ensure(ctx, имя)` — владелец пользователя; нет такого — создаёт системного без оболочки и
  домашнего каталога через `useradd` из закрытого списка. Допустимо одно имя, `ServiceUser`
  (`xray`): политика §3 не разрешает менять других пользователей; иное имя — `ErrName`. Поддельные пользователи получают идентификаторы с 990.
- `Systemd` управляет одним юнитом `xray.service` (имя не параметр, как у `Users`): работает через
  `Exec` с `systemctl` из закрытого списка, одна реализация у `Real` и `Fake`; подделка отвечает на
  `Handle("systemctl", …)`. `Running` — `is-system-running`: `running` и `degraded` годятся, прочее —
  `ErrNoSystemd`. `Status` разбирает `systemctl show` строго: нет свойства или число не число — ошибка;
  юнита нет — `Loaded=false`, не ошибка. Ненулевой код глагола — ошибка с кодом, без вывода процесса.
- `Users.Effective()` — эффективные uid и gid процесса `xm`; у подделки root, пока тест не назначил
  другого (`SetEffective`).
- Фаза 1 — `Exec`, `FS`, `Clock`; фаза 2 — `Net.Get`, `xray` по версии, `Remove`, `Symlink`, `Readlink`, `Users`, `Systemd`;
  остальное `Net` — вместе с первым потребителем (фаза 4).

### store

Состояние `state.json`: загрузка, проверка схемы, миграции, атомарная запись, межпроцессная блокировка.

```go
type Store interface {
    Load() (State, error)                // ErrNoState, ErrSchema, ErrNewerSchema
    Save(State) error                    // только внутри транзакции
    Lock(ctx context.Context) (unlock func(), err error)
    WriteTx(Tx) error; ReadTx() (Tx, bool, error); ClearTx() error // журнал транзакции
    Restore(data []byte) error                                    // байты снимка как есть; nil — удалить
}
```

- Структура состояния и права — [data-model.md](data-model.md). Фаза 1.
- Загрузка: версия схемы → миграции по шагу N → N+1 на разобранном JSON → строгий разбор
  (неизвестное поле, лишние данные, неверный тип — ошибка) → документ обязан совпасть со своей
  записью из `State` (пропущенное поле, `null`, ключ в другом регистре, повтор ключа — ошибка)
  → правила содержимого (порт, адрес, хотя бы один входящий с ключами и shortId, список
  профилей). Состояние новее сборки — отказ «обновите xm». Мигрированное состояние пишет
  следующий `Save`.
- Журнал транзакции `/var/lib/xm/tx/pending.json`: снимок, прежние версия ядра, юнит, активность
  службы и порт; `WriteTx` не перезаписывает существующий. `Restore` схему не проверяет: снимок мог
  быть снят с повреждённого состояния ([ADR-0023](../adr/0023-transaction-control-and-rollback-scope.md)).
- Запись — `platform.FS.WriteFile` с `0600` и root; блокировка — `flock` файла `/run/xm/lock`
  (каталог создаётся при необходимости: `/run` — tmpfs).

### redact

Редактор чувствительных данных: реестр точных значений (ключи, UUID, адреса сервера из
состояния) плюс шаблоны (IP, UUID, ключи, URI-ссылки).

```go
type Redactor interface {
    Register(kind Kind, value string)   // точное значение → метка вида «<uuid:1>»
    Text(s string) string
    JSON(v any) (any, error)            // строки и ключи объектов — через Text
}
```

- Замена стабильна в пределах отчёта: одинаковое значение → одинаковая метка, чтобы отчёт
  оставался читаемым. Политика — [secrets.md](../security/secrets.md). Фаза 1.
- Порядок: ссылки `vless://` и подобные — первыми и целиком; затем зарегистрированные значения
  одним проходом (длинные первыми, без учёта регистра); затем шаблоны — UUID, публичные IPv6 и
  IPv4 (разбор `netip` каждого отрезка слова между двоеточиями; IPv4 с ведущими нулями тоже
  адрес; частные, петлевые и служебные адреса остаются), слова из 43 символов base64url или
  base64 с `=`. Короткое значение регистрируется наравне с длинным: лишняя замена безопаснее
  пропущенного секрета. Ключ, приклеенный к другим символам base64, шаблон не видит — его
  ловит только реестр.
- Регистрирует значения из состояния не `store` (ему `redact` недоступен), а слой выше — при
  первом потребителе (фаза 2).
- `redact/redacttest` — канареечный помощник тестов: `New` (узнаваемые фиктивные значения,
  ключи создаются в тесте) и `AssertClean` (ни одной канарейки в выводах).

### contract

Типы всех машинных выводов (CLI `--json`, HTTP API, мост) и общий конверт со схемой. Только
данные, без логики; импортируется всеми слоями. Правила версионирования — [interfaces.md](interfaces.md) §2. Фаза 1.

```go
type Data interface{ Schema() Schema }               // у каждой схемы — имя и версия
func New(xmVersion string, at time.Time, d Data) Envelope
func NewError(xmVersion string, at time.Time, e Error) Envelope
func Encode(w io.Writer, e Envelope) error           // один документ JSON
```

---

## Менеджеры

### core

Upstream-бинарник Xray на диске. Не знает, откуда берутся релизы (это `update`), и не знает
содержимого конфигурации (это `config`).

```go
type Manager interface {
    Current(ctx context.Context) (Version, error)                // активная версия; пусто — не установлено
    Stage(ctx context.Context, v Version, archive []byte) error  // распаковать xray в каталог версии, проверить
    Activate(ctx context.Context, v Version) error               // проверить версию, атомарно переключить current
    Validate(ctx context.Context, v Version, configPath string) error // xray run -test бинарником версии v
    Previous() (Version, bool)                                   // фаза 5
    Prune(keep int) error                                        // фаза 5
    Tool(ctx context.Context, v Version, sub Subcommand, args ...string) ([]byte, error) // сигнатура — с первым потребителем (api statsquery)
}
```

- Данные: `/usr/local/lib/xm/core/<версия>/xray`, ссылка `current`; хранятся две версии.
- Распаковка защищена от выхода из каталога: любой путь вне каталога, абсолютный или с `\`
  отвергает архив целиком; берётся только `xray` из корня архива, обычным файлом, не больше
  128 МиБ; файлов в архиве не больше 32. Проверяется, что бинарник — исполняемый ELF64 x86-64 и
  `xray version` называет ожидаемую версию; `Activate` повторяет проверку версии.
- Предусловие `Stage`: суммы архива сверены (`update.Fetch`) — `Stage` запускает бинарник; связку
  проверяет сценарий `app`. Выложенная версия не перезаписывается: другое содержимое — `ErrStaged`, тот же проверенный архив — успех без записи (повтор установки после отката); на неё может
  указывать `current`. Бинарник, не прошедший проверку, удаляется.
- Закрытый список подкоманд `core` — `version` и `run`; `x25519` и `uuid` не запускаются: секреты
  создаёт только `security`. Вывод `run -test` в ошибку не попадает — решение по коду выхода
  (23 — `ErrConfig`).
- Каталоги `/usr/local/lib/xm/`, `core/`, `core/<версия>/` создаёт `Stage`: ядро ставится до
  базовой защиты ([overview.md](overview.md) §6). Фаза 2.

### config

Строит конфигурацию Xray из состояния. Детерминированно: одно состояние → побайтно один файл.

```go
type Manager interface {
    Render(st store.State, log json.RawMessage) (Rendered, error) // log — раздел от logging
    Write(ctx context.Context, r Rendered) error  // атомарно, root:xray 0640
    Drift(st store.State) (bool, error)           // файл на диске ≠ applied.config_sha256
    Stage(r Rendered) (path string, err error)    // кандидат для `xray run -test` в каталоге транзакций
    Unstage() error; Remove() error               // убрать кандидата; убрать config.json при откате чистой установки
}

type Rendered struct { Data []byte; SHA256 string }  // SHA256 → applied.config_sha256

type Preset interface {  // каталог пресетов: config/preset
    ID() string                                   // например "reality-xhttp"
    Inbound(p Params) (json.RawMessage, error)
    Requires() Requirements                       // минимальная версия Xray, порт, нужна ли цель
}
```

- Собирает разделы:
  - `log` — готовый раздел передаёт `app` от `logging` (менеджеры друг друга не импортируют);
  - `dns` — из `state.dns`; пока `doh` пуст (до фазы 4), раздела нет;
  - `inbounds` — пресет и клиенты из `state.profiles`;
  - `outbounds`, `routing` — в том числе запрет частных и петлевых адресов назначения
    ([policy.md](../security/policy.md) §4; способ — [Q12](../open-questions.md)).
- В запрет не входят `100.64.0.0/10` (CGNAT) и `::ffff:0:0/96` (IPv4 в IPv6): политика их не требует,
  обработка второго в `ip`-правиле Xray не проверена. Цель REALITY проверяется по синтаксису;
  отказ от частных и петлевых целей — вместе с выбором цели (Q3, фаза 4).
- `Params` (порт, цель, имена, ключ, shortId, клиенты, опции) и `Requirements` (минимальная
  версия Xray, порт, нужна ли цель) — типы `config/preset`.
- Ручная правка файла — дрейф: `status` показывает его, следующее применение сохраняет
  изменённый файл в снимок и перезаписывает.
- Входящий в MVP один; в `clients` попадают только включённые профили. Ошибки отрисовки несут
  имена полей, не значения. Адреса назначения `0.0.0.0/8`, частные, петлевые и link-local
  уходят в `blackhole` правилом с `domainStrategy: IPOnDemand`.
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
    CheckRoot() (Issue, bool)                            // только root: для status, start, stop, restart
    InstallUnit(ctx context.Context, spec UnitSpec) error
    RemoveUnit(ctx context.Context) error
    Service() Service                                    // Start, Stop, Restart, Status, CheckRunning, CheckStopped
    Unit() ([]byte, error)                               // файл юнита как есть; нет — nil
    RestoreUnit(ctx context.Context, data []byte) error  // вернуть снятый юнит; nil — удалить свой
}
```

- Чужая установка — `xray.service` без метки `xm` или конфигурация Xray при отсутствии юнита `xm`:
  остановка с объяснением, код выхода 3. Метка — первая строка юнита `# managed-by: xm`; конфигурация
  JSON метки не несёт, поэтому своя установка всегда определяется юнитом с меткой.
- `New(p, configPath)` — путь конфигурации приносит `cmd/xm` (`config.Path`): менеджеры друг друга не
  импортируют. `Preflight` возвращает все найденные `Issue{Code, Message}` сразу, любая останавливает
  установку: `preflight.not_root`, `.os_unsupported` (Ubuntu 22.04 и 24.04; прочее — до решения Q8),
  `.arch_unsupported` (только x86_64; архитектура — `runtime.GOARCH` самого `xm`), `.resources`
  (память `MemTotal` не меньше 512 МиБ; порог — по замеру фазы 2; диск не проверяется — в порте нет
  вызова `statfs`), `.no_systemd`, `.clock` (часы раньше 2026-11-01), `.foreign_install`.
- Юнит строится из фиксированной части и директив изоляции, которые приносит вызывающий
  (`security.UnitHardening`); директива, переопределяющая запуск (`Type`, `User`, `ExecStart`,
  `Restart`, `RestartSec`), перевод строки в значении или путь вне `[A-Za-z0-9._/-]` — `ErrSpec`
  до всякой записи. `ExecStart` идёт через ссылку `current` (ADR-0019). `InstallUnit` пишет файл
  `root:root 0644`, `daemon-reload`, `enable`; службу не запускает. `RemoveUnit` — `disable`, удаление,
  `daemon-reload`; юнита нет — не ошибка; чужой юнит не трогают оба (`ErrForeign`).
- `Service()` — `Start`, `Stop`, `Restart`, `Status` (`platform.UnitStatus`: загружен, состояние,
  автозапуск, число перезапусков, PID). `CheckRunning(ctx, port)` — контроль после изменения: активна,
  `Restarts` не вырос от первого снимка контроля, порт слушается, повтор после выдержки; `CheckStopped` —
  неактивна и порт свободен. Срок — из `ctx`; провал — `ErrControl`
  ([ADR-0023](../adr/0023-transaction-control-and-rollback-scope.md), [ADR-0026](../adr/0026-restart-counter-from-baseline.md)).
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
    Audit(ctx context.Context) []Observation     // после MVP; SSH, фаервол, права, обновления ОС — только чтение
}
```

- Манифест прав — одна таблица ([data-model.md](data-model.md) §1); `EnsureBaseline` приводит к
  ней, `Audit` сверяет.
- Ключи REALITY — пара X25519 из `crypto/rand` (`crypto/ecdh`), base64 RawURL; открытый ключ
  совпадает с выводом `xray x25519 -i` (L3). Идентификатор клиента — UUID v4, shortId — 16
  шестнадцатеричных знаков.
- `EnsureBaseline` заводит пользователя `xray` и каталоги манифеста (владелец и права — при
  создании); существующий каталог с другими правами или владельцем — ошибка (`FS.Mkdir`), а не молчаливое
  исправление. Каталоги `core` и `cache` создают и их менеджеры (`core.Stage`, `update`): права те же,
  что в манифесте, а `Mkdir` на существующем каталоге ничего не меняет.
  Файлы манифеста создают их менеджеры сразу с нужными правами.
- `UnitHardening` — директивы §3 политики и `CapabilityBoundingSet`/`AmbientCapabilities` =
  `CAP_NET_BIND_SERVICE`; набор подтверждает L4 (шаг 11 фазы 2). `Audit` — после MVP, в коде нет.
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
    XrayLog(ctx context.Context, q Query) (io.ReadCloser, error) // journald; фаза 5
    Settings() Settings                                // уровень; журнал доступа Xray выключен
    XraySection() []byte                               // раздел log конфигурации Xray
}
```

- Хранилище — journald: без собственных файлов и ротации. Запись — `platform.Journal` с
  идентификатором `xm` ([ADR-0022](../adr/0022-journald-from-platform.md)); ошибка записи не
  заменяется выводом в stderr. Каждая запись целиком проходит `redact.Text` до `Journal`.
- Раздел `log` Xray — `{"access":"none","loglevel":"warning"}`: журнал доступа выключен, в нём
  адреса клиентов; ошибки идут в стандартный вывод юнита, то есть в journald. Фаза 2;
  `XrayLog` — фаза 5.

### update

Откуда брать релизы и что именно обновлять. Само переключение версии — транзакция `app`.

```go
type Source interface {  // единственная реализация GitHub: релизы XTLS/Xray-core
    Latest(ctx context.Context) (Release, error)                   // канал один — стабильные
    Fetch(ctx context.Context, r Release, a Arch) (Archive, error) // Archive{Data, Digests}, сверенный
}

type Manager interface {
    Check(ctx context.Context) (Available, error)       // есть ли новее, входит ли в проверенный диапазон
    Plan(ctx context.Context, target Version) (Plan, error)
}
```

- Проверка целостности, диапазон проверенных версий, откат — [updates.md](../operations/updates.md).
- `Fetch` скачивает `.dgst` каждый раз; архив берёт из кэша ([data-model.md](data-model.md) §1),
  если он читается и проходит ту же сверку, иначе скачивает и кладёт в кэш; каталоги кэша
  создаёт сам: загрузка идёт до базовой защиты ([overview.md](overview.md) §6). Предел архива —
  `platform.MaxFileSize`: кэш читается через `FS.ReadFile`. Архитектура — только `amd64`.
- Тем же механизмом обновляется сам `xm` (источник — релизы этого репозитория). Фаза 2 (установка),
  5 (обновление и откат). Реализация фазы 2 знает только `XTLS/Xray-core`; источник релизов `xm`
  (свой репозиторий, сверка SHA-256) добавляется в фазе 5.

### backup

Снимки состояния и восстановление.

```go
type Manager interface {
    Create(ctx context.Context, reason string, meta Meta) (Snapshot, error) // tar.gz + манифест SHA-256
    Read(ctx context.Context, id string) (Archive, error) // проверенное содержимое
    // фаза 5: List, Verify, Prune
}
```

- В снимке: `state.json`, конфигурация Xray, версии `xm` и Xray, версия схемы состояния. Снимок
  содержит секреты: права `0600`, каталог `0700`, за пределы VPS — только осознанной командой
  владельца.
- Идентификатор — `<UTC-время>-<причина>` (причина `[a-z0-9-]`, до 32 знаков); существующий снимок
  не перезаписывается; единственность обеспечивает блокировка транзакции в `app` (проверка и запись
  не атомарны), время точно до секунды. Повреждённое состояние снимается как есть. Файла, которого нет на диске (чистая установка), в снимке нет: `Read`
  возвращает его как `nil`; другая ошибка чтения прерывает снимок.
- `Read` проверяет архив целиком: имена записей — только `state.json`, `config.json`,
  `manifest.json` (пути из архива никуда не подставляются), предел размера записи, состав и
  SHA-256 по манифесту; иначе `ErrCorrupt`. Запись файлов обратно делает транзакция `app`
  (она знает владельцев по манифесту прав), не `backup`.
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

- Транзакция `Apply(ctx, Change)`: блокировка → базовая защита → откат незавершённой → отрисовка → снимок → журнал →
  `xray run -test` → ядро, юнит, конфигурация, состояние → перезапуск → контроль → фиксация или
  откат ([ADR-0005](../adr/0005-transactions-and-rollback.md), [ADR-0023](../adr/0023-transaction-control-and-rollback-scope.md)).
  Базовая защита (`security.EnsureBaseline`) — первый шаг после блокировки. Службу, которую
  владелец остановил, транзакция не запускает ([ADR-0025](../adr/0025-stopped-service-and-install-scenario.md)).
  Ошибки: `ErrRolledBack` (код 1) и `ErrRollbackFailed` (код 5). `Recover` откатывает незавершённую
  транзакцию при следующем запуске.
- Сценарии фазы 2 ([ADR-0025](../adr/0025-stopped-service-and-install-scenario.md)): `Install` —
  проверка ввода, предусловия, загрузка и сверка релиза, `core.Stage`, ключи, транзакция; `Service` —
  `start`, `stop`, `restart` под блокировкой, после отката незавершённой транзакции, с контролем, но не
  транзакцией; `Status` — служба, версии, адреса, порт, дрейф (схема `status`). Сроки операций задаёт
  `app`. Ошибки сценариев: `ErrInput` (код 2), `ErrPreflight` с перечнем причин, `ErrInstalled`,
  `ErrNotInstalled` (код 3). Остальные сценарии — следующие фазы.
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
