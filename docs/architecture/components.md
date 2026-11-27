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
    Start(ctx context.Context, c Command) (Process, error) // процесс в фоне ([ADR-0032](../adr/0032-selftest-client-and-l3-target.md)); Process{Done, Stop}
    Stream(ctx context.Context, c Command) (io.ReadCloser, error) // stdout потоком (ADR-0044)
    FS() FS            // ReadFile, WriteFile (temp + fchown + fchmod + fsync + rename), Mkdir, ReadDir, Remove, Symlink, Readlink, Lock (flock)
    Systemd() Systemd  // только xray.service: Running, Reload, Enable/Disable, Start/Stop/Restart, Status
    Net() Net          // Get по HTTPS, Listening — порт слушается (фаза 2); Addrs — адреса интерфейсов, TLSProbe — проверка TLS узла (фаза 4)
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
  же каталоге) и `Readlink` (ADR-0019); `Remove` удаляет только обычный файл или сокет Unix (след убитого клиента самопроверки); бинарник `xray`
  запускается, только если путь к нему без ссылок и файл обычный (иначе `ErrSymlink`, `ErrNotFound`); файл создаётся сразу с правами и владельцем, без окна с чужими правами.
- Две реализации: настоящая (`New`) и поддельная (`NewFake`: файлы под временным каталогом,
  владельцы записываются, процессы отвечают обработчиками, вызовы записываются) — на ней идут
  тесты уровня L2 ([testing.md](../testing.md)). Работа с файлами у них общая, поэтому правила
  путей, ссылок и блокировок совпадают; общий тест это проверяет. Поддельная реализация лежит в
  самом пакете: подпакет `platform/fake` не мог бы импортировать `platform` по таблице слоёв;
  вызов `NewFake` вне `_test.go` запрещает тест границ. `Fake.RunUnderRoot(program)` запускает
  настоящий файл программы под корнем подделки путём `Real.Exec`, аргументы с ведущим `/` — под
  корнем ([ADR-0020](../adr/0020-l3-stand.md)); `Fake.Start` так же запустит настоящий файл в фоне
  ([ADR-0032](../adr/0032-selftest-client-and-l3-target.md)).
- `platform/xraytest` — стенд L3, только для `_test.go`: `Versions()` (границы проверенного
  диапазона) и `Archive(t, get, версия)` — архив Xray с закреплённой SHA-256, кэш по версии;
  `get` — `Net.Get` настоящей реализации.
- `Net.Get(ctx, Request{URL, Hosts, Max})` — тело ответа 200: адрес и каждое перенаправление —
  только `https` и узел из закрытого списка потребителя (`Hosts`, точное совпадение с портом),
  иначе `ErrURL`; без учётных данных в адресе; не больше 5 перенаправлений; тело больше `Max` —
  `ErrTooLarge`; в ошибке — только узел, без параметров адреса; прокси — из окружения
  (`HTTPS_PROXY`), список сверяется с узлом назначения; срок обязателен; непустой `Token` —
  заголовок `Authorization: Bearer` только у первого запроса, перенаправления — без него
  ([ADR-0031](../adr/0031-github-api-token.md)); подделка отмечает его в `Call.Auth`. Поддельная сеть отвечает заданными телами, кодами и перенаправлениями
  (`Serve`, `ServeStatus`, `Redirect`) по тем же правилам. Поля `Request` ([ADR-0032](../adr/0032-selftest-client-and-l3-target.md)):
  `Proxy` — путь сокета Unix с HTTP-прокси (CONNECT; окружение тогда не действует; не абсолютный
  или не очищенный путь — `ErrPath`; подделка записывает его в `Call.Proxy`); `Status` — ожидаемый
  код ответа, по умолчанию 200, иной — ошибка.
- `Stream(ctx, Command)` — правила `Exec`, stdout потоком без предела, stderr отбрасывается;
  ненулевой код — `ErrExit` в конце чтения; `Close` убивает группу и ждёт. Подделка —
  `HandleStream(программа, обработчик)`; читатель с `Close` закрывается вместе с потоком. Программа `journalctl` — в закрытом списке (`logging`:
  только чтение, [ADR-0044](../adr/0044-journal-read-via-journalctl-stream.md)).
- `Start(ctx, Command)` — фоновый процесс по правилам `Exec` (закрытый список, без оболочки,
  окружение, своя группа, срок обязателен); `Stdin` подаётся целиком и закрывается, вывод
  отбрасывается. `Process.Done()` закрывается при завершении (сам, по сроку, по `Stop`);
  `Process.Stop()` убивает группу и ждёт, повтор безопасен. Подделка запускает настоящий файл под
  корнем и только после `RunUnderRoot`, иначе ошибка; `HandleStart(программа, обработчик)` — процесс без файла
  для L2 (живёт до `Stop` или срока контекста); вызов записывается как `start`. `ServeVia` задаёт
  ответ только на запрос через `Proxy`.
- `Net.Listening(ctx, port)` — слушает ли хост TCP-порт: строки `LISTEN` в `/proc/net/tcp` и `tcp6`
  (нет `tcp6` на хосте без IPv6 — не ошибка); соединений не открывает. `Clock.Sleep(ctx, d)` — ожидание
  до конца `ctx`; у подделки сдвигает часы ([ADR-0023](../adr/0023-transaction-control-and-rollback-scope.md)).
- `Net.Addrs(ctx)` — адреса интерфейсов (`IfAddr{Iface, Addr}`) без отбора; подделка — `SetAddrs`.
- `Net.TLSProbe(ctx, TLSRequest{Host, Port, Allow})` — одно TLS-соединение на первый адрес имени,
  допустимый по `Allow` (нет такого — `ErrNotAllowed` без соединения; время — TCP и TLS без DNS): TLS 1.3,
  ALPN h2, только группа X25519MLKEM768; `TLSInfo{Version, ALPN, Curve, Addr,
  CertErr, Handshake, Status, Location, HeadErr}`; после рукопожатия при ALPN h2 — один `HEAD /`
  с `Host` = имени, без `User-Agent`, по тому же соединению (HTTP/2 стандартной библиотеки, без перехода по
  перенаправлению, заголовки до 16 КиБ, тело не читается, срок 5 с в пределах общего), цепочка — системным
  пулом на имя (итог в `CertErr`); недопустимые узел или
  порт — `ErrURL`, срок обязателен; подделка — `SetTLS`.
  Программы `ss`, `ufw`, `iptables`, `ip6tables` — в закрытом списке (`network`: чтение; единственное изменение — правило UFW, [ADR-0041](../adr/0041-ufw-rule-in-install-transaction.md)).
- `Users.Ensure(ctx, имя)` — владелец пользователя; нет такого — создаёт системного без оболочки и
  домашнего каталога через `useradd` из закрытого списка. Допустимо одно имя, `ServiceUser`
  (`xray`): политика §3 не разрешает менять других пользователей; иное имя — `ErrName`. Поддельные пользователи получают идентификаторы с 990.
  `Users.Remove(ctx, имя)` — `userdel` того же единственного имени; нет пользователя — не ошибка
  (`uninstall --purge`, [ADR-0042](../adr/0042-uninstall-ordered-idempotent.md)).
- `FS.RemoveTree(путь)` — удаление дерева без перехода по ссылкам; ссылка на пути — `ErrSymlink`,
  путь короче двух элементов — `ErrPath`, нет пути — не ошибка. Корни задаёт `security.Remove` по
  манифесту.
- `Systemd` управляет одним юнитом `xray.service` (имя не параметр, как у `Users`): работает через
  `Exec` с `systemctl` из закрытого списка, одна реализация у `Real` и `Fake`; подделка отвечает на
  `Handle("systemctl", …)`. `Running` — `is-system-running`: `running` и `degraded` годятся, прочее —
  `ErrNoSystemd`. `Status` разбирает `systemctl show` строго: нет свойства или число не число — ошибка;
  юнита нет — `Loaded=false`, не ошибка. Ненулевой код глагола — ошибка с кодом, без вывода процесса.
- `Users.Effective()` — эффективные uid и gid процесса `xm`; у подделки root, пока тест не назначил
  другого (`SetEffective`).
- Фаза 1 — `Exec`, `FS`, `Clock`; фаза 2 — `Net.Get`, `xray` по версии, `Remove`, `Symlink`, `Readlink`, `Users`, `Systemd`; A4 — `ReadDir`;
  фаза 4 — `Net.Addrs`, `Net.TLSProbe`, `ss`, `ufw`, `iptables`, `ip6tables`.

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
состояния; токен API GitHub из окружения — вид `token`, [ADR-0031](../adr/0031-github-api-token.md)) плюс шаблоны (IP, UUID, ключи, URI-ссылки).

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
    ValidateCurrent(ctx context.Context, configPath string) error     // то же действующей версией (контроль)
    Prune(keep ...Version) error                                 // удалить каталоги версий N.N.N, кроме keep (активной и предыдущей)
    Tool(ctx context.Context, v Version, sub Subcommand, args ...string) ([]byte, error) // сигнатура — с первым потребителем (api statsquery)
}
```

- Данные: `/usr/local/lib/xm/core/<версия>/xray`, ссылка `current`; хранятся две версии.
- Распаковка защищена от выхода из каталога: любой путь вне каталога, абсолютный или с `\`
  отвергает архив целиком; берётся только `xray` из корня архива, обычным файлом, не больше
  128 МиБ; файлов в архиве не больше 32. Проверяется, что бинарник — исполняемый ELF64 x86-64 и
  `xray version` называет ожидаемую версию; `Activate` повторяет проверку версии.
- Предусловие `Stage`: суммы архива сверены (`update.Fetch`) — `Stage` запускает бинарник; связку
  проверяет сценарий `app`. Выложенная версия не перезаписывается: другое содержимое — `ErrStaged`, тот же проверенный архив — успех без записи (повтор установки после отката); бинарника версии нет на диске — `ErrNotStaged`; на неё может
  указывать `current`. Бинарник, не прошедший проверку, удаляется.
- Закрытый список подкоманд `core` — `version` и `run`; `x25519` и `uuid` не запускаются: секреты
  создаёт только `security`. Вывод `run -test` в ошибку не попадает — решение по коду выхода
  (23 — `ErrConfig`).
- Клиент самопроверки — метод `core` (`core.StartClient(ctx, cfg)`; конфигурация — `config.RenderClient`): `xray run`
  действующей версией от root, конфигурация — `-c stdin:`, процесс `platform.Start`; входящий
  `listen` — `<сокет>,0600`, рядом Xray создаёт `<сокет>.lock`; прежний сокет удаляется до запуска:
  Xray его не удаляет и не стартует; успех — ответ цели, а не `200` прокси на `CONNECT`
  ([compatibility.md](../compatibility.md) §2) ([ADR-0032](../adr/0032-selftest-client-and-l3-target.md)); фаза 3, шаг 7.
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
RenderClient(st store.State, id, socket string) (Rendered, error) // клиент самопроверки и L3 из состояния ([ADR-0032](../adr/0032-selftest-client-and-l3-target.md))

type Preset interface {  // каталог пресетов: config/preset
    ID() string                                   // например "reality-xhttp"
    Inbound(p Params) (json.RawMessage, error)
    Outbound(p ClientParams) (json.RawMessage, error) // исходящий клиента: те же значения, что в ссылке
    Requires() Requirements                       // минимальная версия Xray, порт, нужна ли цель
}
```

- Собирает разделы:
  - `log` — готовый раздел передаёт `app` от `logging` (менеджеры друг друга не импортируют);
  - `dns` — из `state.dns` (`servers`, `queryStrategy`); пока `doh` пуст, раздела нет;
  - `inbounds` — пресет и клиенты из `state.profiles`;
  - `outbounds`, `routing` — `freedom` первым (получает всё, что не поймали правила), `blackhole`
    (`block`) и при разделе `dns` — исходящий `dns` (`dns-out`). `routing` есть всегда: при разделе
    `dns` первое правило — порт `53`, `tcp,udp` → `dns-out` ([ADR-0039](../adr/0039-client-dns-via-dns-outbound.md)), затем
    `protocol: bittorrent` → `block` ([ADR-0038](../adr/0038-client-egress-restrictions.md)). Запрет частных и петлевых адресов назначения
    ([policy.md](../security/policy.md) §4; способ — [ADR-0027](../adr/0027-private-destinations-via-final-rules.md)).
- В запрет не входят `100.64.0.0/10` (CGNAT) и `::ffff:0:0/96` (IPv4 в IPv6): политика их не требует,
  обработка второго в `ip`-правиле Xray не проверена. Цель REALITY проверяется по синтаксису;
  отказ от частных и петлевых целей — вместе с выбором цели ([ADR-0035](../adr/0035-reality-target-candidates.md), фаза 4).
- `Params` (порт, цель, имена, ключ, shortId, клиенты, опции) и `Requirements` (минимальная
  версия Xray, порт, нужна ли цель) — типы `config/preset`.
- Ручная правка файла — дрейф: `status` показывает его, следующее применение сохраняет
  изменённый файл в снимок и перезаписывает.
- Входящий в MVP один; в `clients` попадают только включённые профили и служебный клиент
  самопроверки (`selftest.id`, если он задан).
- `RenderClient` — конфигурация клиента самопроверки из состояния, тот же источник, что у ссылки
  профиля: входящий `http` на сокете Unix `<сокет>,0600` без порта, исходящий — `vless` к первому
  из адресов «домен, IPv4, IPv6» с `Outbound` пресета (fp `chrome`, flow пустой, mode `auto`);
  журнал `none`. Сокет — абсолютный очищенный путь без `,` и `@`; пустой или не UUID `id`,
  нет входящего или адреса — `ErrState`. Разборщика ссылок нет: L3 сверяет параметры ссылки с
  параметрами клиента. Ошибки отрисовки несут
  имена полей, не значения. Адреса назначения `0.0.0.0/8`, частные, петлевые и link-local
  блокирует `settings.finalRules` исходящего `freedom` (`action: block`), в том числе для DoH самого
  Xray (схема `https://` идёт через `freedom`); к исходящему `dns` finalRules не применяются — его правила без `direct` ([ADR-0039](../adr/0039-client-dns-via-dns-outbound.md)). Там же первым правилом —
  `tcp:25` любого адреса; BitTorrent — правило маршрутизации `protocol: bittorrent` в `blackhole`,
  для чего у входящего `sniffing` с `routeOnly` ([ADR-0038](../adr/0038-client-egress-restrictions.md)).
- Проверка — `core.Validate` перед записью. Набор полей сверяется с upstream по скилу
  `xray-upstream`. Фаза 2.

### profile

Клиентские профили и всё, что отдаётся клиентам.

```go
type Manager interface {  // над store.State, без записи: изменение проводит транзакция app
    Add(st store.State, name, id string, now time.Time) (store.State, store.Profile, error)
    List(st store.State) []store.Profile          // в порядке создания
    Get(st store.State, name string) (store.Profile, error)
    Remove(st store.State, name string) (store.State, error)
    // имя по правилу и compat.Check(client, e.Preset) — до экспортёра
    Export(p store.Profile, e export.Endpoint, client string, x export.Exporter) (export.Artifact, error)
    // ссылки на каждый адрес сервера (домен, IPv4, IPv6), QR одного из них, клиенты, которым
    // ссылка не подойдёт; client и address необязательны
    Share(st store.State, name, client, address string) (Share, error)
    Clients(st store.State) []ClientInfo   // таблица совместимости для пресета и ядра сервера
    NextName(st store.State) string        // profile-N для `xm add` без имени
}

type Exporter interface {  // profile/export — единственное место форматов клиентов
    Format() string                        // "uri", "qr"; файл sing-box — после MVP
    Export(p store.Profile, e Endpoint) (Artifact, error)
}

// profile/compat — таблица данных с датой и источником
func Clients(presetID, core string) []ClientSupport  // core — версия Xray сервера N.N.N; ниже 26.9.9 — nil
func Check(client, presetID string) error            // ErrIncompatible с причиной; ErrUnknown
```

- Имя профиля: `[a-z0-9][a-z0-9_-]{0,31}`; оно же — метка в URI. Идентификатор клиента — UUID v4
  от `security.NewClientID`; передаёт его `app` (менеджеры друг друга не импортируют). Ошибки:
  `ErrInput` (имя, идентификатор, повтор идентификатора), `ErrExists`, `ErrNotFound`; в ошибках нет
  идентификатора. Профиль создаётся включённым. Фаза 3, шаг 2.
- `Endpoint` — адрес (IPv4, IPv6 без скобок и зоны, домен), порт и параметры пресета явными
  полями (`Preset`, `SNI`, `PublicKey`, `ShortID`, `Path`); один профиль экспортируется для
  каждого адреса сервера. `Artifact` — `Format` и `Text`. Ошибки `ErrInput`, `ErrPreset` — без
  значений ввода.
- Формат `uri` — ссылка `vless://` для `reality-xhttp`: фиксированный порядок параметров,
  `fp=chrome`, без `flow`, `mode=auto`; значения и имя после `#` — %-кодирование без `+`; IPv6 —
  в `[]`. Имя профиля проверяет `profile` до вызова; экспортёр его только кодирует. Фаза 3, шаг 3.
- `profile/compat` — строки клиентов из [compatibility.md](../compatibility.md) §3 для
  `reality-xhttp`; ID клиентов: `v2rayn`, `v2rayng`, `hiddify-5`, `hiddify-4`, `sing-box`. Тест
  сверки читает `compatibility.md` §3 и падает при расхождении имени, ядра или «да»/«нет».
  Экспорт под пресет, который клиент не поддерживает, — ошибка `Check` с причиной из таблицы, а
  не «приблизительная» ссылка: `profile.Manager.Export` вызывает `Check` до экспортёра. `export`
  и `compat` друг друга не импортируют; ID пресета приходит в `Endpoint.Preset` от `app`, их
  константы — только проверка. Фаза 3, шаг 4.
- `Share` берёт параметры ссылки из состояния (первое входящее: `server_names[0]`, `public_key`,
  `short_ids[0]`, `params.path`, порт сервера) и строит `uri` на каждый заданный адрес. `client`
  задан — совместимость проверяется до построения: `ErrIncompatible` с причиной из таблицы без
  ссылок, `ErrUnknownClient` — ошибка ввода. `client` пуст — ссылки строятся, а клиенты, которым
  они не подойдут, возвращаются в `Unfit` (предупреждение, не ошибка). `address` вне адресов
  сервера — `ErrInput`; пуст — QR первого адреса. Фаза 3, шаг 6.
- Формат `qr` — QR-код для терминала (`rsc.io/qr`, [ADR-0028](../adr/0028-qr-library-and-selftest-address.md)): строит ссылку экспортёром `uri` и рисует её, другого источника нет; отказ ссылки — отказ QR. Две строки модулей — одна строка терминала (`▀ ▄ █`), поле тишины 4 модуля, чёрное на белом задано явно (не зависит от темы терминала), уровень коррекции L. Фаза 3, шаг 5.

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
- `Service()` — `Start`, `Stop`, `Restart`, `Listening(ctx, port)` (один замер порта), `Status` (`platform.UnitStatus`: загружен, состояние,
  автозапуск, число перезапусков, PID). `CheckRunning(ctx, port)` — контроль после изменения: активна,
  `Restarts` не вырос от первого снимка контроля, порт слушается, повтор после выдержки; `CheckStopped` —
  неактивна и порт свободен. Срок — из `ctx`; провал — `ErrControl`
  ([ADR-0023](../adr/0023-transaction-control-and-rollback-scope.md), [ADR-0026](../adr/0026-restart-counter-from-baseline.md)). После `CheckRunning` контроль транзакции продолжает набор `control`
  движка `diag` (`app.control`, [ADR-0024](../adr/0024-health-verdict-and-shared-checks.md)).
- Расширение «несколько VPS»: реестр узлов (алиас SSH, без учётных данных) и исполнитель,
  вызывающий на узле тот же `xm … --json`. Фаза 2; реестр — после MVP.

### network

Сетевые факты и проверки. Только читает.

```go
type Manager interface {
    Facts(ctx context.Context, r Request) (Facts, error) // Request{Address, Port}: адреса IPv4/IPv6, внешний адрес, фаервол для Port
    PortFree(ctx context.Context, port int) (bool, Holder, error) // Holder{Name, PID}, пустой — не определено
    ProbeTarget(ctx context.Context, host string) (TargetReport, error) // TLS 1.3, h2, X25519MLKEM768, сертификат
    Outbound(ctx context.Context, family Family) (Reachability, error)
}
```

- Адреса интерфейсов — `Net.Addrs`; публичный — глобальный одноадресный, не частный (RFC 1918,
  ULA), не CGNAT `100.64.0.0/10`; петлевые и link-local — не публичные.
- Внешний адрес — по семействам раздельно (`Facts.V4`, `Facts.V6`, источник `interface`, `trace`
  или `flag`): публичный адрес интерфейса; нет его — `GET /cdn-cgi/trace` к `1.1.1.1` или
  `[2606:4700:4700::1111]` ([dependencies.md](../dev/dependencies.md) §5), поле `ip`, ответ того же
  семейства и публичный; неудача — «не определён» с причиной (`Note`), не ошибка.
  `Request.Address` (`--address`) — публичный адрес; задан — внешние узлы не опрашиваются, у
  другого семейства адреса нет.
- `PortFree` — занятость по `Net.Listening`; владелец — из `ss -Htlnp`, не ответил — пустой `Holder`.
- Локальный фаервол (`Facts.Firewall`, задача A3): `allowed`, `denied` или `unknown`. UFW активен
  (`ufw status verbose`) — первое правило порта с источником `Anywhere`, без правила — политика
  входящих; правило с ограничением источника — `unknown`. UFW не активен или нет — `iptables -S INPUT` и `ip6tables -S INPUT` (Source
  `iptables`): в обоих семействах политика `ACCEPT` и у правил только цели `ACCEPT`, `RETURN`, `LOG` —
  `allowed`; политика `DROP`, иная цель (`DROP`, `REJECT`, переход `-j цепочка` или `-g`) — `unknown` (запрет не доказан, `denied` не
  выдаётся); незнакомый формат вывода, нет утилиты, сбой или срок — `unknown`, причина в `Note`.
  Срок ufw — `unknown`, иной сбой ufw — в `Note`. У trace, ufw, iptables, ip6tables, ss — свои сроки; имя владельца порта — только печатные символы без пробелов и кавычек.
  `allowed` — только локально: фаервол хостера с сервера не виден. Ничего не меняет
  ([ADR-0036](../adr/0036-install-changes-only-own.md)).
- Цель REALITY ([ADR-0035](../adr/0035-reality-target-candidates.md)): `ProbeTarget(ctx, host)` —
  имя домена (не IP), одно соединение `Net.TLSProbe` к `host:443` на первый публичный адрес имени (`Allow: public`;
  публичного нет — соединения нет, `address` не прошёл), свой срок
  10 с; `TargetReport{Host, Addr, Handshake, Checks}` — критерии `tls13`, `h2`, `x25519mlkem768`
  (клиент предлагает только эту группу), `certificate` (цепочка системным пулом на имя),
  `address` (адрес соединения публичный — правило выше), `redirect` (ответ на `HEAD /` не 3xx
  или 3xx с `Location` — путь с одним ведущим `/` или `https` на то же имя, `\` — провал, в
  причине не больше 256 байт; нет ответа — «не проверено»;
  [ADR-0040](../adr/0040-reality-target-root-redirect.md)), у непрошедшего — причина; провал
  соединения — все критерии не прошли с его причиной. `SelectTarget(ctx, sni)`: `sni` задан —
  только он, провал — ошибка; иначе все `Candidates()` (закрытый список из 9 имён) параллельно
  с общим сроком 15 с, выбор прошедшего с наименьшим `Handshake`, при равенстве — раньше по
  списку; ни один не прошёл — ошибка с причиной по каждому и подсказкой `--sni`. Связь с
  `xm install` и сохранение в `target` — `app.Install` ([ADR-0035](../adr/0035-reality-target-candidates.md)).
- Правило UFW ([ADR-0041](../adr/0041-ufw-rule-in-install-transaction.md)) — единственное
  изменение системы в `network`: `AllowPort(ctx, port)` — `ufw allow <порт>/tcp`,
  `RevokePort(ctx, port)` — `ufw delete allow <порт>/tcp` (правила нет — не ошибка).
  `Firewall.CanAllow` — UFW активен, порт закрыт политикой по умолчанию, правила для порта нет.
  Вызывает только транзакция `app`.

### dns

Раздел `dns` конфигурации Xray и проверка резолвинга на сервере. Системный резолвер не меняет.

```go
func Plan(n NetFacts) store.DNS                  // DoH-серверы, стратегия IPv4/IPv6 → state.dns

type Manager interface {                         // после MVP
    Check(ctx context.Context) []Observation     // системный резолвер, DoH, расхождение ответов
}
```

- Запросы клиентов на `:53` внутри тоннеля отвечает встроенный DNS Xray через DoH. `Check` — после MVP.
- `Plan` — функция пакета: `NetFacts{IPv4, IPv6}` (есть ли внешний адрес семейства; заполняет
  вызывающий из `network.Facts`) → `store.DNS`, пишется в `state.dns`. Серверы —
  закрытый список `https://1.1.1.1/dns-query`, `https://dns.quad9.net/dns-query`
  ([dependencies.md](../dev/dependencies.md) §5); схема `https://` (через маршрутизацию и `freedom`),
  не `https+local://`. `queryStrategy`: оба семейства — `UseIP`, только IPv6 — `UseIPv6`, иначе
  `UseIPv4`. `disableCache`, `disableFallback`, bootstrap не задаются; `domainStrategy` freedom не
  меняется. Фаза 4.
- Имя `dns.quad9.net` разрешает резолвер ОС (bootstrap в Xray нет, freedom `AsIs`). Вернёт он
  частный или петлевой адрес — finalRules `freedom` заблокируют этот DoH, и при отказе обоих
  серверов DNS клиентов перестанет отвечать: отказ, а не утечка.
- Исходящий `dns-out` — явные правила: `hijack` для `qType` `1,28` (A, AAAA — встроенному DNS),
  остальное — `return` с `rCode` 5 (REFUSED); на исходный адрес запроса ничего не уходит. L3
  `TestL3ClientDNSHijacked`: A и TXT через тоннель к слушателю порта DNS до него не доходят.

### security

Ключи, права, изоляция службы, аудит. Единственный источник случайных секретов.

```go
type Manager interface {
    NewRealityKeys(ctx context.Context) (RealityKeys, error)
    NewClientID() (string, error)
    NewShortID() (string, error)
    EnsureBaseline(ctx context.Context) error    // пользователь xray, владельцы и права по манифесту
    Remove(ctx context.Context, purge bool) error // удаление по манифесту (uninstall, ADR-0042)
    UnitHardening() []UnitOption                 // директивы изоляции systemd
    Audit(ctx context.Context) []Observation     // после MVP; SSH, фаервол, права, обновления ОС — только чтение
}
```

- Манифест прав — одна таблица ([data-model.md](data-model.md) §1); `EnsureBaseline` создаёт по
  ней недостающее, `Remove` удаляет, `Audit` сверяет. Удаление — здесь, а не у `core` и `backup`:
  владелец манифеста один, и корни для `uninstall` задаются одним списком рядом с ним
  ([ADR-0042](../adr/0042-uninstall-ordered-idempotent.md)).
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
  после MVP, отдельный ADR ([ADR-0036](../adr/0036-install-changes-only-own.md)). Фаза 2 (ключи, права); аудит и усиление — после MVP.

### diag

Движок диагностики: реестр проверок, сбор наблюдений, анализ, отчёт, история.

```go
type Check interface {
    ID() string         // "xray.service.active", …; категория — первая часть:
                        // xray | reach | ipv4 | ipv6 | dns | tls | conn | route | ssh | change | filter | host
    Requires() []string // проверки, без успеха которых эта не измеряет
    Run(ctx context.Context) []Observation
    Fact(o Observation) Finding // вывод fact по наблюдению fail: код, текст, влияние, действие
}

type Rule func(obs []Observation) []Finding // выводы probable и hypothesis

func New(checks []Check, sets map[string][]string, rules []Rule) (*Engine, error)
func (e *Engine) Run(ctx context.Context, set string) (Report, error) // Report.Health, Report.Cause()

type Vantage interface { // точка наблюдения: сейчас local; позже probe (внешний узел), client
    ID() string
    Collect(ctx context.Context, sel Selector) ([]Observation, error)
}
// позже: Engine.History(limit) и Engine.Import(obs) — наблюдения другой точки, тот же формат
```

- Измерения проверка получает через конструктор — интерфейсы потребителя, объявленные в `diag`;
  реализации от `server`, `core`, `config`, `profile` подставляет `app` (ADR-0024); проверки —
  файлы пакета `diag` ([ADR-0030](../adr/0030-diag-checks-in-package.md)).
- Самопроверка `reach.selftest` ([ADR-0032](../adr/0032-selftest-client-and-l3-target.md)): входит в
  `control`, только если заданы измерения (`ControlDeps.Selftest`, иначе набор из трёх проверок:
  контроль после отката, `xm status`, [ADR-0033](../adr/0033-selftest-only-in-change-control.md)); требует `reach.listen`. Прямой `GET` тестового адреса `cp.cloudflare.com/generate_204`
  с сервера: не прошёл — `skip` (не измерено, вердикт `unknown`, не вывод о фильтрации); прошёл —
  удаляется прежний сокет, запускается клиент из состояния (`SelftestDeps.Start`), и `GET` через его
  сокет (`Net.Get` с `Proxy`, код 204) повторяется каждые 200 мс до 15 с; `ok` — ответ получен;
  `fail` — окно вышло (факт `reach.selftest.failed`, `down`); `error` — клиент не запустился или
  завершился, сокет не убрать, срок контроля вышел. Транзакцию откатывают `fail` и `error`, а `skip` — нет. Клиент останавливается, сокет убирается.
  Измерения — `SelftestDeps{Host, Socket, Start}`: `Host` (`FS`, `Net`, `Clock`) и `Process` объявлены
  в `diag`, чтобы `app` не импортировал `platform`; подставляет `cmd/xm`.
- Время наблюдения и точка наблюдения (`vantage`) войдут в отчёт вместе со схемой `diag-report`;
  сейчас отчёт живёт только внутри процесса.
- Реестр проверяется в `New`: ID по правилу и без повторов;
  зависимость зарегистрирована раньше зависимой и входит в те же наборы; набор `control` есть.
  Нарушение — `ErrRegistry`.
- `Run` идёт по набору в порядке реестра. Зависимость не дала `ok` — проверка не запускается, её
  наблюдение — `skip` с причиной. Наблюдение без `limits` у `ok` и `fail`, `skip` и `error` без
  причины, неизвестное состояние, пустой результат, факт провала без влияния, истёкший срок —
  `error`, а не тихий успех. Факт даёт только проверка по своему `fail` ([ADR-0029](../adr/0029-facts-from-checks.md)); правило, вернувшее `fact`,
  `probable` без альтернатив или `hypothesis` без «подтвердит» и «опровергнет», — `ErrRule`.
- Вердикт `Health`: факт с влиянием `down` → `down`; `skip` или `error` проверки набора `control`
  → `unknown`; факт `degraded` → `degraded`; иначе `ok`. `Cause()` — первый факт `down`, иначе
  `degraded`: зависимые не запускаются, поэтому он без проваленных зависимостей.
- Анализ — правила «наблюдения → вывод» классов `probable | hypothesis`; факт строит проверка (ADR-0029); модель и
  каталог проверок — [diagnostics.md](../operations/diagnostics.md).
- Отчёт всегда проходит `redact` перед сохранением и экспортом. Движок, вердикт и набор `control` есть; поле `health` схемы `status` и строка вердикта в `install` и `status` есть, поле схемы `diag-report` — с отчётом фазы 5 ([ADR-0024](../adr/0024-health-verdict-and-shared-checks.md), задача A2 в [roadmap.md](../roadmap.md) §7); каталог — фаза 5; полностью — после MVP.

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
  адреса клиентов; ошибки идут в стандартный вывод юнита, то есть в journald. Фаза 2.
- `XrayLog(ctx, Query{Since, Follow})` — `journalctl` через `platform.Stream`: юнит Xray и
  идентификатор `xm`, строки «время UTC источник: сообщение», управляющие символы заменены,
  каждая строка — через `redact.Text`; неверный `Since` — `ErrSince` до запуска
  ([ADR-0044](../adr/0044-journal-read-via-journalctl-stream.md)). Данные установки регистрирует
  `app.Logs` чтением состояния до вызова.

### update

Откуда брать релизы и что именно обновлять. Само переключение версии — транзакция `app`.

```go
type Source interface {  // единственная реализация GitHub: релизы XTLS/Xray-core
    Latest(ctx context.Context) (Release, error)                   // канал один — стабильные
    Tag(ctx context.Context, version string) (Release, error)      // стабильный релиз v<version>
    Fetch(ctx context.Context, r Release, a Arch) (Archive, error) // Archive{Data, Digests}, сверенный
}

Verified() Range                                              // проверенный диапазон: Min, Max включительно
Choose(ctx, src, rg) (target, latest Release, err error)      // последняя стабильная в диапазоне
NewChecks(p).Save(Check) / Load() (Check, bool, error)        // итог последней проверки для status
```

- Выбор версии и итог проверки — [ADR-0043](../adr/0043-verified-range-and-update-check.md);
  сценарий `xm update` (выбор → загрузка → `core.Stage` → `xray run -test` новой версией на
  действующей конфигурации → транзакция `Change{Core}` → `core.Prune(новая, прежняя)`) — `app.Update`; `--rollback` — та же
  транзакция на `core.previous` без сети и без `Prune`; удалённый каталог версии — `core.ErrNotStaged`.
- Проверка целостности, диапазон проверенных версий, откат — [updates.md](../operations/updates.md).
- `NewGitHub(p, token)`: `token` — значение `XM_GITHUB_TOKEN`, его читает `cmd/xm` и
  регистрирует в редакторе (вид `token`), если `ValidToken`; `Latest` проверяет формат до сети и шлёт токен только в
  API, `Fetch` — без него ([ADR-0031](../adr/0031-github-api-token.md)).
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
    List(ctx context.Context) ([]Entry, error)            // все снимки, каждый проверен Read
    Prune(ctx context.Context, kind Kind, keep int) error // оставить keep самых новых вида kind
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
- Автоснимок перед каждой транзакцией; хранение — [data-model.md](data-model.md) §4: после
  фиксации транзакции `app` вызывает `Prune(AutoKeep)` (10); при незавершённой транзакции
  хранение не запускается, её снимок нужен откату. Сбой `Prune` — предупреждение в журнале:
  изменение уже зафиксировано. Порядок — по идентификатору; файлы не по правилу имени не
  трогаются. Вид снимка — по причине: `manual` — ручной (`xm backup`, хранение `ManualKeep`, 20),
  любая другая — автоматический; `Prune` удаляет только снимки своего вида.
- `List` показывает и повреждённый снимок — с причиной: владелец его видит, `restore` не примет.
- `xm restore <id>` — транзакция `app` с `Change.Restore`: состояние из проверенного архива
  (`store.Parse` — миграция и проверка, как у `Load`), конфигурация перерисовывается из него,
  версия ядра не меняется. Текущее состояние может быть повреждено — транзакция его не требует,
  а её автоснимок `restore` сохраняет как есть; откат возвращает те же байты и оставляет службу
  остановленной (порт прежнего состояния неизвестен). Состояния нет совсем — `app.not_installed`;
  порт снимка не равен текущему — отказ: правило UFW открыто для текущего. Причина `manual`
  зарезервирована за `xm backup`. Фаза 2 (снимок и возврат), 4 (хранение
  автоснимков, A4), 5 (команды, ручные снимки, список).

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
    ProfileAdd(ctx context.Context, name string, o ShareOptions) (ProfileView, error)  // name пусто — profile-N
    ProfileList(ctx context.Context) (contract.Profiles, error)
    ProfileShow(ctx context.Context, name string, o ShareOptions) (ProfileView, error)
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
  До отрисовки пустой `selftest.id` заполняется через `security.NewClientID` и регистрируется в
  редакторе ([ADR-0032](../adr/0032-selftest-client-and-l3-target.md)).
  Базовая защита (`security.EnsureBaseline`) — первый шаг после блокировки. Службу, которую
  владелец остановил, транзакция не запускает ([ADR-0025](../adr/0025-stopped-service-and-install-scenario.md)).
  Контроль (`app.control`, один срок `ControlTimeout`): `CheckRunning` — ожидание запуска, затем набор
  `control` движка `diag` — `xray.service.active`, `reach.listen` (требует службу), `xray.config.valid`
  (`xray run -test` действующей версией на действующей конфигурации) и `reach.selftest` (клиент из
  состояния — `config.RenderClient`, `core.StartClient`; `app` читает состояние с диска: к контролю
  оно записано, после отката восстановлено; `Services.Host` — платформа для измерений). Исход `fail` или `error` любой проверки набора —
  `server.ErrControl` с названием первопричины и действием, без значений измерений. Контроль идёт и после отката,
  но набором без самопроверки: не прошёл — `ErrRollbackFailed`. Самопроверка — только в контроле
  изменения ([ADR-0033](../adr/0033-selftest-only-in-change-control.md)); `xm status` и вердикт в `xm install` её не запускают. Движок собирается в `app` из менеджеров, порт —
  из состояния ([ADR-0030](../adr/0030-diag-checks-in-package.md)).
  Ошибки: `ErrRolledBack` (код 1) и `ErrRollbackFailed` (код 5). `Recover` откатывает незавершённую
  транзакцию при следующем запуске.
- Сценарии фазы 2 ([ADR-0025](../adr/0025-stopped-service-and-install-scenario.md)): `Install` —
  проверка ввода, предусловия, загрузка и сверка релиза, `core.Stage`, ключи, транзакция; `Service` —
  `start`, `stop`, `restart` под блокировкой, после отката незавершённой транзакции, с контролем, но не
  транзакцией; `Status` — служба, версии, адреса, порт, дрейф (схема `status`). Сроки операций задаёт
  `app`. Ошибки сценариев: `ErrInput` (код 2), `ErrPreflight` с перечнем причин, `ErrInstalled`,
  `ErrNotInstalled` (код 3). Остальные сценарии — следующие фазы.
- `Change.Edit` — изменение поверх текущего состояния, вычисляется под блокировкой транзакции
  ([ADR-0005](../adr/0005-transactions-and-rollback.md)): чтение и запись не разделены. `State` —
  для установки (`Create`), `Edit` — для изменения существующей; заданы оба — ошибка. Сценарии
  профилей фазы 3: `ProfileAdd`, `ProfileRemove` — транзакции через `Edit`; `ProfileList`,
  `ProfileShow` — чтение. `ProfileView` — схема `profile` (`contract.Profile`) и QR для терминала
  (в машинный документ не входит); `ProfileList` — схема `profiles`, без секретов. Все требуют
  root и установку; ошибки `profile` сводятся к `ErrInput` (код 2), кроме `ErrIncompatible`
  (код 1: аргументы верны, клиенту сервер не подходит). `ProfileAdd` строит ссылки внутри
  `Edit`: несовместимый клиент отказывает до изменения, профиль не создаётся. `Install` создаёт
  первый профиль `profile-1` в той же транзакции, `InstallResult.Profile` называет его, ссылки —
  `ProfileShow`. Сценарий `Install` фазы 4: параметры необязательны; порядок — ввод → root →
  откат незавершённой → установлена? (повтор: параметры сверяются с установкой, ничего не
  меняется, итог `Existing`) → предусловия → `network.Facts` (адреса обоих семейств, фаервол) →
  `PortFree` (занят — `preflight.port_busy`) → `SelectTarget` → релиз и ядро → ключи → состояние
  (`dns.Plan` по семействам адресов, `firewall.ufw_rule` по `CanAllow`) → транзакция. Внешний
  адрес не определён и не задан — `preflight.no_address`. Правило UFW — шаг транзакции после
  записи состояния; порт правила — в журнале транзакции, откат его снимает
  ([ADR-0041](../adr/0041-ufw-rule-in-install-transaction.md)). `Status` несёт число профилей и таблицу клиентов. Идентификаторы клиентов
  регистрируются в редакторе.
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
