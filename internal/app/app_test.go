package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/logging"
	"github.com/grokki91/xray_core/internal/network"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/profile"
	"github.com/grokki91/xray_core/internal/redact"
	"github.com/grokki91/xray_core/internal/security"
	"github.com/grokki91/xray_core/internal/server"
	"github.com/grokki91/xray_core/internal/store"
	"github.com/grokki91/xray_core/internal/update"
)

const (
	v1, v2 = "26.10.31", "26.11.9"
	port   = 443
)

// Значения собраны во время теста: в исходниках секретоподобных строк нет.
// 43 знака base64 RawURL, последний — «A», чтобы значение было ключом из 32 байт.
var secretKey = strings.Repeat("Z", 10) + "canary" + "CANARY" + strings.Repeat("9", 10) + strings.Repeat("Z", 10) + "A"

// armedFS — файловая система, которая один раз отказывает в записи по пути (после arm).
type armedFS struct {
	platform.FS
	path       string // запись по пути с этим началом
	removePath string // удаление этого пути
	exact      bool   // запись только по пути path, а не по началу
	armed      bool
}

func (a *armedFS) WriteFile(path string, data []byte, perm os.FileMode, o platform.Owner) error {
	if a.armed && (path == a.path || !a.exact && strings.HasPrefix(path, a.path)) {
		a.armed = false
		return errors.New("сбой записи (тест)")
	}
	return a.FS.WriteFile(path, data, perm, o)
}

func (a *armedFS) Remove(path string) error {
	if a.removePath != "" && path == a.removePath {
		a.removePath = ""
		return errors.New("сбой удаления (тест)")
	}
	return a.FS.Remove(path)
}

type armedPlatform struct {
	platform.Platform
	fs *armedFS
}

func (p armedPlatform) FS() platform.FS { return p.fs }

// sys — поддельная машина: systemctl с состоянием, xray с кодом проверки, порт по плану.
type sys struct {
	f   *platform.Fake
	fs  *armedFS
	app *App
	rel *fakeReleases
	reg *redact.Redactor

	active             bool
	failVerb           string // глагол systemctl, который отказывает
	listenPort         int    // порт, который «слушает» поддельный хост после запуска; ноль — port
	testExit           int    // код `xray run -test` до перезапуска службы
	controlExits       []int  // коды `run -test` после перезапуска (набор control), по одному на запуск; пусто — 0
	badVersion         string // версия, которую xray называет неверно
	restartListens     []bool // слушает ли порт после очередного перезапуска; пусто — слушает
	restarts, nRestart int
	startErr           error              // отказ запуска клиента самопроверки
	started            []platform.Command // запуски клиента самопроверки

	ufwStatus     string   // вывод `ufw status verbose`; по умолчанию UFW выключен
	ufwRules      []string // вызовы ufw, меняющие правила: «allow 443/tcp», «delete allow 443/tcp»
	ufwRevokeExit int      // код выхода ufw на снятие правила
	ufwExit       int      // код выхода ufw на добавление правила (снятие всегда проходит)
}

// ufwDenyByDefault — активный UFW, порт 443 закрыт политикой по умолчанию.
const ufwDenyByDefault = "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo Action From\n-- ------ ----\n22/tcp ALLOW IN Anywhere\n"

// selftestURL — тестовый адрес самопроверки (docs/dev/dependencies.md §5).
const selftestURL = "https://cp.cloudflare.com/generate_204"

// newSys — машина с готовой установкой: базовая защита выполнена, выложены две версии Xray,
// current указывает на первую.
func newSys(t *testing.T) *sys { return build(t, true) }

// newFresh — чистая Ubuntu: есть только то, что есть на любой машине.
func newFresh(t *testing.T) *sys { return build(t, false) }

func build(t *testing.T, installed bool) *sys {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"/etc/systemd/system", "/usr/lib", "/usr/local/bin", "/usr/local/lib", "/usr/local/etc", "/var/lib", "/run", "/proc"} {
		if err := os.MkdirAll(root+d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f := platform.NewFake(root, time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	s := &sys{f: f, rel: &fakeReleases{}}
	s.fs = &armedFS{FS: f.FS()}
	p := armedPlatform{f, s.fs}
	host := map[string]string{
		"/usr/lib/os-release": "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n",
		"/proc/meminfo":       "MemTotal:        2008064 kB\n",
	}
	for path, data := range host {
		if err := f.FS().WriteFile(path, []byte(data), 0o644, platform.Root()); err != nil {
			t.Fatal(err)
		}
	}
	if installed {
		if err := security.New(p).EnsureBaseline(ctx(t)); err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{v1, v2} {
			d := platform.CoreDir + "/" + v
			if err := os.MkdirAll(root+d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := f.FS().WriteFile(d+"/xray", []byte("не настоящий бинарник"), 0o755, platform.Root()); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.FS().Symlink(platform.CoreDir+"/current", v1); err != nil {
			t.Fatal(err)
		}
	}
	f.Handle("xray", func(c platform.Command) (platform.Result, error) {
		if c.Args[0] == "version" {
			name := c.Version
			if name == s.badVersion {
				name = "0.0.1"
			}
			return platform.Result{Stdout: []byte("Xray " + name + " (Xray, Penetrates Everything.) abc (go1.27.4 linux/amd64)\n")}, nil
		}
		if s.nRestart > 0 { // после перезапуска Xray проверяет действующую конфигурацию
			code := 0
			if len(s.controlExits) > 0 {
				code, s.controlExits = s.controlExits[0], s.controlExits[1:]
			}
			return platform.Result{ExitCode: code}, nil
		}
		return platform.Result{ExitCode: s.testExit}, nil
	})
	// Клиент самопроверки — процесс без файла; тестовый адрес отвечает 204 и напрямую, и через
	// сервер. Провал самопроверки задаёт тест: f.ServeVia(selftestURL, 502, nil).
	f.HandleStart("xray", func(c platform.Command) error {
		s.started = append(s.started, c)
		if s.startErr != nil {
			return s.startErr
		}
		return nil
	})
	f.ServeStatus(selftestURL, 204, nil)
	f.Handle("systemctl", func(c platform.Command) (platform.Result, error) {
		verb := c.Args[2]
		if verb == "is-system-running" {
			return platform.Result{Stdout: []byte("running\n")}, nil
		}
		if verb == s.failVerb {
			s.failVerb = "" // отказ одноразовый: откат должен мочь выполнить тот же глагол
			return platform.Result{ExitCode: 1}, nil
		}
		switch verb {
		case "show":
			_, err := os.Stat(f.Path(server.UnitPath))
			load := "not-found"
			if err == nil {
				load = "loaded"
			}
			act := "inactive"
			if s.active {
				act = "active"
			}
			sub := map[bool]string{true: "running", false: "dead"}[s.active]
			return platform.Result{Stdout: []byte(fmt.Sprintf("LoadState=%s\nActiveState=%s\nSubState=%s\nUnitFileState=enabled\nNRestarts=0\nMainPID=1\n", load, act, sub))}, nil
		case "restart", "start":
			listens := true
			if s.nRestart < len(s.restartListens) {
				listens = s.restartListens[s.nRestart]
			}
			s.nRestart++
			s.restarts++
			s.active = true
			f.SetListening(s.listen(), listens)
		case "stop":
			s.active = false
			f.SetListening(s.listen(), false)
		}
		return platform.Result{}, nil
	})
	// Фаервол и цель REALITY: чистый хост без UFW; example.com — годная цель.
	f.Handle(platform.UFW, func(c platform.Command) (platform.Result, error) {
		if c.Args[0] == "status" {
			return platform.Result{Stdout: []byte(s.ufwStatus)}, nil
		}
		s.ufwRules = append(s.ufwRules, strings.Join(c.Args, " "))
		if c.Args[0] == "allow" {
			return platform.Result{ExitCode: s.ufwExit}, nil
		}
		return platform.Result{ExitCode: s.ufwRevokeExit}, nil
	})
	s.ufwStatus = "Status: inactive\n"
	f.Handle(platform.IPTables, func(platform.Command) (platform.Result, error) {
		return platform.Result{Stdout: []byte("-P INPUT ACCEPT\n")}, nil
	})
	f.Handle(platform.IP6Tables, func(platform.Command) (platform.Result, error) {
		return platform.Result{Stdout: []byte("-P INPUT ACCEPT\n")}, nil
	})
	f.SetTLS("example.com", platform.TLSInfo{Version: tls.VersionTLS13, ALPN: "h2", Curve: tls.X25519MLKEM768,
		Addr: netip.MustParseAddr("198.51.100.20"), Handshake: 30 * time.Millisecond, Status: 200}, nil)
	reg := redact.New()
	s.reg = reg
	cfgPath := config.Path
	s.app = New(Services{
		Store: store.New(p.FS()), Backup: backup.New(p), Config: config.New(p), Core: core.New(p),
		Server: server.New(p, cfgPath), Logging: logging.New(p, reg, slog.LevelInfo), Profile: profile.New(),
		Network:  network.New(p),
		Security: security.New(p), Releases: s.rel, Self: update.NewSelf(p, ""), Checks: update.NewChecks(p), Redactor: regAdapter{reg},
		XM: "0.1.0", Now: f.Clock().Now, ControlTimeout: 150 * time.Millisecond, Host: p,
	})
	return s
}

func (s *sys) listen() int {
	if s.listenPort != 0 {
		return s.listenPort
	}
	return port
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func stateOf(profiles ...string) store.State {
	st := store.State{
		SchemaVersion: store.SchemaVersion,
		Server:        store.Server{Port: port, Addresses: store.Addresses{IPv4: "203.0.113.10"}},
		Inbounds: []store.Inbound{{
			Preset: "reality-xhttp",
			Reality: store.Reality{Target: "example.com:443", ServerNames: []string{"example.com"},
				PrivateKey: secretKey, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortIDs: []string{"0123456789abcdef"}},
			Params: map[string]string{"path": "/example"},
		}},
		Profiles: []store.Profile{},
	}
	for i, n := range profiles {
		st.Profiles = append(st.Profiles, store.Profile{Name: n, ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1), Enabled: true})
	}
	return st
}

var unit1 = &server.UnitSpec{Hardening: []server.UnitOption{{Key: "NoNewPrivileges", Value: "true"}}}
var unit2 = &server.UnitSpec{Hardening: []server.UnitOption{{Key: "NoNewPrivileges", Value: "true"}, {Key: "PrivateTmp", Value: "true"}}}

// snapshot — всё, что транзакция обязана возвращать: файлы, ссылка current, служба.
type snapshot struct {
	state, config, unit []byte
	current             string
	active              bool
	tx                  bool
}

func (s *sys) snap(t *testing.T) snapshot {
	t.Helper()
	read := func(p string) []byte {
		b, err := os.ReadFile(s.f.Path(p))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cur, _ := s.f.FS().Readlink(platform.CoreDir + "/current")
	_, txErr := os.Stat(s.f.Path(store.TxPath))
	return snapshot{read(store.StatePath), read(config.Path), read(server.UnitPath), cur, s.active, txErr == nil}
}

func (a snapshot) equal(b snapshot) bool {
	return bytes.Equal(a.state, b.state) && bytes.Equal(a.config, b.config) && bytes.Equal(a.unit, b.unit) &&
		a.current == b.current && a.active == b.active && a.tx == b.tx
}

func TestApplyCleanInstall(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	got := s.snap(t)
	if got.state == nil || got.config == nil || got.unit == nil || !got.active || got.tx {
		t.Fatalf("после установки: %+v", got)
	}
	st, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if drift, err := s.app.s.Config.Drift(st); err != nil || drift {
		t.Fatalf("applied.config_sha256 не совпал с файлом: %v %v", drift, err)
	}
	if st.Applied.At.IsZero() {
		t.Fatal("applied.at не заполнен")
	}
	// Снимок перед транзакцией лежит и читается.
	if _, err := os.Stat(s.f.Path(backup.Dir + "/20261116T120000Z-install.tar.gz")); err != nil {
		t.Fatalf("снимка нет: %v", err)
	}
}

// Служебный клиент самопроверки (ADR-0032): транзакция с пустым selftest.id создаёт его, он
// попадает в конфигурацию, но не в профили; следующая транзакция его не меняет.
func TestApplyCreatesSelftestClientOnce(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	st, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	id := st.Selftest.ID
	if id == "" || len(st.Profiles) != 1 {
		t.Fatalf("selftest.id %q, профилей %d", id, len(st.Profiles))
	}
	if cfg := string(s.snap(t).config); !strings.Contains(cfg, id) {
		t.Fatalf("служебного клиента нет в конфигурации:\n%s", cfg)
	}
	edit := func(st store.State) (store.State, error) { st.Profiles[0].Name = "tablet"; return st, nil }
	if err := s.app.Apply(ctx(t), Change{Reason: "rename", Edit: edit}); err != nil {
		t.Fatal(err)
	}
	again, err := s.app.s.Store.Load()
	if err != nil || again.Selftest.ID != id {
		t.Fatalf("после второй транзакции selftest.id %q, был %q: %v", again.Selftest.ID, id, err)
	}
}

// Самопроверка — часть контроля (ADR-0024, ADR-0032): клиент строится из сохранённого
// состояния, конфигурация идёт только через stdin, а провал откатывает транзакцию.
func TestApplyRunsSelftestFromStoredState(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	st, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.started) != 1 {
		t.Fatalf("клиент самопроверки запущен %d раз", len(s.started))
	}
	c := s.started[0]
	cfg := string(c.Stdin)
	if strings.Join(c.Args, " ") != "run -c stdin:" || !strings.Contains(cfg, st.Selftest.ID) ||
		!strings.Contains(cfg, "/run/xm/selftest.sock,0600") || strings.Contains(strings.Join(c.Args, ""), st.Selftest.ID) {
		t.Fatalf("команда %q, конфигурация клиента:\n%s", c.Args, cfg)
	}
}

func TestApplySelftestFailureRollsBack(t *testing.T) {
	for name, tune := range map[string]func(*sys){
		"запрос через сервер не прошёл": func(s *sys) { s.f.ServeVia(selftestURL, 502, nil) },
		"клиент не запустился":          func(s *sys) { s.startErr = errors.New("нет бинарника") },
	} {
		t.Run(name, func(t *testing.T) {
			s := newSys(t)
			before := s.snap(t)
			tune(s)
			err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1})
			if !errors.Is(err, ErrRolledBack) || !errors.Is(err, server.ErrControl) {
				t.Fatalf("err = %v, нужны ErrRolledBack и ErrControl", err)
			}
			if after := s.snap(t); !after.equal(before) {
				t.Fatalf("после отката система не совпала с исходной:\n%+v\n%+v", before, after)
			}
		})
	}
}

// ADR-0033: адрес недоступен с самого сервера — самопроверка skip, и это не провал контроля.
func TestApplySelftestSkipDoesNotRollBack(t *testing.T) {
	s := newSys(t)
	s.f.ServeStatus(selftestURL, 500, nil)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatalf("skip самопроверки откатил транзакцию: %v", err)
	}
	if len(s.started) != 0 {
		t.Errorf("клиент запущен при недоступном адресе: %d", len(s.started))
	}
}

// ADR-0033: самопроверка, падающая независимо от изменения, не делает откат неудачным, а
// контроль после отката и xm status её не запускают.
func TestSelftestOnlyInChangeControl(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	if len(s.started) != 1 {
		t.Fatalf("после установки клиент запущен %d раз", len(s.started))
	}
	if _, err := s.app.Status(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if len(s.started) != 1 {
		t.Errorf("xm status запустил клиент самопроверки")
	}
	s.f.ServeVia(selftestURL, 502, nil) // тоннель не работает независимо от изменения
	edit := func(st store.State) (store.State, error) { st.Profiles[0].Name = "tablet"; return st, nil }
	err := s.app.Apply(ctx(t), Change{Reason: "rename", Edit: edit})
	if !errors.Is(err, ErrRolledBack) || errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("err = %v, нужен ErrRolledBack: контроль отката без самопроверки", err)
	}
	if len(s.started) != 2 {
		t.Errorf("клиент запущен %d раз: нужен один запуск в контроле изменения, ни одного в откате", len(s.started)-1)
	}
	if _, err := s.app.Status(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if len(s.started) != 2 {
		t.Errorf("xm status запустил клиент самопроверки")
	}
}

// После каждой транзакции остаются AutoKeep последних автоснимков (docs/roadmap.md, A4).
func TestApplyPrunesAutoSnapshots(t *testing.T) {
	s := newSys(t)
	start := s.f.Clock().Now()
	for i := range backup.AutoKeep + 1 {
		s.f.SetNow(start.Add(time.Duration(i) * time.Minute))
		if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
			t.Fatal(err)
		}
	}
	if n := countSnapshots(t, s); n != backup.AutoKeep {
		t.Fatalf("снимков %d, нужно %d", n, backup.AutoKeep)
	}
	if _, err := os.Stat(s.f.Path(backup.Dir + "/20261116T120000Z-install.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("самый старый снимок не удалён: %v", err)
	}
	// Незавершённая транзакция: её снимок не удаляется, хранение не запускается.
	s.f.SetNow(start.Add(time.Hour))
	s.nRestart, s.restartListens = 0, []bool{false, false}
	if err := s.app.Apply(ctx(t), Change{Reason: "update", State: stateOf("phone", "laptop"), Unit: unit2}); !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("ждали ErrRollbackFailed, получено %v", err)
	}
	if _, err := os.Stat(s.f.Path(backup.Dir + "/20261116T130000Z-update.tar.gz")); err != nil {
		t.Fatalf("снимок незавершённой транзакции удалён: %v", err)
	}
	if n := countSnapshots(t, s); n != backup.AutoKeep+1 {
		t.Fatalf("при незавершённой транзакции снимков %d, нужно %d", n, backup.AutoKeep+1)
	}
}

// Сбой хранения после фиксации не превращает изменение в провал.
func TestApplyPruneFailureIsNotFailure(t *testing.T) {
	s := newSys(t)
	start := s.f.Clock().Now()
	for i := range backup.AutoKeep + 1 {
		s.f.SetNow(start.Add(time.Duration(i) * time.Minute))
		if i == backup.AutoKeep {
			s.fs.removePath = backup.Dir + "/20261116T120000Z-install.tar.gz"
		}
		if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
			t.Fatalf("транзакция %d: %v", i, err)
		}
	}
	if got := s.snap(t); got.tx {
		t.Fatal("журнал транзакции остался")
	}
	if n := countSnapshots(t, s); n != backup.AutoKeep+1 {
		t.Fatalf("снимков %d, нужно %d", n, backup.AutoKeep+1)
	}
}

func countSnapshots(t *testing.T, s *sys) int {
	t.Helper()
	ents, err := os.ReadDir(s.f.Path(backup.Dir))
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// Провал на каждом шаге оставляет исходное состояние (docs/roadmap.md, критерий фазы 2).
func TestApplyFailureAtEachStepRestoresOriginal(t *testing.T) {
	steps := map[string]struct {
		arm  func(s *sys)
		want string // фрагмент причины: сбой случился именно на этом шаге
	}{
		"проверка xray run -test":     {func(s *sys) { s.testExit = 23 }, "отверг конфигурацию"},
		"переключение ядра":           {func(s *sys) { s.badVersion = v2 }, "не называет эту версию"},
		"установка юнита":             {func(s *sys) { s.failVerb = "enable" }, "systemctl enable"},
		"запись конфигурации":         {func(s *sys) { s.fs.path, s.fs.armed = config.Path, true }, "конфигурация: запись"},
		"запись состояния":            {func(s *sys) { s.fs.path, s.fs.armed = store.StatePath, true }, "сбой записи"},
		"перезапуск":                  {func(s *sys) { s.failVerb = "restart" }, "systemctl restart"},
		"удаление кандидата":          {func(s *sys) { s.fs.removePath = config.CandidatePath }, "сбой удаления"},
		"контроль: порт закрыт":       {func(s *sys) { s.restartListens = []bool{false, true} }, "контроль не пройден"},
		"набор control: конфигурация": {func(s *sys) { s.controlExits = []int{23} }, "Xray не принимает действующую конфигурацию"},
	}
	for name, step := range steps {
		t.Run(name, func(t *testing.T) {
			s := newSys(t)
			if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
				t.Fatal(err)
			}
			before := s.snap(t)
			s.nRestart, s.restartListens = 0, nil
			step.arm(s)
			ch := Change{Reason: "update", State: stateOf("phone", "laptop"), Unit: unit2, Core: v2}
			err := s.app.Apply(ctx(t), ch)
			if !errors.Is(err, ErrRolledBack) {
				t.Fatalf("ждали ErrRolledBack, получено %v", err)
			}
			if !strings.Contains(err.Error(), step.want) {
				t.Fatalf("сбой не на ожидаемом шаге (%q): %v", step.want, err)
			}
			if after := s.snap(t); !before.equal(after) {
				t.Fatalf("исходное состояние не возвращено:\nдо    %+v\nпосле %+v", before, after)
			}
			if strings.Contains(err.Error(), secretKey) {
				t.Fatal("текст ошибки содержит секрет")
			}
		})
	}
}

func TestApplyCleanInstallFailureLeavesNothing(t *testing.T) {
	s := newSys(t)
	s.failVerb = "restart"
	err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1})
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v", err)
	}
	got := s.snap(t)
	if got.state != nil || got.config != nil || got.unit != nil || got.active || got.tx {
		t.Fatalf("после отката чистой установки остались следы: %+v", got)
	}
	if _, err := os.Stat(s.f.Path(config.CandidatePath)); err == nil {
		t.Fatal("файл-кандидат остался")
	}
}

func TestApplyRejectsBadStateBeforeAnyChange(t *testing.T) {
	s := newSys(t)
	bad := stateOf("phone")
	bad.Inbounds = nil
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: bad, Unit: unit1}); err == nil || errors.Is(err, ErrRolledBack) {
		t.Fatalf("ждали отказ до изменений, получено %v", err)
	}
	entries, _ := os.ReadDir(s.f.Path(backup.Dir))
	if len(entries) != 0 || s.snap(t).tx {
		t.Fatal("снимок или журнал созданы до проверки ввода")
	}
}

func TestApplyReasonIsChecked(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "Плохая причина", State: stateOf("phone"), Unit: unit1}); err == nil {
		t.Fatal("причина принята")
	}
	if s.snap(t).state != nil {
		t.Fatal("состояние записано при отказе на снимке")
	}
}

// Откат, не прошедший контроль, — код 5; журнал остаётся, следующий запуск откатывает снова.
func TestRollbackFailureKeepsJournalAndRecoverRetries(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	s.nRestart, s.restartListens = 0, []bool{false, false} // и изменение, и откат не поднимают порт
	err := s.app.Apply(ctx(t), Change{Reason: "update", State: stateOf("phone", "laptop"), Unit: unit2})
	if !errors.Is(err, ErrRollbackFailed) || errors.Is(err, ErrRolledBack) {
		t.Fatalf("ждали ErrRollbackFailed, получено %v", err)
	}
	if !s.snap(t).tx {
		t.Fatal("журнал удалён при проваленном откате")
	}
	// Любое следующее изменение сначала откатывает; пока откат не идёт — оно не начинается.
	s.nRestart, s.restartListens = 0, []bool{false}
	if err := s.app.Apply(ctx(t), Change{Reason: "again", State: stateOf("x"), Unit: unit1}); !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("при неудавшемся откате изменение началось: %v", err)
	}
	s.nRestart, s.restartListens = 0, nil
	recovered, err := s.app.Recover(ctx(t))
	if err != nil || !recovered {
		t.Fatalf("Recover: %v %v", recovered, err)
	}
	if after := s.snap(t); !before.equal(after) {
		t.Fatalf("исходное состояние не возвращено: %+v", after)
	}
}

// Незавершённая транзакция (процесс убит после журнала) откатывается при следующем запуске.
func TestRecoverAfterCrash(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	unitBytes, _ := s.app.s.Server.Unit()
	snap, err := s.app.s.Backup.Create(ctx(t), "update", backup.Meta{XM: "0.1.0", Xray: v1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.app.s.Store.WriteTx(store.Tx{Snapshot: snap.ID, CoreBefore: v1, UnitBefore: unitBytes, WasActive: true, PortBefore: port}); err != nil {
		t.Fatal(err)
	}
	// «Транзакция» успела испортить состояние и переключить ядро, затем процесс убит.
	if err := s.f.FS().WriteFile(store.StatePath, []byte("испорчено"), 0o600, platform.Root()); err != nil {
		t.Fatal(err)
	}
	if err := s.app.s.Core.Activate(ctx(t), v2); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.app.Recover(ctx(t))
	if err != nil || !recovered {
		t.Fatalf("Recover: %v %v", recovered, err)
	}
	if after := s.snap(t); !before.equal(after) {
		t.Fatalf("после отката: %+v", after)
	}
	if again, err := s.app.Recover(ctx(t)); err != nil || again {
		t.Fatalf("повторный Recover: %v %v", again, err)
	}
}

func TestRecoverDamagedJournalIsRollbackFailure(t *testing.T) {
	s := newSys(t)
	if err := s.f.FS().WriteFile(store.TxPath, []byte("не журнал"), 0o600, platform.Root()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.app.Recover(ctx(t)); !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("%v", err)
	}
}

// Канарейка: секрет состояния не попадает в журнал транзакции и в ошибки.
func TestCanaryNotInJournalOrErrors(t *testing.T) {
	s := newSys(t)
	s.testExit = 23
	err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1})
	if !errors.Is(err, ErrRolledBack) || strings.Contains(err.Error(), secretKey) {
		t.Fatalf("%v", err)
	}
	for _, j := range s.f.Journaled() {
		if strings.Contains(j.Message, secretKey) {
			t.Fatalf("секрет в журнале xm: %q", j.Message)
		}
	}
	if _, err := os.Stat(s.f.Path(store.TxPath)); err == nil {
		t.Fatal("журнал остался после отката")
	}
}

// До журнала ничего не изменено: сбой снимка или записи журнала — обычная ошибка, не откат.
func TestFailureBeforeJournalChangesNothing(t *testing.T) {
	for name, arm := range map[string]func(s *sys){
		"снимок":            func(s *sys) { s.fs.path, s.fs.armed = backup.Dir, true },
		"журнал транзакции": func(s *sys) { s.fs.path, s.fs.armed = store.TxPath, true },
	} {
		t.Run(name, func(t *testing.T) {
			s := newSys(t)
			if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
				t.Fatal(err)
			}
			before := s.snap(t)
			arm(s)
			err := s.app.Apply(ctx(t), Change{Reason: "update", State: stateOf("phone", "laptop"), Unit: unit2, Core: v2})
			if err == nil || errors.Is(err, ErrRolledBack) || errors.Is(err, ErrRollbackFailed) {
				t.Fatalf("ждали обычную ошибку до изменений, получено %v", err)
			}
			if after := s.snap(t); !before.equal(after) {
				t.Fatalf("система изменена до журнала: %+v", after)
			}
		})
	}
}

// Чужой юнит — отказ до снимка и журнала: его байты в журнал не попадают и откат невозможен.
func TestForeignUnitRefusedBeforeJournal(t *testing.T) {
	for name, unit := range map[string]*server.UnitSpec{"юнит не меняется": nil, "юнит меняется": unit1} {
		t.Run(name, func(t *testing.T) {
			s := newSys(t)
			foreign := "[Service]\nEnvironment=TOKEN=" + secretKey + "\n"
			if err := s.f.FS().WriteFile(server.UnitPath, []byte(foreign), 0o644, platform.Root()); err != nil {
				t.Fatal(err)
			}
			err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit})
			if !errors.Is(err, server.ErrForeign) {
				t.Fatalf("ждали ErrForeign, получено %v", err)
			}
			if s.snap(t).tx || s.snap(t).state != nil {
				t.Fatal("что-то записано до отказа")
			}
			if got, _ := os.ReadFile(s.f.Path(server.UnitPath)); string(got) != foreign {
				t.Fatal("чужой юнит изменён")
			}
		})
	}
}

// Секрет не остаётся ни в журнале транзакции, ни в файле-кандидате.
func TestCandidateAndJournalHoldNoSecret(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.f.Path(config.CandidatePath)); err == nil {
		t.Fatal("кандидат остался после успешной транзакции")
	}
	// Откат не удался — журнал остался на диске: в нём не должно быть секрета.
	s.nRestart, s.restartListens = 0, []bool{false, false}
	if err := s.app.Apply(ctx(t), Change{Reason: "update", State: stateOf("phone", "laptop"), Unit: unit2}); !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("%v", err)
	}
	j, err := os.ReadFile(s.f.Path(store.TxPath))
	if err != nil || bytes.Contains(j, []byte(secretKey)) {
		t.Fatalf("журнал: %v, секрет внутри: %v", err, bytes.Contains(j, []byte(secretKey)))
	}
	if info, err := os.Stat(s.f.Path(store.TxPath)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("права журнала: %v %v", info, err)
	}
}

// Откат проходит тот же набор control: действующая после отката конфигурация не принята — код 5.
func TestRollbackControlFailureIsRollbackFailed(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	s.nRestart, s.controlExits = 0, []int{23, 23} // и изменение, и откат
	err := s.app.Apply(ctx(t), Change{Reason: "update", State: stateOf("phone", "laptop"), Unit: unit2})
	if !errors.Is(err, ErrRollbackFailed) || errors.Is(err, ErrRolledBack) {
		t.Fatalf("ждали ErrRollbackFailed, получено %v", err)
	}
	if !strings.Contains(err.Error(), "после отката") || !s.snap(t).tx {
		t.Fatalf("откат не прошёл контроль набора, журнал сохранён: %v", err)
	}
}

// Служба и порт в порядке, конфигурацию Xray не принимает — изменение не фиксируется, и это
// видно только набору control: контроль запуска такого не измеряет.
func TestApplyControlSetRunsAfterRunningCheck(t *testing.T) {
	s := newSys(t)
	s.controlExits = []int{23}
	s.nRestart = 0
	err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1})
	if !errors.Is(err, ErrRolledBack) || !errors.Is(err, server.ErrControl) {
		t.Fatalf("%v", err)
	}
	if s.snap(t).active {
		t.Fatal("служба осталась запущенной после отката чистой установки")
	}
}

// Порт набора control — из состояния, а не константа: сервер на другом порту проходит контроль.
func TestApplyControlUsesStatePort(t *testing.T) {
	s := newSys(t)
	s.listenPort = 8443
	st := stateOf("phone")
	st.Server.Port = 8443
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: st, Unit: unit1}); err != nil {
		t.Fatal(err)
	}
}
