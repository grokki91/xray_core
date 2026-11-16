package app

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/server"
	"github.com/grokki91/xray_core/internal/store"
	"github.com/grokki91/xray_core/internal/update"
)

// fakeReleases — источник релизов: тег и архив задаёт тест; считает обращения.
type fakeReleases struct {
	tag                  string
	archive              []byte
	latestErr            error
	latestCalls, fetches int
}

func (r *fakeReleases) Latest(context.Context) (update.Release, error) {
	r.latestCalls++
	return update.Release{Tag: r.tag}, r.latestErr
}

func (r *fakeReleases) Fetch(context.Context, update.Release, update.Arch) (update.Archive, error) {
	r.fetches++
	return update.Archive{Data: r.archive}, nil
}

// elf64 — заголовок исполняемого ELF64 x86-64: больше `core.Stage` от бинарника не требует до
// запуска, а запуск подменён обработчиком xray.
func elf64() []byte {
	h := make([]byte, 64)
	copy(h, "\x7fELF")
	h[4], h[5], h[6] = 2, 1, 1                // 64 бита, little-endian, версия 1
	binary.LittleEndian.PutUint16(h[16:], 2)  // ET_EXEC
	binary.LittleEndian.PutUint16(h[18:], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint16(h[52:], 64) // e_ehsize
	return h
}

func release(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	hd := &zip.FileHeader{Name: "xray", Method: zip.Deflate}
	hd.SetMode(0o755)
	fw, err := w.CreateHeader(hd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(elf64()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fresh — чистая машина и источник с релизом v2.
func fresh(t *testing.T) *sys {
	s := newFresh(t)
	s.rel.tag, s.rel.archive = "v"+v2, release(t)
	return s
}

var okOpts = InstallOptions{SNI: "example.com", Address: "203.0.113.10", Port: 443}

func TestInstallFreshMachine(t *testing.T) {
	s := fresh(t)
	res, err := s.app.Install(ctx(t), okOpts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Xray != v2 || res.Port != 443 || res.Address != "203.0.113.10" {
		t.Fatalf("итог: %+v", res)
	}
	got := s.snap(t)
	if got.state == nil || got.config == nil || got.unit == nil || !got.active || got.tx || got.current != v2 {
		t.Fatalf("после установки: %+v", got)
	}
	st, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	in := st.Inbounds[0]
	if st.Server.Port != 443 || st.Server.Addresses.IPv4 != "203.0.113.10" || in.Preset != "reality-xhttp" ||
		in.Reality.Target != "example.com:443" || len(in.Reality.ServerNames) != 1 || in.Reality.ServerNames[0] != "example.com" ||
		in.Reality.PrivateKey == "" || in.Reality.PublicKey == "" || len(in.Reality.ShortIDs) != 1 || len(st.Profiles) != 0 {
		t.Fatalf("состояние: %+v", st)
	}
	if drift, err := s.app.s.Config.Drift(st); err != nil || drift {
		t.Fatalf("дрейф сразу после установки: %v %v", drift, err)
	}
	if !listens(t, s, 443) {
		t.Fatal("порт не слушается")
	}
	// Итог печатается человеку: ключей в нём нет.
	doc, _ := json.Marshal(res)
	if strings.Contains(string(doc), in.Reality.PrivateKey) || strings.Contains(string(doc), in.Reality.PublicKey) {
		t.Fatalf("в итоге ключ: %s", doc)
	}
}

func TestInstallAddressKinds(t *testing.T) {
	cases := map[string]store.Addresses{
		"203.0.113.10":    {IPv4: "203.0.113.10"},
		"2001:db8::10":    {IPv6: "2001:db8::10"},
		"vpn.example.org": {Domain: "vpn.example.org"},
	}
	for addr, want := range cases {
		s := fresh(t)
		o := okOpts
		o.Address = addr
		if _, err := s.app.Install(ctx(t), o); err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		st, err := s.app.s.Store.Load()
		if err != nil || st.Server.Addresses != want {
			t.Fatalf("%s: адреса %+v, ошибка %v", addr, st.Server.Addresses, err)
		}
	}
}

// Неверный ввод отвергается до первого обращения к сети и системе.
func TestInstallRejectsBadInputBeforeAnyChange(t *testing.T) {
	cases := map[string]InstallOptions{
		"нет --sni":          {Address: "203.0.113.10", Port: 443},
		"нет --address":      {SNI: "example.com", Port: 443},
		"порт 0":             {SNI: "example.com", Address: "203.0.113.10", Port: 0},
		"порт больше 65535":  {SNI: "example.com", Address: "203.0.113.10", Port: 70000},
		"sni с пробелом":     {SNI: "exa mple.com", Address: "203.0.113.10", Port: 443},
		"sni с портом":       {SNI: "example.com:443", Address: "203.0.113.10", Port: 443},
		"sni — адрес":        {SNI: "203.0.113.10", Address: "203.0.113.11", Port: 443},
		"sni с дефисом":      {SNI: "-example.com", Address: "203.0.113.10", Port: 443},
		"address со слэшем":  {SNI: "example.com", Address: "203.0.113.10/24", Port: 443},
		"address с пробелом": {SNI: "example.com", Address: "bad host", Port: 443},
		"address с URL":      {SNI: "example.com", Address: "https://vpn.example.org", Port: 443},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			before := len(s.f.Calls())
			if _, err := s.app.Install(ctx(t), o); !errors.Is(err, ErrInput) {
				t.Fatalf("ожидалась ErrInput, получено %v", err)
			}
			if s.rel.latestCalls != 0 || len(s.f.Calls()) != before {
				t.Fatal("до проверки ввода что-то запускалось или загружалось")
			}
		})
	}
}

func TestInstallPreflightFailureStopsBeforeDownload(t *testing.T) {
	s := fresh(t)
	s.f.SetEffective(platform.Owner{UID: 1000, GID: 1000})
	_, err := s.app.Install(ctx(t), okOpts)
	var pe *PreflightError
	if !errors.Is(err, ErrPreflight) || !errors.As(err, &pe) || len(pe.Issues) != 1 || pe.Issues[0].Code != server.CodeNotRoot {
		t.Fatalf("%v", err)
	}
	if s.rel.latestCalls != 0 {
		t.Fatal("релиз запрашивался при невыполненных предусловиях")
	}
}

// Повторная установка поверх своей ничего не меняет и называет причину (идемпотентность — фаза 4).
func TestInstallRefusedWhenAlreadyInstalled(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	before, calls := s.snap(t), s.rel.latestCalls
	if _, err := s.app.Install(ctx(t), okOpts); !errors.Is(err, ErrInstalled) {
		t.Fatalf("%v", err)
	}
	if !before.equal(s.snap(t)) || s.rel.latestCalls != calls {
		t.Fatal("отказ что-то изменил или загрузил")
	}
}

func TestInstallSourceFailureChangesNothing(t *testing.T) {
	s := fresh(t)
	s.rel.latestErr = errors.New("нет сети (тест)")
	if _, err := s.app.Install(ctx(t), okOpts); err == nil || !strings.Contains(err.Error(), "нет сети") {
		t.Fatalf("%v", err)
	}
	if got := s.snap(t); got.state != nil || got.unit != nil || got.config != nil || got.current != "" || got.tx {
		t.Fatalf("%+v", got)
	}
}

// Провал контроля откатывает установку: состояния, конфигурации и юнита нет, служба остановлена.
// Выложенная версия остаётся (ADR-0023), поэтому повтор не упирается в ErrStaged.
func TestInstallControlFailureRollsBackAndRetrySucceeds(t *testing.T) {
	s := fresh(t)
	s.restartListens = []bool{false}
	_, err := s.app.Install(ctx(t), okOpts)
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v", err)
	}
	if got := s.snap(t); got.state != nil || got.unit != nil || got.config != nil || got.active || got.tx {
		t.Fatalf("после отката: %+v", got)
	}
	if _, err := os.Stat(s.f.Path(platform.CoreDir + "/" + v2 + "/xray")); err != nil {
		t.Fatalf("выложенная версия пропала: %v", err)
	}
	s.restartListens = nil
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatalf("повтор после отката: %v", err)
	}
}

// Поддельный архив не доходит до установки: Stage отвергает его до транзакции.
func TestInstallRejectsBadBinary(t *testing.T) {
	s := fresh(t)
	s.rel.archive = release(t)[:20]
	if _, err := s.app.Install(ctx(t), okOpts); err == nil {
		t.Fatal("битый архив принят")
	}
	if got := s.snap(t); got.state != nil || got.unit != nil || got.current != "" {
		t.Fatalf("%+v", got)
	}
}

// Базовая защита выполняется внутри транзакции: каталоги манифеста есть после установки, а при
// каждой следующей транзакции проверяются (docs/security/policy.md §2).
func TestApplyEnsuresBaseline(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.f.Path("/etc/xm"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	st, _ := s.app.s.Store.Load()
	err := s.app.Apply(ctx(t), Change{Reason: "noop", State: st, Unit: unit1})
	if err == nil || !strings.Contains(err.Error(), "базовая защита") {
		t.Fatalf("права каталога не проверены: %v", err)
	}
	if !before.equal(s.snap(t)) {
		t.Fatal("отказ базовой защиты что-то изменил")
	}
}

// A5: транзакция не запускает службу, которую владелец остановил (`xm stop`).
func TestApplyKeepsStoppedServiceStopped(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	if err := s.app.Service(ctx(t), Stop); err != nil {
		t.Fatal(err)
	}
	starts := s.restarts
	if err := s.app.Apply(ctx(t), Change{Reason: "add", State: stateOf("phone", "tablet"), Unit: unit2}); err != nil {
		t.Fatal(err)
	}
	if s.active || s.restarts != starts {
		t.Fatalf("остановленную службу запустили: active=%v, запусков %d→%d", s.active, starts, s.restarts)
	}
	st, _ := s.app.s.Store.Load()
	if len(st.Profiles) != 2 {
		t.Fatalf("изменение не записано: %+v", st.Profiles)
	}
	if drift, err := s.app.s.Config.Drift(st); err != nil || drift {
		t.Fatalf("дрейф: %v %v", drift, err)
	}
}

// Сбой после начала изменения остановленной службы возвращает прежнее и тоже её не запускает.
func TestApplyFailureWithStoppedServiceStaysStopped(t *testing.T) {
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	if err := s.app.Service(ctx(t), Stop); err != nil {
		t.Fatal(err)
	}
	before, starts := s.snap(t), s.restarts
	s.fs.path, s.fs.armed = store.StatePath, true
	if err := s.app.Apply(ctx(t), Change{Reason: "add", State: stateOf("phone", "tablet"), Unit: unit2}); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v", err)
	}
	if !before.equal(s.snap(t)) || s.restarts != starts {
		t.Fatalf("после отката: %+v, запусков %d→%d", s.snap(t), starts, s.restarts)
	}
}

func TestServiceCommands(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		a      Action
		active bool
	}{{Stop, false}, {Start, true}, {Restart, true}, {Stop, false}}
	for _, st := range steps {
		if err := s.app.Service(ctx(t), st.a); err != nil {
			t.Fatalf("%s: %v", st.a, err)
		}
		if s.active != st.active || listens(t, s, 443) != st.active {
			t.Fatalf("после %s: active=%v, порт слушается=%v", st.a, s.active, listens(t, s, 443))
		}
	}
}

func TestServiceRequiresInstallAndRoot(t *testing.T) {
	s := fresh(t)
	if err := s.app.Service(ctx(t), Start); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("%v", err)
	}
	s.f.SetEffective(platform.Owner{UID: 1000, GID: 1000})
	if err := s.app.Service(ctx(t), Start); !errors.Is(err, ErrPreflight) {
		t.Fatalf("%v", err)
	}
	if _, err := s.app.Status(ctx(t)); !errors.Is(err, ErrPreflight) {
		t.Fatalf("status без root: %v", err)
	}
}

func TestServiceRejectsUnknownAction(t *testing.T) {
	s := fresh(t)
	if err := s.app.Service(ctx(t), Action("reload")); !errors.Is(err, ErrInput) {
		t.Fatalf("%v", err)
	}
}

// Провал контроля запуска — ошибка, а не откат: состояние `start` не менял.
func TestServiceStartControlFailureIsNotRollback(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	if err := s.app.Service(ctx(t), Stop); err != nil {
		t.Fatal(err)
	}
	s.restartListens, s.nRestart = []bool{false}, 0
	err := s.app.Service(ctx(t), Start)
	if !errors.Is(err, server.ErrControl) || errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v", err)
	}
}

// Незавершённая транзакция откатывается раньше, чем команда службы что-то делает.
func TestServiceRecoversPendingTransactionFirst(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	if err := s.f.FS().WriteFile(store.TxPath, []byte("не журнал"), 0o600, platform.Root()); err != nil {
		t.Fatal(err)
	}
	starts := s.restarts
	if err := s.app.Service(ctx(t), Restart); !errors.Is(err, ErrRollbackFailed) || s.restarts != starts {
		t.Fatalf("%v, перезапусков %d→%d", err, starts, s.restarts)
	}
}

func TestStatus(t *testing.T) {
	s := fresh(t)
	st, err := s.app.Status(ctx(t))
	if err != nil || st.Installed || st.Versions.XM != "0.1.0" {
		t.Fatalf("не установлено: %+v %v", st, err)
	}
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	st, err = s.app.Status(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Installed || st.Versions.Xray != v2 || st.Port != 443 || st.Addresses.IPv4 != "203.0.113.10" || st.Drift ||
		!st.Service.Loaded || st.Service.Active != "active" || st.Service.Sub != "running" || !st.Service.Enabled {
		t.Fatalf("установлено: %+v", st)
	}
	// Конфигурацию правили руками — status это показывает.
	if err := s.f.FS().WriteFile("/usr/local/etc/xray/config.json", []byte("{}\n"), 0o640, platform.Owner{}); err != nil {
		t.Fatal(err)
	}
	if st, err = s.app.Status(ctx(t)); err != nil || !st.Drift {
		t.Fatalf("дрейф не виден: %+v %v", st, err)
	}
}

func listens(t *testing.T, s *sys, port int) bool {
	t.Helper()
	on, err := s.f.Net().Listening(ctx(t), port)
	if err != nil {
		t.Fatal(err)
	}
	return on
}
