package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/core"
	"github.com/grokki91/xray_core/internal/network"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/redact"
	"github.com/grokki91/xray_core/internal/server"
	"github.com/grokki91/xray_core/internal/store"
	"github.com/grokki91/xray_core/internal/update"
)

// fakeReleases — источник релизов: тег и архив задаёт тест; считает обращения.
type fakeReleases struct {
	tag                  string
	archive              []byte
	latestErr, fetchErr  error
	latestCalls, fetches int
	onFetch              func() // что произойдёт между проверкой «состояния нет» и транзакцией
}

func (r *fakeReleases) Latest(context.Context) (update.Release, error) {
	r.latestCalls++
	return update.Release{Tag: r.tag}, r.latestErr
}

func (r *fakeReleases) Fetch(context.Context, update.Release, update.Arch) (update.Archive, error) {
	r.fetches++
	if r.onFetch != nil {
		r.onFetch()
	}
	return update.Archive{Data: r.archive}, r.fetchErr
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
		in.Reality.PrivateKey == "" || in.Reality.PublicKey == "" || len(in.Reality.ShortIDs) != 1 || len(st.Profiles) != 1 || st.Profiles[0].Name != res.Profile {
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
		"порт больше 65535":    {SNI: "example.com", Address: "203.0.113.10", Port: 70000},
		"sni с пробелом":       {SNI: "exa mple.com", Address: "203.0.113.10", Port: 443},
		"sni с портом":         {SNI: "example.com:443", Address: "203.0.113.10", Port: 443},
		"sni — адрес":          {SNI: "203.0.113.10", Address: "203.0.113.11", Port: 443},
		"sni с дефисом":        {SNI: "-example.com", Address: "203.0.113.10", Port: 443},
		"address со слэшем":    {SNI: "example.com", Address: "203.0.113.10/24", Port: 443},
		"address с пробелом":   {SNI: "example.com", Address: "bad host", Port: 443},
		"address с URL":        {SNI: "example.com", Address: "https://vpn.example.org", Port: 443},
		"address — петля":      {SNI: "example.com", Address: "127.0.0.1", Port: 443},
		"address — любой":      {SNI: "example.com", Address: "0.0.0.0", Port: 443},
		"address — ::1":        {SNI: "example.com", Address: "::1", Port: 443},
		"address — ::":         {SNI: "example.com", Address: "::", Port: 443},
		"address — multicast":  {SNI: "example.com", Address: "ff02::1", Port: 443},
		"address — link-local": {SNI: "example.com", Address: "169.254.1.1", Port: 443},
		"address — fe80":       {SNI: "example.com", Address: "fe80::1", Port: 443},
		"address — 4in6":       {SNI: "example.com", Address: "::ffff:203.0.113.10", Port: 443},
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
// Транзакция установки отказывает под блокировкой, если установка уже есть (параллельная
// команда успела раньше): ErrInstalled.
func TestInstallTransactionRefusesWhenInstalled(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	st, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: st, Create: true}); !errors.Is(err, ErrInstalled) {
		t.Fatalf("%v", err)
	}
	if !before.equal(s.snap(t)) {
		t.Fatal("отказ что-то изменил")
	}
}

// Повторный запуск ничего не меняет: состояние, конфигурация и ключи те же, релиз не
// загружается, фаервол не трогается; итог — существующая установка.
func TestInstallRepeatChangesNothing(t *testing.T) {
	s := fresh(t)
	s.ufwStatus = ufwDenyByDefault
	first, err := s.app.Install(ctx(t), okOpts)
	if err != nil {
		t.Fatal(err)
	}
	before, calls, rules := s.snap(t), s.rel.latestCalls, len(s.ufwRules)
	for _, o := range []InstallOptions{{}, okOpts, {SNI: "EXAMPLE.com"}, {Address: "203.0.113.10", Port: 443}} {
		res, err := s.app.Install(ctx(t), o)
		if err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
		if !res.Existing || res.Profile != first.Profile || res.Xray != first.Xray || res.Port != 443 || res.Address != first.Address {
			t.Fatalf("итог повтора %+v, первый %+v", res, first)
		}
	}
	if !before.equal(s.snap(t)) || s.rel.latestCalls != calls || len(s.ufwRules) != rules {
		t.Fatal("повтор что-то изменил, загрузил или тронул фаервол")
	}
}

// Параметры, расходящиеся с установленным, повтор не меняет: ErrInput, ничего не тронуто.
func TestInstallRepeatWithOtherParamsIsInputError(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	for name, o := range map[string]InstallOptions{
		"sni":    {SNI: "other.example.org"},
		"порт":   {Port: 8443},
		"адрес":  {Address: "203.0.113.99"},
		"домен":  {Address: "vpn.example.org"},
		"адрес6": {Address: "2001:db8::99"},
	} {
		if _, err := s.app.Install(ctx(t), o); !errors.Is(err, ErrInput) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if !before.equal(s.snap(t)) {
		t.Fatal("отказ что-то изменил")
	}
}

// Без флагов: адреса — по сетевым фактам (оба семейства), цель — из закрытого списка, DNS — по
// семействам; профиль получает ссылку на каждый адрес.
func TestInstallWithoutFlags(t *testing.T) {
	s := fresh(t)
	cand := network.Candidates()
	s.f.SetTLS(cand[0], platform.TLSInfo{Version: tls.VersionTLS13, ALPN: "h2", Curve: tls.X25519MLKEM768,
		Addr: netip.MustParseAddr("198.51.100.30"), Handshake: 10 * time.Millisecond, Status: 200}, nil)
	s.f.SetAddrs([]platform.IfAddr{
		{Iface: "eth0", Addr: netip.MustParseAddr("203.0.113.7")},
		{Iface: "eth0", Addr: netip.MustParseAddr("2001:db8::7")},
	})
	res, err := s.app.Install(ctx(t), InstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Server.Port != 443 || st.Server.Addresses != (store.Addresses{IPv4: "203.0.113.7", IPv6: "2001:db8::7"}) ||
		st.Inbounds[0].Reality.ServerNames[0] != cand[0] || st.DNS.Strategy != "UseIP" || len(st.DNS.DoH) == 0 {
		t.Fatalf("состояние: %+v", st)
	}
	v, err := s.app.ProfileShow(ctx(t), res.Profile, ShareOptions{})
	if err != nil || len(v.Links) != 2 {
		t.Fatalf("ссылки по одной на адрес сервера: %+v, %v", v.Links, err)
	}
	if res.Address != "203.0.113.7" {
		t.Fatalf("итог: %+v", res)
	}
}

// Только IPv4: семейство IPv6 в состоянии не появляется, стратегия DNS — UseIPv4.
func TestInstallIPv4Only(t *testing.T) {
	s := fresh(t)
	s.f.SetAddrs([]platform.IfAddr{{Iface: "eth0", Addr: netip.MustParseAddr("203.0.113.7")}})
	if _, err := s.app.Install(ctx(t), InstallOptions{SNI: "example.com"}); err != nil {
		t.Fatal(err)
	}
	st, err := s.app.s.Store.Load()
	if err != nil || st.Server.Addresses != (store.Addresses{IPv4: "203.0.113.7"}) || st.DNS.Strategy != "UseIPv4" {
		t.Fatalf("%+v, %v", st, err)
	}
}

func TestInstallNoAddressFoundAsksFlag(t *testing.T) {
	s := fresh(t) // интерфейсов нет, узел определения адреса не отвечает
	before := len(s.f.Calls())
	_, err := s.app.Install(ctx(t), InstallOptions{SNI: "example.com"})
	var pe *PreflightError
	if !errors.As(err, &pe) || pe.Issues[0].Code != "preflight.no_address" || !strings.Contains(err.Error(), "--address") {
		t.Fatalf("%v", err)
	}
	if got := s.snap(t); s.rel.latestCalls != 0 || got.state != nil || got.tx {
		t.Fatalf("до остановки что-то изменено (%d вызовов): %+v", len(s.f.Calls())-before, got)
	}
}

func TestInstallPortBusy(t *testing.T) {
	s := fresh(t)
	s.f.SetListening(443, true)
	_, err := s.app.Install(ctx(t), okOpts)
	var pe *PreflightError
	if !errors.As(err, &pe) || pe.Issues[0].Code != "preflight.port_busy" || !strings.Contains(err.Error(), "--port") {
		t.Fatalf("%v", err)
	}
	if s.rel.latestCalls != 0 || s.snap(t).state != nil {
		t.Fatal("занятый порт не остановил установку до загрузки")
	}
}

func TestInstallTargetFailureChangesNothing(t *testing.T) {
	s := fresh(t)
	o := okOpts
	o.SNI = "no-answer.example.org" // подделка не отвечает
	if _, err := s.app.Install(ctx(t), o); err == nil {
		t.Fatal("цель без ответа принята")
	}
	if s.rel.latestCalls != 0 || s.snap(t).state != nil {
		t.Fatal("провал цели не остановил установку до загрузки")
	}
}

// UFW активен и закрывает порт политикой: правило ставит транзакция, метка — в состоянии.
func TestInstallAddsUFWRule(t *testing.T) {
	s := fresh(t)
	s.ufwStatus = ufwDenyByDefault
	res, err := s.app.Install(ctx(t), okOpts)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := s.app.s.Store.Load()
	if !st.Firewall.UFWRule || strings.Join(s.ufwRules, "|") != "allow 443/tcp" || !res.Firewall.Added || res.Firewall.Open != "" {
		t.Fatalf("метка %v, вызовы %q, итог %+v", st.Firewall, s.ufwRules, res.Firewall)
	}
}

// Правило есть, UFW выключен, чужой фаервол — правило не ставится и метки нет.
func TestInstallLeavesFirewallAlone(t *testing.T) {
	for name, ufw := range map[string]string{
		"уже разрешён": ufwDenyByDefault + "443/tcp ALLOW IN Anywhere\n",
		"выключен":     "Status: inactive\n",
		"явный deny":   ufwDenyByDefault + "443 DENY IN Anywhere\n",
	} {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			s.ufwStatus = ufw
			res, err := s.app.Install(ctx(t), okOpts)
			if err != nil {
				t.Fatal(err)
			}
			st, _ := s.app.s.Store.Load()
			if st.Firewall.UFWRule || len(s.ufwRules) != 0 || res.Firewall.Added {
				t.Fatalf("метка %v, вызовы %q", st.Firewall, s.ufwRules)
			}
		})
	}
}

// Закрыт ли порт правилами iptables, с сервера не доказать: итог называет «не определено» и
// команду, которую владелец выполняет сам; xm правил iptables не меняет (ADR-0036).
func TestInstallNamesCommandForIptables(t *testing.T) {
	s := fresh(t)
	s.f.Handle(platform.IPTables, func(platform.Command) (platform.Result, error) {
		return platform.Result{Stdout: []byte("-P INPUT DROP\n")}, nil
	})
	res, err := s.app.Install(ctx(t), okOpts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Firewall.State != "unknown" || !strings.Contains(res.Firewall.Open, "iptables -I INPUT -p tcp --dport 443 -j ACCEPT") {
		t.Fatalf("%+v", res.Firewall)
	}
	for _, c := range s.f.Calls() {
		if c.Op == "exec" && c.Path == platform.IPTables && len(c.Args) > 0 && c.Args[0] != "-S" {
			t.Fatalf("iptables изменён: %v", c.Args)
		}
	}
}

// Провал контроля после добавления правила: правило снято, состояния нет — «сбой после
// изменения → прежнее значение».
func TestInstallControlFailureRevokesUFWRule(t *testing.T) {
	s := fresh(t)
	s.ufwStatus = ufwDenyByDefault
	s.restartListens = []bool{false}
	if _, err := s.app.Install(ctx(t), okOpts); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v", err)
	}
	if strings.Join(s.ufwRules, "|") != "allow 443/tcp|delete allow 443/tcp" || s.snap(t).state != nil {
		t.Fatalf("вызовы ufw %q", s.ufwRules)
	}
}

// ufw отказал в добавлении: установка откатывается, снятие правила безопасно (его не было).
func TestInstallUFWFailureRollsBack(t *testing.T) {
	s := fresh(t)
	s.ufwStatus = ufwDenyByDefault
	s.ufwExit = 1
	if _, err := s.app.Install(ctx(t), okOpts); err == nil {
		t.Fatal("отказ ufw принят")
	}
	if s.snap(t).state != nil || s.snap(t).tx {
		t.Fatal("отказ ufw оставил установку")
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

// Отказ проверки загрузки (суммы, адрес) останавливает установку до выкладки версии и транзакции.
func TestInstallFetchRejectionChangesNothing(t *testing.T) {
	for _, e := range []error{update.ErrIntegrity, platform.ErrURL} {
		t.Run(e.Error(), func(t *testing.T) {
			s := fresh(t)
			s.rel.fetchErr = e
			if _, err := s.app.Install(ctx(t), okOpts); !errors.Is(err, e) {
				t.Fatalf("%v, нужна %v", err, e)
			}
			if got := s.snap(t); got.state != nil || got.unit != nil || got.config != nil || got.current != "" || got.tx {
				t.Fatalf("%+v", got)
			}
			if _, err := os.Stat(s.f.Path(platform.CoreDir + "/" + v2)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("версия выложена: %v", err)
			}
		})
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
	if st.Health.Verdict != "ok" || st.Health.Unchecked == "" {
		t.Fatalf("вердикт здоровой установки: %+v", st.Health)
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

// regAdapter — то же, что связывает cmd/xm: app называет вид значения строкой.
type regAdapter struct{ r *redact.Redactor }

func (g regAdapter) Register(kind, value string) { g.r.Register(redact.Kind(kind), value) }

// Секреты и данные установки регистрируются в редакторе: шаблон не ловит shortId, а ключ ловит
// только по длине. Значение должно быть заменено, даже если его вставили в чужой текст.
func TestInstallRegistersValuesWithRedactor(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	st, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	r := st.Inbounds[0].Reality
	for name, v := range map[string]string{"закрытый ключ": r.PrivateKey, "открытый ключ": r.PublicKey,
		"shortId": r.ShortIDs[0], "адрес": st.Server.Addresses.IPv4, "sni": r.ServerNames[0]} {
		if got := s.reg.Text("сбой: " + v); strings.Contains(got, v) {
			t.Errorf("%s не зарегистрирован: %q", name, got)
		}
	}
}

// Канарейка: при провале установки значения состояния не попадают в ошибку и журнал xm.
func TestInstallFailureLeaksNoSecret(t *testing.T) {
	s := fresh(t)
	s.testExit = 23 // xray run -test отвергает конфигурацию: ключи уже созданы
	_, err := s.app.Install(ctx(t), okOpts)
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v", err)
	}
	for _, j := range s.f.Journaled() {
		if strings.Contains(j.Message, "203.0.113.10") {
			t.Fatalf("адрес сервера в журнале xm: %q", j.Message)
		}
	}
	if strings.Contains(err.Error(), "203.0.113.10") {
		t.Fatalf("адрес сервера в ошибке: %v", err)
	}
}

// Состояние появилось между проверкой и транзакцией: Apply под блокировкой отказывает и ничего
// не трогает — чужая установка не перезаписывается.
func TestInstallRaceDoesNotOverwriteExistingState(t *testing.T) {
	s := fresh(t)
	s.rel.onFetch = func() {
		if err := s.app.s.Security.EnsureBaseline(ctx(t)); err != nil {
			t.Error(err)
		}
		other := stateOf()
		other.Server.Port = 8443
		if err := s.app.s.Store.Save(other); err != nil {
			t.Error(err)
		}
	}
	if _, err := s.app.Install(ctx(t), okOpts); !errors.Is(err, ErrInstalled) {
		t.Fatalf("%v", err)
	}
	st, err := s.app.s.Store.Load()
	if err != nil || st.Server.Port != 8443 {
		t.Fatalf("состояние перезаписано: %+v %v", st.Server, err)
	}
	if got := s.snap(t); got.unit != nil || got.config != nil || got.tx {
		t.Fatalf("%+v", got)
	}
}

// Версия, выложенная с другим содержимым, не принимается: целостность бинарника важнее повтора.
func TestInstallRejectsStagedBinaryWithOtherContent(t *testing.T) {
	s := fresh(t)
	dir := platform.CoreDir + "/" + v2
	if err := os.MkdirAll(s.f.Path(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.f.FS().WriteFile(dir+"/xray", []byte("непроверенный бинарник"), 0o755, platform.Root()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.app.Install(ctx(t), okOpts); !errors.Is(err, core.ErrStaged) {
		t.Fatalf("%v", err)
	}
	if got := s.snap(t); got.state != nil || got.unit != nil || got.current != "" {
		t.Fatalf("%+v", got)
	}
}

// Незавершённая транзакция откатывается до проверки «уже установлено».
func TestInstallRecoversPendingTransactionFirst(t *testing.T) {
	s := fresh(t)
	if err := s.app.s.Security.EnsureBaseline(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.f.FS().WriteFile(store.TxPath, []byte("не журнал"), 0o600, platform.Root()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.app.Install(ctx(t), okOpts); !errors.Is(err, ErrRollbackFailed) || s.rel.latestCalls != 0 {
		t.Fatalf("%v", err)
	}
}

// Установка завершается рабочим первым профилем: он в состоянии и в конфигурации Xray, ссылка
// строится, а идентификатор клиента не попадает ни в журнал xm, ни в итог установки.
func TestInstallCreatesFirstProfile(t *testing.T) {
	s := fresh(t)
	res, err := s.app.Install(ctx(t), okOpts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Profile != "profile-1" {
		t.Fatalf("имя первого профиля %q", res.Profile)
	}
	pid := idOf(t, s, res.Profile)
	if !strings.Contains(readConfig(t, s), pid) {
		t.Fatal("ключ первого профиля не в конфигурации")
	}
	v, err := s.app.ProfileShow(ctx(t), res.Profile, ShareOptions{})
	if err != nil || len(v.Links) != 1 || !strings.Contains(v.Links[0].URI, pid) || v.QR == "" {
		t.Fatalf("показ: %+v %v", v.Profile, err)
	}
	if doc, _ := json.Marshal(res); strings.Contains(string(doc), pid) {
		t.Fatalf("в итоге установки ключ профиля: %s", doc)
	}
	for _, j := range s.f.Journaled() {
		if strings.Contains(j.Message, pid) {
			t.Fatalf("ключ профиля в журнале xm: %q", j.Message)
		}
	}
}

// Остановленная служба — вердикт down с причиной и действием; xm status не меняет систему.
func TestStatusHealthDownWhenStopped(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Install(ctx(t), okOpts); err != nil {
		t.Fatal(err)
	}
	if err := s.app.Service(ctx(t), Stop); err != nil {
		t.Fatal(err)
	}
	st, err := s.app.Status(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if st.Health.Verdict != "down" || st.Health.Cause == "" || st.Health.Action == "" || st.Health.Unchecked != "" {
		t.Fatalf("вердикт остановленной службы: %+v", st.Health)
	}
}

// Установка возвращает вердикт: после контроля транзакции он ok.
func TestInstallReturnsHealth(t *testing.T) {
	s := fresh(t)
	res, err := s.app.Install(ctx(t), okOpts)
	if err != nil || res.Health.Verdict != "ok" {
		t.Fatalf("%+v %v", res, err)
	}
}

// Оборванная установка с правилом UFW: журнал с портом, следующий запуск откатывает и снимает правило.
func TestRecoverRevokesUFWRuleFromJournal(t *testing.T) {
	s := fresh(t)
	s.ufwStatus = ufwDenyByDefault
	s.restartListens = []bool{false}
	if _, err := s.app.Install(ctx(t), okOpts); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("%v", err)
	}
	s.ufwRules = nil
	// Журнал оборванной транзакции: снимок есть, порт правила записан.
	snap, err := s.app.s.Backup.Create(ctx(t), "install", backup.Meta{XM: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.app.s.Store.WriteTx(store.Tx{Snapshot: snap.ID, UFWPort: 443, Started: s.f.Clock().Now()}); err != nil {
		t.Fatal(err)
	}
	if did, err := s.app.Recover(ctx(t)); err != nil || !did {
		t.Fatalf("Recover: %v %v", did, err)
	}
	if strings.Join(s.ufwRules, "|") != "delete allow 443/tcp" || s.snap(t).tx {
		t.Fatalf("вызовы ufw %q, журнал %v", s.ufwRules, s.snap(t).tx)
	}
}

// Отказ ufw при снятии правила — откат не удался (код 5), журнал остаётся для повтора.
func TestRollbackFailsWhenUFWRevokeFails(t *testing.T) {
	s := fresh(t)
	s.ufwStatus = ufwDenyByDefault
	s.restartListens = []bool{false}
	s.ufwRevokeExit = 1
	if _, err := s.app.Install(ctx(t), okOpts); !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("%v", err)
	}
	if !s.snap(t).tx {
		t.Fatal("журнал удалён при неудавшемся откате")
	}
}
