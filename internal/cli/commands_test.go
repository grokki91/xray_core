package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/app"
	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/server"
)

// fakeApp запоминает, что у него просили, и отвечает заданным.
type fakeApp struct {
	opts   app.InstallOptions
	fw     app.FirewallResult // итог фаервола, который вернёт Install
	exists bool               // Install вернёт существующую установку
	health contract.Health
	action app.Action
	status contract.Status
	err    error
	// профили: что просили и что отвечать
	name     string
	share    app.ShareOptions
	view     app.ProfileView
	profiles contract.Profiles
	removed  string
	// обновление
	upd     contract.Update
	updOpts app.UpdateOptions
	// снимки
	backups  contract.Backups
	restored string
}

func (f *fakeApp) Backup(context.Context) (contract.BackupItem, error) {
	return contract.BackupItem{ID: "20260101T000000Z-manual", Kind: "manual", Valid: true}, f.err
}

func (f *fakeApp) BackupList(context.Context) (contract.Backups, error) { return f.backups, f.err }

func (f *fakeApp) Restore(_ context.Context, id string) error { f.restored = id; return f.err }

func (f *fakeApp) Update(_ context.Context, o app.UpdateOptions) (contract.Update, error) {
	f.updOpts = o
	return f.upd, f.err
}

func (f *fakeApp) Install(_ context.Context, o app.InstallOptions) (app.InstallResult, error) {
	f.opts = o
	return app.InstallResult{Xray: "26.11.9", Address: o.Address, Port: o.Port, Profile: "profile-1", Existing: f.exists, Firewall: f.fw, Health: f.health}, f.err
}

func (f *fakeApp) ProfileAdd(_ context.Context, name string, o app.ShareOptions) (app.ProfileView, error) {
	f.name, f.share = name, o
	return f.view, f.err
}

func (f *fakeApp) ProfileShow(_ context.Context, name string, o app.ShareOptions) (app.ProfileView, error) {
	f.name, f.share = name, o
	return f.view, f.err
}

func (f *fakeApp) ProfileList(context.Context) (contract.Profiles, error) { return f.profiles, f.err }

func (f *fakeApp) ProfileRemove(_ context.Context, name string) error { f.removed = name; return f.err }

func (f *fakeApp) Service(_ context.Context, a app.Action) error { f.action = a; return f.err }

func (f *fakeApp) Uninstall(context.Context, bool) error { return f.err }

func (f *fakeApp) Status(context.Context) (contract.Status, error) { return f.status, f.err }

func runWith(a App, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, Env{Ctx: context.Background(), Stdout: &out, Stderr: &errOut, Version: "0.1.0", Clock: fixedClock{}, App: a,
		Redact: func(s string) string { return strings.ReplaceAll(s, "CANARY", "[секрет]") }})
	return code, out.String(), errOut.String()
}

func TestInstallPassesFlagsAndNoFlagsAreOptional(t *testing.T) {
	f := &fakeApp{}
	code, stdout, stderr := runWith(f, "install", "--sni", "example.com", "--address", "203.0.113.10")
	if code != exitOK || stderr != "" || !strings.Contains(stdout, "Xray 26.11.9 установлен") {
		t.Fatalf("код %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := (app.InstallOptions{SNI: "example.com", Address: "203.0.113.10"}); f.opts != want {
		t.Fatalf("app получил %+v", f.opts)
	}
	runWith(f, "install", "--sni", "example.com", "--address", "vpn.example.org", "--port", "8443")
	if f.opts.Port != 8443 {
		t.Fatalf("порт %d", f.opts.Port)
	}
	if code, _, _ := runWith(f, "install", "--port", "много"); code != exitUsage {
		t.Fatalf("нечисловой порт: код %d", code)
	}
	// Флаги необязательны: пустые параметры уходят в app, он определяет их сам.
	f = &fakeApp{}
	if code, _, stderr := runWith(f, "install"); code != exitOK || stderr != "" || f.opts != (app.InstallOptions{}) {
		t.Fatalf("install без флагов: код %d, stderr %q, app получил %+v", code, stderr, f.opts)
	}
}

func TestServiceCommandsCallAction(t *testing.T) {
	for _, a := range []app.Action{app.Start, app.Stop, app.Restart} {
		f := &fakeApp{}
		if code, stdout, _ := runWith(f, string(a)); code != exitOK || f.action != a || !strings.HasPrefix(stdout, "Служба Xray ") {
			t.Fatalf("%s: код %d, действие %q, stdout %q", a, code, f.action, stdout)
		}
	}
}

// Коды выхода — docs/architecture/interfaces.md §1.
func TestFailureExitCodes(t *testing.T) {
	cases := []struct {
		err  error
		exit int
		code string
	}{
		{fmt.Errorf("%w: нужен --sni", app.ErrInput), 2, "cli.bad_arguments"},
		{&app.PreflightError{Issues: []server.Issue{{Code: server.CodeNotRoot, Message: "нужен root"}}}, 3, "preflight.not_root"},
		{app.ErrInstalled, 3, "app.already_installed"},
		{app.ErrNotInstalled, 3, "app.not_installed"},
		{fmt.Errorf("%w: %w", app.ErrRolledBack, errors.New("порт не слушается")), 1, "app.rolled_back"},
		{fmt.Errorf("%w: %w (причина: %w)", app.ErrRollbackFailed, errors.New("служба"), errors.New("контроль")), 5, "app.rollback_failed"},
		{fmt.Errorf("%w: sing-box: вырезает X25519MLKEM768", app.ErrIncompatible), 1, "profile.incompatible"},
		{errors.New("что-то иное"), 1, "app.failed"},
	}
	for _, tc := range cases {
		f := &fakeApp{err: tc.err}
		code, _, stderr := runWith(f, "start")
		if code != tc.exit || !strings.HasPrefix(stderr, "xm: ") || strings.Count(stderr, "\n") < 2 {
			t.Errorf("%v: код %d, stderr %q", tc.err, code, stderr)
		}
		code, stdout, _ := runWith(f, "status", "--json")
		if code != tc.exit || !strings.Contains(stdout, `"name": "error"`) || !strings.Contains(stdout, `"code": "`+tc.code+`"`) {
			t.Errorf("%v: status --json: код %d, stdout %q", tc.err, code, stdout)
		}
	}
}

// Текст ошибки приходит из системы: управляющие последовательности в терминал не попадают.
func TestFailureMessageIsEscaped(t *testing.T) {
	f := &fakeApp{err: errors.New("плохо\x1b[31m")}
	if _, _, stderr := runWith(f, "start"); strings.Contains(stderr, "\x1b") {
		t.Fatalf("в stderr управляющий символ: %q", stderr)
	}
}

var installed = contract.Status{
	Installed: true,
	Service:   contract.ServiceState{Loaded: true, Active: "active", Sub: "running", Enabled: true},
	Versions:  contract.Versions{XM: "0.1.0", Xray: "26.11.9"},
	Addresses: contract.ServerAddress{IPv4: "203.0.113.10"},
	Port:      443,
	Profiles:  2,
	Health:    contract.Health{Verdict: "ok", Unchecked: "доступность порта снаружи и самопроверка не проверены"},
	Clients: []contract.ClientSupport{
		{Name: "v2rayN", Works: true, Condition: "ядро Xray клиента не старше v25.7.26"},
		{Name: "Hiddify 4.x", Reason: "вырезает X25519MLKEM768"},
	},
	Update: contract.Available{Version: "26.11.9", Checked: "2026-01-01T00:00:00Z"},
}

// Вывод xm status --json побайтно совпадает с эталоном схемы status.
func TestStatusJSONMatchesGolden(t *testing.T) {
	want, err := os.ReadFile("../contract/testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runWith(&fakeApp{status: installed}, "status", "--json")
	if code != exitOK || stderr != "" || stdout != string(want) {
		t.Fatalf("код %d, stderr %q, stdout:\n%s", code, stderr, stdout)
	}
}

func TestStatusHuman(t *testing.T) {
	code, stdout, _ := runWith(&fakeApp{status: installed}, "status")
	for _, want := range []string{"active (running)", "Xray 26.11.9", "IPv4: 203.0.113.10", "Порт: 443", "совпадает с состоянием",
		"Профилей: 2", "Клиент v2rayN: подключится, если ядро Xray клиента", "Клиент Hiddify 4.x: не подключится (вырезает X25519MLKEM768)",
		"Доступен Xray 26.11.9 (проверено 2026-01-01T00:00:00Z): xm update"} {
		if code != exitOK || !strings.Contains(stdout, want) {
			t.Errorf("нет %q: код %d, stdout:\n%s", want, code, stdout)
		}
	}
	drift := installed
	drift.Drift = true
	if _, stdout, _ := runWith(&fakeApp{status: drift}, "status"); !strings.Contains(stdout, "расходится") {
		t.Fatalf("дрейф не показан:\n%s", stdout)
	}
	none := contract.Status{Versions: contract.Versions{XM: "0.1.0"}}
	if code, stdout, _ := runWith(&fakeApp{status: none}, "status"); code != exitOK || !strings.Contains(stdout, "не установлен") {
		t.Fatalf("не установлено: код %d, stdout %q", code, stdout)
	}
}

// Текст ошибки идёт через редактор и в stderr, и в документе error в stdout.
func TestFailureMessageGoesThroughRedactor(t *testing.T) {
	f := &fakeApp{err: errors.New("не прочитать CANARY")}
	_, _, stderr := runWith(f, "start")
	_, stdout, _ := runWith(f, "status", "--json")
	for name, out := range map[string]string{"stderr": stderr, "stdout": stdout} {
		if strings.Contains(out, "CANARY") || !strings.Contains(out, "[секрет]") {
			t.Errorf("%s: %q", name, out)
		}
	}
}

// Профиль для проверок вывода: совпадает с эталоном схемы profile.
var phone = app.ProfileView{
	Profile: contract.Profile{
		ProfileItem: contract.ProfileItem{Name: "phone", Created: 1767225600, Enabled: true},
		Links: []contract.ProfileLink{
			{Address: "vpn.example.com", URI: "vless://00000000-0000-4000-8000-000000000001@vpn.example.com:443?encryption=none#phone"},
		},
		QRAddress: "vpn.example.com",
		Unfit:     []contract.UnfitClient{{Client: "Hiddify 4.x", Reason: "вырезает X25519MLKEM768"}},
	},
	QR: "QR-РИСУНОК\n",
}

// add: имя и флаги доходят до app в любом порядке; в stdout ссылка и QR, предупреждение о
// клиентах — в stderr.
func TestAddPrintsLinksAndQR(t *testing.T) {
	f := &fakeApp{view: phone}
	for _, args := range [][]string{
		{"add", "phone", "--client", "hiddify-5", "--address", "192.0.2.10"},
		{"add", "--client", "hiddify-5", "phone", "--address", "192.0.2.10"},
		{"add", "--client", "hiddify-5", "--address", "192.0.2.10", "phone"},
	} {
		code, stdout, stderr := runWith(f, args...)
		if code != exitOK || f.name != "phone" || f.share != (app.ShareOptions{Client: "hiddify-5", Address: "192.0.2.10"}) {
			t.Fatalf("%v: код %d, имя %q, опции %+v", args, code, f.name, f.share)
		}
		for _, want := range []string{"Профиль создан «phone»", "vpn.example.com", "vless://", "QR для vpn.example.com:\nQR-РИСУНОК"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%v: в stdout нет %q:\n%s", args, want, stdout)
			}
		}
		if !strings.Contains(stderr, "Hiddify 4.x не подключится: вырезает X25519MLKEM768") || strings.Contains(stdout, "Предупреждение") {
			t.Errorf("предупреждение: stderr %q", stderr)
		}
	}
	runWith(f, "add")
	if f.name != "" || f.share != (app.ShareOptions{}) {
		t.Fatalf("add без аргументов: %q %+v", f.name, f.share)
	}
}

func TestShowNeedsOneName(t *testing.T) {
	f := &fakeApp{view: phone}
	for _, args := range [][]string{{"show"}, {"show", "a", "b"}, {"rm"}, {"rm", "a", "b"}, {"add", "a", "b"}, {"list", "x"}} {
		if code, _, stderr := runWith(f, args...); code != exitUsage || !strings.HasPrefix(stderr, "xm: ") {
			t.Errorf("%v: код %d, stderr %q", args, code, stderr)
		}
	}
	if code, stdout, _ := runWith(f, "show", "phone"); code != exitOK || f.name != "phone" || !strings.Contains(stdout, "Профиль «phone»") {
		t.Fatalf("show: код %d, имя %q", code, f.name)
	}
}

// Машинный вывод add и show — документ profile побайтно как эталон; QR в него не входит.
func TestProfileJSONMatchesGolden(t *testing.T) {
	want, err := os.ReadFile("../contract/testdata/profile.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "phone", "--json"}, {"show", "phone", "--json"}} {
		code, stdout, stderr := runWith(&fakeApp{view: phone}, args...)
		if code != exitOK || stderr != "" || stdout != string(want) || strings.Contains(stdout, "QR-РИСУНОК") {
			t.Fatalf("%v: код %d, stderr %q, stdout:\n%s", args, code, stderr, stdout)
		}
	}
}

func TestListHumanAndJSON(t *testing.T) {
	f := &fakeApp{profiles: contract.Profiles{Profiles: []contract.ProfileItem{
		{Name: "phone", Created: 1767225600, Enabled: true}, {Name: "laptop", Created: 1767229200},
	}}}
	code, stdout, _ := runWith(f, "list")
	if code != exitOK || !strings.Contains(stdout, "phone") || !strings.Contains(stdout, "2026-01-01  включён") || !strings.Contains(stdout, "выключен") {
		t.Fatalf("list: код %d\n%s", code, stdout)
	}
	if strings.Contains(stdout, "vless") {
		t.Fatal("в списке ссылка")
	}
	want, err := os.ReadFile("../contract/testdata/profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, _ := runWith(f, "list", "--json"); code != exitOK || stdout != string(want) {
		t.Fatalf("list --json: код %d\n%s", code, stdout)
	}
	if _, stdout, _ := runWith(&fakeApp{}, "list"); !strings.Contains(stdout, "Профилей нет") {
		t.Fatalf("пустой список: %q", stdout)
	}
}

func TestRemove(t *testing.T) {
	f := &fakeApp{}
	if code, stdout, _ := runWith(f, "rm", "phone"); code != exitOK || f.removed != "phone" || !strings.Contains(stdout, "удалён") {
		t.Fatalf("rm: код %d, удалён %q, stdout %q", code, f.removed, stdout)
	}
	if code, _, _ := runWith(&fakeApp{err: fmt.Errorf("%w: профиля нет", app.ErrInput)}, "rm", "x"); code != exitUsage {
		t.Fatalf("rm чужого: код %d", code)
	}
}

// Установка завершается ссылкой и QR первого профиля.
func TestInstallPrintsFirstProfile(t *testing.T) {
	f := &fakeApp{view: phone}
	code, stdout, _ := runWith(f, "install", "--sni", "example.com", "--address", "203.0.113.10")
	if code != exitOK || f.name != "profile-1" {
		t.Fatalf("код %d, показан профиль %q", code, f.name)
	}
	for _, want := range []string{"Xray 26.11.9 установлен", "Первый профиль «phone»", "vless://", "QR-РИСУНОК"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("нет %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "пока нет") {
		t.Fatal("устаревшее сообщение об отсутствии профилей")
	}
}

// Повторный запуск: «ничего не изменено», строки про фаервол нет, ссылка показана.
func TestInstallRepeatSaysNothingChanged(t *testing.T) {
	_, stdout, _ := runWith(&fakeApp{view: phone, exists: true}, "install")
	if !strings.Contains(stdout, "уже установлен, ничего не изменено") || strings.Contains(stdout, "Фаервол") || !strings.Contains(stdout, "vless://") {
		t.Fatalf("повтор:\n%s", stdout)
	}
}

// Итог про фаервол: правило UFW — сказано, что снимет uninstall; закрытый порт — команда владельцу.
func TestInstallPrintsFirewall(t *testing.T) {
	_, stdout, _ := runWith(&fakeApp{view: phone, fw: app.FirewallResult{State: "denied", Source: "ufw", Added: true}}, "install")
	if !strings.Contains(stdout, "в UFW добавлено правило") || !strings.Contains(stdout, "при удалении") {
		t.Fatalf("правило UFW не названо:\n%s", stdout)
	}
	open := "iptables -I INPUT -p tcp --dport 443 -j ACCEPT"
	_, stdout, _ = runWith(&fakeApp{view: phone, fw: app.FirewallResult{State: "unknown", Source: "iptables", Note: "политика DROP", Open: open}}, "install")
	if !strings.Contains(stdout, "не определён как открытый") || !strings.Contains(stdout, open) {
		t.Fatalf("команда не названа:\n%s", stdout)
	}
}

// Каждое состояние локального фаервола даёт свой итог; запрет — факт с командой, а пустой
// команды итог не печатает (A3).
func TestInstallFirewallOutcomes(t *testing.T) {
	cases := []struct {
		fw   app.FirewallResult
		want []string
		not  []string
	}{
		{app.FirewallResult{State: "allowed", Source: "ufw"}, []string{"локально не закрыт", "фаервол хостера с сервера не виден"}, []string{"откройте"}},
		{app.FirewallResult{State: "denied", Source: "ufw", Note: "правило UFW запрещает порт", Open: "ufw insert 1 allow 443/tcp"},
			[]string{"закрыт локально", "правило UFW запрещает порт", "ufw insert 1 allow 443/tcp"}, []string{"не определён"}},
		{app.FirewallResult{State: "denied", Source: "iptables", Note: "запрет"}, []string{"закрыт локально (запрет)."}, []string{"сами:"}},
		{app.FirewallResult{State: "unknown", Source: "ufw", Note: "политика UFW не разобрана"},
			[]string{"не определён как открытый", "политика UFW не разобрана"}, []string{"сами:"}},
	}
	for _, c := range cases {
		_, stdout, _ := runWith(&fakeApp{view: phone, fw: c.fw}, "install")
		for _, w := range c.want {
			if !strings.Contains(stdout, w) {
				t.Errorf("%s: нет %q:\n%s", c.fw.State, w, stdout)
			}
		}
		for _, n := range c.not {
			if strings.Contains(stdout, n) {
				t.Errorf("%s: лишнее %q:\n%s", c.fw.State, n, stdout)
			}
		}
	}
}

// Ошибки профильных команд идут через общий разбор: неверное имя — код 2, несовместимый
// клиент — код 1 с причиной.
func TestProfileFailures(t *testing.T) {
	code, _, stderr := runWith(&fakeApp{err: fmt.Errorf("%w: sing-box: вырезает X25519MLKEM768", app.ErrIncompatible)}, "add", "--client", "sing-box")
	if code != exitFail || !strings.Contains(stderr, "X25519MLKEM768") {
		t.Fatalf("код %d, stderr %q", code, stderr)
	}
	if code, _, _ := runWith(&fakeApp{err: fmt.Errorf("%w: имя", app.ErrInput)}, "show", "Bad"); code != exitUsage {
		t.Fatalf("код %d", code)
	}
}

// Status и install заканчиваются строкой вердикта: ok — с тем, что не проверено; иначе — причина
// и действие (ADR-0024).
func TestVerdictLineEndsStatusAndInstall(t *testing.T) {
	down := contract.Health{Verdict: "down", Cause: "служба xray не активна", Action: "xm start"}
	st := installed
	st.Health = down
	_, stdout, _ := runWith(&fakeApp{status: st}, "status")
	last := strings.Split(strings.TrimSpace(stdout), "\n")
	if got := last[len(last)-1]; got != "Состояние: не работает. Причина: служба xray не активна. Что делать: xm start." {
		t.Fatalf("status: %q", got)
	}
	_, stdout, _ = runWith(&fakeApp{status: installed}, "status")
	if !strings.Contains(stdout, "Состояние: работает. Не проверено: доступность порта снаружи") {
		t.Fatalf("status ok:\n%s", stdout)
	}
	_, stdout, _ = runWith(&fakeApp{view: phone, health: down}, "install", "--sni", "example.com", "--address", "203.0.113.10")
	if !strings.HasSuffix(strings.TrimSpace(stdout), "Что делать: xm start.") {
		t.Fatalf("install заканчивается не вердиктом:\n%s", stdout)
	}
}

var updated = contract.Update{
	Current: "26.10.21", Target: "26.11.9", Latest: "26.12.1",
	Range: contract.Range{Min: "26.10.21", Max: "26.11.9"}, InRange: true, Updated: true,
	Checked: "2026-01-01T00:00:00Z", Unchecked: "сторонние клиентские ядра не проверялись",
}

// Вывод xm update --json побайтно совпадает с эталоном схемы update; флаги доходят до app.
func TestUpdateJSONMatchesGolden(t *testing.T) {
	want, err := os.ReadFile("../contract/testdata/update.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeApp{upd: updated}
	code, stdout, stderr := runWith(f, "update", "--to", "v26.11.9", "--check", "--json")
	if code != exitOK || stderr != "" || stdout != string(want) || f.updOpts != (app.UpdateOptions{Check: true, To: "v26.11.9"}) {
		t.Fatalf("код %d, stderr %q, опции %+v, stdout:\n%s", code, stderr, f.updOpts, stdout)
	}
}

func TestUpdateHuman(t *testing.T) {
	cases := []struct {
		args []string
		res  func(contract.Update) contract.Update
		want []string
	}{
		{nil, func(u contract.Update) contract.Update { return u },
			[]string{"новее проверенного диапазона 26.10.21–26.11.9", "Xray обновлён: 26.10.21 → 26.11.9", "Не проверено: сторонние"}},
		{[]string{"--check"}, func(u contract.Update) contract.Update { u.Updated = false; return u }, []string{"Доступен Xray 26.11.9 (сейчас 26.10.21): xm update"}},
		{nil, func(u contract.Update) contract.Update { u.Updated, u.Held = false, true; return u }, []string{"удержано"}},
		{nil, func(u contract.Update) contract.Update { u.Updated, u.Current = false, u.Target; return u }, []string{"уже эта версия"}},
		{nil, func(u contract.Update) contract.Update { u.InRange, u.Latest, u.Target = false, "", "27.0.0"; return u }, []string{"вне проверенного диапазона"}},
	}
	for _, c := range cases {
		_, stdout, _ := runWith(&fakeApp{upd: c.res(updated)}, append([]string{"update"}, c.args...)...)
		for _, w := range c.want {
			if !strings.Contains(stdout, w) {
				t.Errorf("%v: нет %q:\n%s", c.args, w, stdout)
			}
		}
	}
}
