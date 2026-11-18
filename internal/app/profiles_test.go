package app

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/profile"
	"github.com/grokki91/xray_core/internal/server"
)

func installed(t *testing.T) *sys {
	t.Helper()
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf(), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	return s
}

func readConfig(t *testing.T, s *sys) string {
	t.Helper()
	b, err := os.ReadFile(s.f.Path(config.Path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// idOf — идентификатор клиента профиля из состояния: наружу app его не отдаёт.
func idOf(t *testing.T, s *sys, name string) string {
	t.Helper()
	st, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.app.s.Profile.Get(st, name)
	if err != nil {
		t.Fatal(err)
	}
	return p.ID
}

// Профиль добавляется и удаляется транзакцией: его ключ появляется в конфигурации Xray и
// исчезает из неё, служба перезапускается.
func TestProfileAddListShowRemove(t *testing.T) {
	s := installed(t)
	restarts := s.restarts
	p, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pid := idOf(t, s, "phone")
	if !p.Enabled || p.Name != "phone" || pid == "" {
		t.Fatalf("профиль: %+v", p)
	}
	if !strings.Contains(readConfig(t, s), pid) {
		t.Fatal("ключ профиля не попал в конфигурацию")
	}
	if s.restarts == restarts || s.snap(t).tx {
		t.Fatal("изменение не применено транзакцией")
	}
	if _, err := s.app.ProfileAdd(ctx(t), "laptop", ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	list, err := s.app.ProfileList(ctx(t))
	if err != nil || len(list.Profiles) != 2 || list.Profiles[0].Name != "phone" || list.Profiles[1].Name != "laptop" {
		t.Fatalf("список: %+v %v", list, err)
	}
	if got, err := s.app.ProfileShow(ctx(t), "phone", ShareOptions{}); err != nil || !strings.Contains(got.Links[0].URI, pid) {
		t.Fatalf("показ: %+v %v", got, err)
	}
	if err := s.app.ProfileRemove(ctx(t), "phone"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readConfig(t, s), pid) {
		t.Fatal("ключ удалённого профиля остался в конфигурации")
	}
	if _, err := s.app.ProfileShow(ctx(t), "phone", ShareOptions{}); !errors.Is(err, ErrInput) || !errors.Is(err, profile.ErrNotFound) {
		t.Fatalf("удалённый профиль: %v", err)
	}
}

// Отказ до изменения: система не тронута, снимка нет.
func TestProfileRefusals(t *testing.T) {
	s := installed(t)
	if _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	restarts := s.restarts
	for name, run := range map[string]func() error{
		"плохое имя":  func() error { _, err := s.app.ProfileAdd(ctx(t), "Phone", ShareOptions{}); return err },
		"повтор":      func() error { _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{}); return err },
		"rm нет":      func() error { return s.app.ProfileRemove(ctx(t), "none") },
		"rm плохое":   func() error { return s.app.ProfileRemove(ctx(t), "../x") },
		"show плохое": func() error { _, err := s.app.ProfileShow(ctx(t), "a b", ShareOptions{}); return err },
	} {
		if err := run(); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v, нужен ErrInput", name, err)
		}
	}
	if after := s.snap(t); !before.equal(after) || s.restarts != restarts {
		t.Fatal("отказ изменил систему")
	}
}

func TestProfileNeedsInstallAndRoot(t *testing.T) {
	s := newFresh(t)
	if _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{}); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("add без установки: %v", err)
	}
	if _, err := s.app.ProfileList(ctx(t)); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("list без установки: %v", err)
	}
	s.f.SetEffective(platform.Owner{UID: 1000, GID: 1000})
	var pe *PreflightError
	if _, err := s.app.ProfileList(ctx(t)); !errors.As(err, &pe) || pe.Issues[0].Code != server.CodeNotRoot {
		t.Fatalf("list не от root: %v", err)
	}
}

// Провал контроля после добавления откатывает транзакцию: профиля нет ни в состоянии, ни в
// конфигурации.
func TestProfileAddRollsBack(t *testing.T) {
	s := installed(t)
	before := s.snap(t)
	s.nRestart, s.restartListens = 0, []bool{false}
	if _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{}); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("ждали ErrRolledBack: %v", err)
	}
	if after := s.snap(t); !before.equal(after) {
		t.Fatal("откат не вернул исходное")
	}
	if list, err := s.app.ProfileList(ctx(t)); err != nil || len(list.Profiles) != 0 {
		t.Fatalf("профиль остался: %+v %v", list, err)
	}
}

// Идентификатор клиента — ключ доступа: его нет ни в ошибках, ни в журнале xm, в том числе при
// откате после добавления и после удаления профиля.
func TestProfileIDNotInJournalOrErrors(t *testing.T) {
	s := installed(t)
	if _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	pid := idOf(t, s, "phone")
	s.nRestart, s.restartListens = 0, []bool{false}
	_, addErr := s.app.ProfileAdd(ctx(t), "laptop", ShareOptions{})
	if !errors.Is(addErr, ErrRolledBack) {
		t.Fatalf("ждали откат: %v", addErr)
	}
	s.nRestart, s.restartListens, s.testExit = 0, nil, 23 // отказ проверки до перезапуска
	rmErr := s.app.ProfileRemove(ctx(t), "phone")
	if !errors.Is(rmErr, ErrRolledBack) {
		t.Fatalf("ждали откат: %v", rmErr)
	}
	for _, e := range []error{addErr, rmErr} {
		if strings.Contains(e.Error(), pid) {
			t.Fatalf("идентификатор в ошибке: %v", e)
		}
	}
	for _, j := range s.f.Journaled() {
		if strings.Contains(j.Message, pid) {
			t.Fatalf("идентификатор в журнале xm: %q", j.Message)
		}
	}
}

// Параллельные добавления не теряют друг друга: чтение и запись состояния — под одной
// блокировкой (Change.Edit).
func TestProfileAddConcurrent(t *testing.T) {
	s := installed(t)
	names := []string{"a1", "a2", "a3", "a4"}
	errs := make(chan error, len(names))
	for _, n := range names {
		go func() { _, err := s.app.ProfileAdd(ctx(t), n, ShareOptions{}); errs <- err }()
	}
	for range names {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.app.ProfileList(ctx(t))
	if err != nil || len(list.Profiles) != len(names) {
		t.Fatalf("профили: %+v %v", list, err)
	}
}

// Добавление без имени даёт profile-N; ответ содержит ссылку на каждый адрес сервера с ключом
// профиля и QR; профиль уже в конфигурации.
func TestProfileAddDefaultNameAndLinks(t *testing.T) {
	s := installed(t)
	v, err := s.app.ProfileAdd(ctx(t), "", ShareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "profile-1" || !v.Enabled || len(v.Links) != 1 || v.Links[0].Address != "203.0.113.10" || v.QR == "" {
		t.Fatalf("профиль: %+v", v.Profile)
	}
	pid := idOf(t, s, "profile-1")
	if !strings.HasPrefix(v.Links[0].URI, "vless://"+pid+"@203.0.113.10:") || !strings.Contains(readConfig(t, s), pid) {
		t.Fatal("ссылка или конфигурация без ключа профиля")
	}
	if v2, err := s.app.ProfileAdd(ctx(t), "", ShareOptions{}); err != nil || v2.Name != "profile-2" {
		t.Fatalf("второй: %+v %v", v2.Name, err)
	}
}

// Клиент, которому сервер не подойдёт, отказывает до изменения: профиль не создан, служба не
// перезапущена. Неизвестный клиент — ошибка ввода.
func TestProfileAddClientCheck(t *testing.T) {
	s := installed(t)
	restarts := s.restarts
	_, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{Client: "sing-box"})
	if !errors.Is(err, profile.ErrIncompatible) || errors.Is(err, ErrInput) || !strings.Contains(err.Error(), "X25519MLKEM768") {
		t.Fatalf("sing-box: %v", err)
	}
	if _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{Client: "nope"}); !errors.Is(err, ErrInput) {
		t.Fatalf("неизвестный клиент: %v", err)
	}
	if list, _ := s.app.ProfileList(ctx(t)); len(list.Profiles) != 0 || s.restarts != restarts {
		t.Fatalf("после отказа: %+v, перезапусков %d", list, s.restarts-restarts)
	}
	if _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{Client: "hiddify-5"}); err != nil {
		t.Fatalf("hiddify-5: %v", err)
	}
}

// Список не содержит секретов; показ с чужим адресом — ошибка ввода.
func TestProfileListHasNoSecretsAndShowAddress(t *testing.T) {
	s := installed(t)
	if _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	pid := idOf(t, s, "phone")
	list, _ := s.app.ProfileList(ctx(t))
	if doc, _ := json.Marshal(list); strings.Contains(string(doc), pid) || strings.Contains(string(doc), "vless") {
		t.Fatalf("секрет в списке: %s", doc)
	}
	if _, err := s.app.ProfileShow(ctx(t), "phone", ShareOptions{Address: "198.51.100.1"}); !errors.Is(err, ErrInput) {
		t.Fatalf("чужой адрес: %v", err)
	}
}

// Число профилей и таблица клиентов — в status.
func TestStatusHasProfilesAndClients(t *testing.T) {
	s := installed(t)
	st, _ := s.app.s.Store.Load()
	st.Core.Version = v1
	if err := s.app.Apply(ctx(t), Change{Reason: "x", State: st, Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.app.ProfileAdd(ctx(t), "phone", ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.app.Status(ctx(t))
	if err != nil || got.Profiles != 1 || got.Clients == nil {
		t.Fatalf("status: %+v %v", got, err)
	}
}
