package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/backup"
	"github.com/grokki91/xray_core/internal/config"
	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/store"
	"github.com/grokki91/xray_core/internal/update"
)

var (
	oldXM = []byte("#!old xm\n")
	newXM = []byte("#!new xm\n")
)

// selfReady — установка, действующий xm прежней версии и выложенный новый (ADR-0045);
// config.json — «правила прежней версии», которые новый xm должен перерисовать.
func selfReady(t *testing.T) *sys {
	t.Helper()
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{update.BinPath: oldXM, platform.XMNextPath: newXM} {
		if err := s.f.FS().WriteFile(path, data, 0o755, platform.Root()); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.f.FS().WriteFile(config.Path, []byte(`{"old":"rules"}`), 0o640, platform.Root()); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *sys) file(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(s.f.Path(path))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

// Новый xm ставит себя на место прежнего, перерисовывает конфигурацию своими правилами и
// записывает версии в состояние; ключи не меняются.
func TestSelfApplyReplacesRendersRecords(t *testing.T) {
	s := selfReady(t)
	before, err := s.app.s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.app.SelfApply(ctx(t), "0.0.3")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updated || res.Component != "xm" || res.Current != "0.0.3" || res.Target != "0.1.0" {
		t.Fatalf("итог: %+v", res)
	}
	if !bytes.Equal(s.file(t, update.BinPath), newXM) || !bytes.Equal(s.file(t, update.PrevPath), oldXM) {
		t.Fatal("бинарники не заменены")
	}
	st, err := s.app.s.Store.Load()
	if err != nil || st.XM != (store.XM{Version: "0.1.0", Previous: "0.0.3"}) {
		t.Fatalf("состояние xm: %+v %v", st.XM, err)
	}
	if st.Inbounds[0].Reality.PrivateKey != before.Inbounds[0].Reality.PrivateKey {
		t.Fatal("ключи REALITY сменились")
	}
	cfg := s.file(t, config.Path)
	sum := sha256.Sum256(cfg)
	if strings.Contains(string(cfg), "old") || hex.EncodeToString(sum[:]) != st.Applied.ConfigSHA256 {
		t.Fatalf("конфигурация не перерисована:\n%s", cfg)
	}
	if got := s.snap(t); !got.active || got.tx {
		t.Fatalf("после обновления: %+v", got)
	}
}

// Провал контроля — откат: прежний бинарник, состояние и конфигурация на месте.
func TestSelfApplyControlFailureRestoresBinary(t *testing.T) {
	s := selfReady(t)
	before := s.snap(t)
	s.restartListens = append(make([]bool, s.nRestart), false)
	for i := range s.nRestart {
		s.restartListens[i] = true
	}
	if _, err := s.app.SelfApply(ctx(t), "0.0.3"); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("ошибка %v, нужен откат", err)
	}
	if !bytes.Equal(s.file(t, update.BinPath), oldXM) {
		t.Fatal("прежний xm не возвращён")
	}
	if got := s.snap(t); !got.equal(before) {
		t.Fatalf("после отката:\n%+v\nдо:\n%+v", got, before)
	}
}

// Обрыв после журнала: следующий запуск откатывает транзакцию и возвращает прежний xm.
func TestRecoverRestoresReplacedBinary(t *testing.T) {
	s := selfReady(t)
	if err := s.app.s.Self.Install(); err != nil {
		t.Fatal(err)
	}
	snap, err := s.app.s.Backup.Create(ctx(t), "self-update", backup.Meta{XM: "0.1.0", Xray: v1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.app.s.Store.WriteTx(store.Tx{Snapshot: snap.ID, CoreBefore: v1, XMReplaced: true}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.app.Recover(ctx(t)); err != nil || !ok {
		t.Fatalf("откат: %v %v", ok, err)
	}
	if !bytes.Equal(s.file(t, update.BinPath), oldXM) {
		t.Fatal("прежний xm не возвращён")
	}
}

// selfRelease — релиз xm в поддельной сети и ответы нового бинарника.
func selfRelease(t *testing.T, s *sys, tag string, bin []byte, probe string) *[]platform.Command {
	t.Helper()
	sum := sha256.Sum256(bin)
	s.f.Serve("https://api.github.com/repos/grokki91/xray_core/releases/latest", fmt.Appendf(nil, `{"tag_name":%q,"assets":[]}`, tag))
	base := "https://github.com/grokki91/xray_core/releases/download/" + tag + "/"
	s.f.Serve(base+"SHA256SUMS", fmt.Appendf(nil, "%s  xm-linux-amd64\n", hex.EncodeToString(sum[:])))
	s.f.Serve(base+"xm-linux-amd64", bin)
	var calls []platform.Command
	s.f.Handle(platform.XMNext, func(c platform.Command) (platform.Result, error) {
		calls = append(calls, c)
		if c.Args[0] == "version" {
			return platform.Result{Stdout: fmt.Appendf(nil, `{"data":{"xm":%q}}`, probe)}, nil
		}
		return platform.Result{Stdout: []byte(`{"data":{"component":"xm","current":"0.1.0","target":"0.2.0","updated":true}}`)}, nil
	})
	return &calls
}

// Старый xm сверяет и проверяет новый бинарник, отдаёт транзакцию ему и убирает выложенный файл.
func TestUpdateSelfDelegatesToNewBinary(t *testing.T) {
	s := selfReady(t)
	calls := selfRelease(t, s, "v0.2.0", newXM, "0.2.0")
	res, err := s.app.Update(ctx(t), UpdateOptions{Self: true})
	if err != nil || !res.Updated || res.Target != "0.2.0" {
		t.Fatalf("итог %+v, %v", res, err)
	}
	if len(*calls) != 2 || strings.Join((*calls)[1].Args, " ") != "self-apply --previous 0.1.0 --json" {
		t.Fatalf("запуски нового xm: %+v", *calls)
	}
	if s.file(t, platform.XMNextPath) != nil {
		t.Fatal("выложенный бинарник не убран")
	}
}

// Версия нового бинарника не совпала с тегом — self-apply не запускается.
func TestUpdateSelfRejectsVersionMismatch(t *testing.T) {
	s := selfReady(t)
	calls := selfRelease(t, s, "v0.2.0", newXM, "0.1.9")
	if _, err := s.app.Update(ctx(t), UpdateOptions{Self: true}); !errors.Is(err, update.ErrIntegrity) {
		t.Fatalf("ошибка %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("запуски: %+v", *calls)
	}
}

// Релиз не новее — ничего не делается; --self с другими флагами — ошибка ввода.
func TestUpdateSelfNotNewerAndFlags(t *testing.T) {
	s := selfReady(t)
	calls := selfRelease(t, s, "v0.1.0", newXM, "0.1.0")
	if res, err := s.app.Update(ctx(t), UpdateOptions{Self: true}); err != nil || res.Updated || len(*calls) != 0 {
		t.Fatalf("итог %+v, %v, запуски %d", res, err, len(*calls))
	}
	if _, err := s.app.Update(ctx(t), UpdateOptions{Self: true, Check: true}); !errors.Is(err, ErrInput) {
		t.Fatalf("--self --check: %v", err)
	}
}

// Недопустимая --previous — ошибка ввода до всякого изменения: бинарник не заменён.
func TestSelfApplyRejectsBadPrevious(t *testing.T) {
	for _, prev := range []string{"", "../x", "0.1.0 x", "0.1.0\n", strings.Repeat("1", 65)} {
		s := selfReady(t)
		if _, err := s.app.SelfApply(ctx(t), prev); !errors.Is(err, ErrInput) {
			t.Fatalf("%q: ошибка %v", prev, err)
		}
		if !bytes.Equal(s.file(t, update.BinPath), oldXM) || s.file(t, update.PrevPath) != nil {
			t.Fatalf("%q: бинарник тронут", prev)
		}
	}
}

// Запись нового бинарника не удалась после копии прежнего — прежний на месте, без ErrRollbackFailed.
func TestSelfApplyInstallFailureKeepsBinary(t *testing.T) {
	s := selfReady(t)
	s.fs.path, s.fs.exact, s.fs.armed = update.BinPath, true, true
	_, err := s.app.SelfApply(ctx(t), "0.0.3")
	if err == nil || errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("ошибка %v", err)
	}
	if !bytes.Equal(s.file(t, update.BinPath), oldXM) || !bytes.Equal(s.file(t, update.PrevPath), oldXM) || s.fs.armed {
		t.Fatal("прежний xm не на месте или сбой не сработал")
	}
}
