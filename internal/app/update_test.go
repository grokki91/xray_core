package app

import (
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/store"
)

const vOld = "26.9.30" // версия старше предыдущей: после обновления удаляется

// installedOn — установка на v1; выложенная v2 убрана, чтобы обновление выложило её из архива
// источника; рядом лежит устаревшая vOld.
func installedOn(t *testing.T) *sys {
	t.Helper()
	s := newSys(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "install", State: stateOf("phone"), Unit: unit1}); err != nil {
		t.Fatal(err)
	}
	if err := s.f.FS().RemoveTree(platform.CoreDir + "/" + v2); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{vOld, "foreign"} {
		if err := os.MkdirAll(s.f.Path(platform.CoreDir+"/"+d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s.rel.tag, s.rel.archive = "v"+v2, release(t)
	return s
}

func coreDirs(t *testing.T, s *sys) []string {
	t.Helper()
	names, err := s.f.FS().ReadDir(platform.CoreDir)
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(names, func(n string) bool { return n == "current" })
}

func TestUpdateSwitchesRecordsAndPrunes(t *testing.T) {
	s := installedOn(t)
	res, err := s.app.Update(ctx(t), UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updated || res.Current != v1 || res.Target != v2 || !res.InRange || res.Unchecked == "" {
		t.Fatalf("итог: %+v", res)
	}
	got := s.snap(t)
	// Удалена только vOld: активная, предыдущая, current и чужое имя на месте.
	if got.current != v2 || !got.active || got.tx {
		t.Fatalf("после обновления: %+v", got)
	}
	st, err := s.app.s.Store.Load()
	if err != nil || st.Core.Version != v2 || st.Core.Previous != v1 {
		t.Fatalf("состояние: %+v %v", st.Core, err)
	}
	if dirs := coreDirs(t, s); !slices.Equal(dirs, []string{v1, v2, "foreign"}) {
		t.Fatalf("версии на диске: %v", dirs)
	}
	// status без сети видит, что новее в диапазоне нет.
	stat, err := s.app.Status(ctx(t))
	if err != nil || stat.Update.Version != "" || stat.Update.Checked == "" {
		t.Fatalf("status.update: %+v %v", stat.Update, err)
	}
}

// Провал контроля — автоматический откат: current и состояние прежние, версии не удалены.
func TestUpdateControlFailureRollsBack(t *testing.T) {
	s := installedOn(t)
	before := s.snap(t)
	s.restartListens = append(make([]bool, s.nRestart), false) // следующий перезапуск порт не поднимает
	for i := range s.nRestart {
		s.restartListens[i] = true
	}
	if _, err := s.app.Update(ctx(t), UpdateOptions{}); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("нужен откат: %v", err)
	}
	after := s.snap(t)
	if after.current != v1 || !after.active || after.tx || string(after.state) != string(before.state) {
		t.Fatalf("после отката: %+v", after)
	}
	if dirs := coreDirs(t, s); !slices.Contains(dirs, vOld) {
		t.Fatalf("при провале удалены версии: %v", dirs)
	}
}

// Провал `xray run -test` новой версией — служба не тронута.
func TestUpdateValidateFailureKeepsService(t *testing.T) {
	s := installedOn(t)
	restarts := s.restarts
	s.controlExits = []int{23} // после установки `run -test` отвечает из controlExits
	if _, err := s.app.Update(ctx(t), UpdateOptions{}); err == nil {
		t.Fatal("конфигурация отвергнута, а обновление прошло")
	}
	if got := s.snap(t); got.current != v1 || s.restarts != restarts {
		t.Fatalf("служба тронута: %+v, перезапусков %d", got, s.restarts-restarts)
	}
}

func TestUpdateCheckChangesNothing(t *testing.T) {
	s := installedOn(t)
	before := s.snap(t)
	res, err := s.app.Update(ctx(t), UpdateOptions{Check: true})
	if err != nil || res.Updated || res.Target != v2 || s.rel.fetches != 0 {
		t.Fatalf("%+v %v загрузок %d", res, err, s.rel.fetches)
	}
	if !s.snap(t).equal(before) {
		t.Fatal("--check изменил систему")
	}
	stat, err := s.app.Status(ctx(t))
	if err != nil || stat.Update.Version != v2 {
		t.Fatalf("status не показал доступную версию: %+v %v", stat.Update, err)
	}
}

func TestUpdateHoldChangesNothing(t *testing.T) {
	s := installedOn(t)
	if err := s.app.Apply(ctx(t), Change{Reason: "hold", Edit: func(st store.State) (store.State, error) {
		st.Core.Hold = true
		return st, nil
	}}); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	for _, o := range []UpdateOptions{{}, {To: v2}} {
		res, err := s.app.Update(ctx(t), o)
		if err != nil || !res.Held || res.Updated {
			t.Fatalf("%+v: %+v %v", o, res, err)
		}
	}
	if !s.snap(t).equal(before) || s.rel.fetches != 0 {
		t.Fatal("удержание не соблюдено")
	}
}

// Latest новее диапазона: ставится верхняя граница, запрошенная по тегу.
func TestUpdatePicksRangeMaxWhenLatestNewer(t *testing.T) {
	s := installedOn(t)
	s.rel.tag = "v99.0.0"
	res, err := s.app.Update(ctx(t), UpdateOptions{Check: true})
	if err != nil || res.Target != v2 || res.Latest != "99.0.0" || !slices.Equal(s.rel.tags, []string{v2}) {
		t.Fatalf("%+v %v теги %v", res, err, s.rel.tags)
	}
}

// --to вне диапазона ставится с пометкой in_range=false; итог проверки не перезаписывается.
func TestUpdateToOutsideRange(t *testing.T) {
	s := installedOn(t)
	res, err := s.app.Update(ctx(t), UpdateOptions{Check: true, To: "v99.0.0"})
	if err != nil || res.Target != "99.0.0" || res.InRange || s.rel.latestCalls != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, ok, _ := s.app.s.Checks.Load(); ok {
		t.Fatal("--to записал итог проверки")
	}
}

func TestUpdateRejectsInput(t *testing.T) {
	s := installedOn(t)
	for _, to := range []string{"latest", "1.2", "1.2.3/../4", "v1.2.3\n"} {
		if _, err := s.app.Update(ctx(t), UpdateOptions{To: to}); !errors.Is(err, ErrInput) {
			t.Errorf("--to %q: %v", to, err)
		}
	}
	if len(s.rel.tags)+s.rel.latestCalls != 0 {
		t.Fatal("неверный ввод дошёл до сети")
	}
}

func TestUpdateNotInstalled(t *testing.T) {
	s := fresh(t)
	if _, err := s.app.Update(ctx(t), UpdateOptions{}); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("%v", err)
	}
}

// install выбирает версию тем же правилом, что update: latest новее диапазона — верхняя граница.
func TestInstallPicksRangeMax(t *testing.T) {
	s := fresh(t)
	s.rel.tag = "v99.0.0"
	res, err := s.app.Install(ctx(t), okOpts)
	if err != nil || res.Xray != v2 || !slices.Equal(s.rel.tags, []string{v2}) {
		t.Fatalf("%+v %v теги %v", res, err, s.rel.tags)
	}
}

// Повторное обновление на ту же версию ничего не удаляет и не меняет.
func TestUpdateSameVersionChangesNothing(t *testing.T) {
	s := installedOn(t)
	if _, err := s.app.Update(ctx(t), UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	before := s.snap(t)
	res, err := s.app.Update(ctx(t), UpdateOptions{})
	if err != nil || res.Updated || !s.snap(t).equal(before) {
		t.Fatalf("%+v %v", res, err)
	}
	if dirs := coreDirs(t, s); !slices.Equal(dirs, []string{v1, v2, "foreign"}) {
		t.Fatalf("версии: %v", dirs)
	}
}
