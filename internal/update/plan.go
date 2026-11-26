package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// Range — проверенный диапазон версий Xray: границы включительно, N.N.N. Версии между границами
// считаются проверенными (docs/operations/updates.md §2, ADR-0043).
type Range struct{ Min, Max string }

// Verified — проверенный диапазон этой версии xm: версии, на которых прошли L3 и сверена
// таблица совместимости клиентов (docs/compatibility.md). Расширяется выпуском xm.
func Verified() Range { return Range{Min: "26.10.21", Max: "26.11.9"} }

// Contains сообщает, входит ли версия в диапазон.
func (r Range) Contains(v string) bool { return Compare(v, r.Min) >= 0 && Compare(v, r.Max) <= 0 }

// Compare сравнивает версии N.N.N покомпонентно: -1, 0, 1. Ввод проверен platform.ValidVersion.
func Compare(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range 3 {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

// Lookup — что нужно выбору версии от источника; настоящий — GitHub.
type Lookup interface {
	Latest(ctx context.Context) (Release, error)
	Tag(ctx context.Context, version string) (Release, error)
}

// ErrBelowRange — последний стабильный релиз старше проверенного диапазона: ставить нечего.
var ErrBelowRange = errors.New("последний стабильный релиз старше проверенного диапазона")

// Choose — последний стабильный релиз внутри диапазона и последний стабильный вообще: latest
// новее верхней границы — берётся релиз верхней границы по тегу (ADR-0043).
func Choose(ctx context.Context, src Lookup, rg Range) (target, latest Release, err error) {
	latest, err = src.Latest(ctx)
	if err != nil {
		return Release{}, Release{}, err
	}
	switch v := latest.Version(); {
	case Compare(v, rg.Min) < 0:
		return Release{}, latest, fmt.Errorf("%w: %s < %s", ErrBelowRange, v, rg.Min)
	case Compare(v, rg.Max) <= 0:
		return latest, latest, nil
	}
	target, err = src.Tag(ctx, rg.Max)
	return target, latest, err
}

// checkFile — итог последней проверки обновления: его читает `xm status` без сети. Лежит в
// кэше update (docs/architecture/data-model.md §1).
const checkFile = cacheDir + "/update-check.json"

// Check — итог проверки: целевая версия внутри диапазона, последняя стабильная и когда проверено.
type Check struct {
	Target  string    `json:"target"`
	Latest  string    `json:"latest"`
	Checked time.Time `json:"checked"`
}

// Checks — запись и чтение итога последней проверки.
type Checks struct{ p platform.Platform }

func NewChecks(p platform.Platform) *Checks { return &Checks{p: p} }

// Save записывает итог атомарно (0600).
func (c *Checks) Save(ch Check) error {
	for _, dir := range []string{dataDir, cacheDir} {
		if err := c.p.FS().Mkdir(dir, 0o700, platform.Root()); err != nil {
			return fmt.Errorf("итог проверки: %w", err)
		}
	}
	data, err := json.Marshal(ch)
	if err != nil {
		return err
	}
	if err := c.p.FS().WriteFile(checkFile, data, 0o600, platform.Root()); err != nil {
		return fmt.Errorf("итог проверки: %w", err)
	}
	return nil
}

// Load читает итог; проверки не было — ok=false без ошибки. Версии в файле проверяются: файл
// печатается человеку.
func (c *Checks) Load() (ch Check, ok bool, err error) {
	data, err := c.p.FS().ReadFile(checkFile)
	if errors.Is(err, platform.ErrNotFound) {
		return Check{}, false, nil
	}
	if err != nil {
		return Check{}, false, fmt.Errorf("итог проверки: %w", err)
	}
	// Испорченный файл — отказ с подсказкой: xm update --check его перезаписывает (ADR-0043).
	if err := json.Unmarshal(data, &ch); err != nil {
		return Check{}, false, fmt.Errorf("итог проверки %s испорчен (%w): выполните xm update --check", checkFile, err)
	}
	if !platform.ValidVersion(ch.Target) || !platform.ValidVersion(ch.Latest) {
		return Check{}, false, fmt.Errorf("итог проверки %s испорчен (версия не вида N.N.N): выполните xm update --check", checkFile)
	}
	return ch, true, nil
}
