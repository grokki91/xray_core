package update

import (
	"context"
	"errors"
	"testing"
	"time"
)

type lookup struct {
	latest string
	tags   []string
}

func (l *lookup) Latest(context.Context) (Release, error) { return Release{Tag: "v" + l.latest}, nil }
func (l *lookup) Tag(_ context.Context, v string) (Release, error) {
	l.tags = append(l.tags, v)
	return Release{Tag: "v" + v}, nil
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"26.11.9", "26.11.9", 0}, {"26.9.30", "26.10.21", -1}, {"26.11.10", "26.11.9", 1}, {"27.0.0", "26.99.99", 1}}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s, %s) = %d, нужно %d", c.a, c.b, got, c.want)
		}
	}
}

// Выбор: latest в диапазоне — он; новее верхней границы — релиз границы по тегу; старше нижней — ошибка.
func TestChoose(t *testing.T) {
	rg := Range{Min: "26.10.21", Max: "26.11.9"}
	cases := map[string]struct {
		latest, target string
		tags           int
	}{
		"в диапазоне":     {"26.10.31", "26.10.31", 0},
		"верхняя граница": {"26.11.9", "26.11.9", 0},
		"новее диапазона": {"26.12.1", "26.11.9", 1},
	}
	for name, c := range cases {
		l := &lookup{latest: c.latest}
		target, latest, err := Choose(ctx(t), l, rg)
		if err != nil || target.Version() != c.target || latest.Version() != c.latest || len(l.tags) != c.tags {
			t.Errorf("%s: %v %v %v теги %v", name, target, latest, err, l.tags)
		}
	}
	if _, _, err := Choose(ctx(t), &lookup{latest: "26.9.9"}, rg); !errors.Is(err, ErrBelowRange) {
		t.Fatalf("старше диапазона: %v", err)
	}
}

func TestVerifiedRangeIsOrdered(t *testing.T) {
	rg := Verified()
	if Compare(rg.Min, rg.Max) > 0 || !rg.Contains(rg.Min) || !rg.Contains(rg.Max) {
		t.Fatalf("диапазон %+v", rg)
	}
}

func TestTagRequestsExactRelease(t *testing.T) {
	f, g := env(t)
	f.Serve(tagURL+"v26.10.31", releaseJSON("v26.10.31", false, "sha256:00"))
	r, err := g.Tag(ctx(t), "26.10.31")
	if err != nil || r.Tag != "v26.10.31" {
		t.Fatalf("%v %v", r, err)
	}
	f.Serve(tagURL+"v26.10.21", releaseJSON("v26.10.31", false, "sha256:00"))
	if _, err := g.Tag(ctx(t), "26.10.21"); err == nil {
		t.Fatal("другой тег в ответе принят")
	}
	f.Serve(tagURL+"v26.9.9", releaseJSON("v26.9.9", true, "sha256:00"))
	if _, err := g.Tag(ctx(t), "26.9.9"); err == nil {
		t.Fatal("предварительный релиз принят")
	}
	if _, err := g.Tag(ctx(t), "1.2/../3"); err == nil {
		t.Fatal("версия не N.N.N принята")
	}
}

func TestChecksRoundTripAndRejectsBadVersion(t *testing.T) {
	f, _ := env(t)
	c := NewChecks(f)
	if _, ok, err := c.Load(); ok || err != nil {
		t.Fatalf("до проверки: %v %v", ok, err)
	}
	in := Check{Target: "26.11.9", Latest: "26.12.1", Checked: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := c.Save(in); err != nil {
		t.Fatal(err)
	}
	if out, ok, err := c.Load(); !ok || err != nil || out != in {
		t.Fatalf("%+v %v %v", out, ok, err)
	}
	if err := c.Save(Check{Target: "\x1b[31m", Latest: "26.12.1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Load(); err == nil {
		t.Fatal("версия с управляющими символами принята")
	}
}
