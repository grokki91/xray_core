package diag

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// testProc — клиент самопроверки подделки: живёт до Stop.
type testProc struct {
	done    chan struct{}
	stopped atomic.Bool
}

func newProc(exited bool) *testProc {
	p := &testProc{done: make(chan struct{})}
	if exited {
		close(p.done)
	}
	return p
}

func (p *testProc) Done() <-chan struct{} { return p.done }
func (p *testProc) Stop() {
	if p.stopped.CompareAndSwap(false, true) {
		select {
		case <-p.done:
		default:
			close(p.done)
		}
	}
}

// host — подделка платформы; failFirst — сколько запросов через прокси сначала не проходит
// (клиент ещё поднимается).
type host struct {
	*platform.Fake
	failFirst int32
	viaCalls  atomic.Int32
}

func (h *host) Net() platform.Net { return flaky{h.Fake.Net(), h} }

type flaky struct {
	platform.Net
	h *host
}

func (n flaky) Get(ctx context.Context, r platform.Request) ([]byte, error) {
	if r.Proxy != "" && n.h.viaCalls.Add(1) <= n.h.failFirst {
		return nil, errors.New("сокет ещё не создан")
	}
	return n.Net.Get(ctx, r)
}

type stand struct {
	h      *host
	proc   *testProc
	starts atomic.Int32
	deps   SelftestDeps
}

func newStand(t *testing.T) *stand {
	t.Helper()
	f := platform.NewFake(t.TempDir(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	for _, d := range []string{"/run", "/run/xm"} {
		if err := f.FS().Mkdir(d, 0o700, platform.Root()); err != nil {
			t.Fatal(err)
		}
	}
	f.ServeStatus(selftestURL, 204, nil)
	s := &stand{h: &host{Fake: f}, proc: newProc(false)}
	s.deps = SelftestDeps{Host: s.h, Socket: SelftestSocket, Start: func(context.Context) (Process, error) {
		s.starts.Add(1)
		return s.proc, nil
	}}
	return s
}

func (s *stand) run(t *testing.T) Report {
	t.Helper()
	c := healthy()
	c.selftest = s.deps
	return c.run(t)
}

func TestSelftestOK(t *testing.T) {
	s := newStand(t)
	// След убитого клиента: сокет без процесса удаляется до запуска.
	ln, err := net.Listen("unix", s.h.Path(SelftestSocket))
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	r := s.run(t)
	if r.Health != HealthOK || status(r, CheckSelftest) != StatusOK {
		t.Fatalf("самопроверка: %q %+v", r.Health, r.Observations)
	}
	if _, err := os.Lstat(s.h.Path(SelftestSocket)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("прежний сокет остался: %v", err)
	}
	if !s.proc.stopped.Load() || s.starts.Load() != 1 {
		t.Errorf("клиент: остановлен %v, запусков %d", s.proc.stopped.Load(), s.starts.Load())
	}
	var via, direct int
	for _, c := range s.h.Calls() {
		if c.Op == "get" && c.Proxy == SelftestSocket {
			via++
		} else if c.Op == "get" && c.Proxy == "" {
			direct++
		}
	}
	if via != 1 || direct != 1 {
		t.Errorf("запросов через сокет %d, прямых %d; нужно по одному", via, direct)
	}
	for _, o := range r.Observations {
		if o.Check == CheckSelftest && len(o.Limits) == 0 {
			t.Error("у самопроверки нет limits")
		}
	}
}

// Клиент поднимается не сразу: запрос повторяется до окна, успех после нескольких отказов.
func TestSelftestRetriesWhileClientStarts(t *testing.T) {
	s := newStand(t)
	s.h.failFirst = 5
	if r := s.run(t); status(r, CheckSelftest) != StatusOK {
		t.Fatalf("%+v", r.Observations)
	}
}

// Запрос через сервер не прошёл, хотя адрес достижим напрямую: факт down, вердикт down.
func TestSelftestFailIsDown(t *testing.T) {
	s := newStand(t)
	s.h.ServeVia(selftestURL, 502, nil)
	r := s.run(t)
	if status(r, CheckSelftest) != StatusFail || r.Health != HealthDown {
		t.Fatalf("%q %+v", r.Health, r.Observations)
	}
	if f := r.Cause(); f == nil || f.Code != "reach.selftest.failed" || f.Impact != ImpactDown {
		t.Fatalf("первопричина: %+v", f)
	}
	if !s.proc.stopped.Load() {
		t.Error("клиент не остановлен после провала")
	}
	if now := s.h.Clock().Now(); now.Sub(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) < selftestWindow {
		t.Errorf("провал объявлен до конца окна ожидания: прошло %v", now)
	}
}

// Адрес недоступен с самого сервера: это не провал подключения, а «не измерено» — skip,
// вердикт unknown, клиент не запускался.
func TestSelftestTargetUnreachableIsSkip(t *testing.T) {
	s := newStand(t)
	s.h.Fake = platform.NewFake(t.TempDir(), time.Time{}) // маршрутов нет: 404
	r := s.run(t)
	if status(r, CheckSelftest) != StatusSkip || r.Health != HealthUnknown || s.starts.Load() != 0 {
		t.Fatalf("%q %+v, запусков %d", r.Health, r.Observations, s.starts.Load())
	}
	for _, o := range r.Observations {
		if o.Check == CheckSelftest && (o.Reason == "" || strings.Contains(strings.ToLower(o.Reason), "блок")) {
			t.Errorf("причина skip: %q (нужна причина без вывода о фильтрации)", o.Reason)
		}
	}
}

func TestSelftestClientProblemsAreError(t *testing.T) {
	s := newStand(t)
	s.proc = newProc(true) // клиент завершился сразу, ответа нет
	s.h.failFirst = 1000
	if r := s.run(t); status(r, CheckSelftest) != StatusError || r.Health != HealthUnknown {
		t.Fatalf("клиент завершился: %q %+v", r.Health, r.Observations)
	}

	s = newStand(t)
	s.deps.Start = func(context.Context) (Process, error) {
		return nil, errors.New("секрет в тексте ошибки")
	}
	r := s.run(t)
	if status(r, CheckSelftest) != StatusError {
		t.Fatalf("клиент не запустился: %+v", r.Observations)
	}
	for _, o := range r.Observations {
		if strings.Contains(o.Reason, "секрет") {
			t.Errorf("текст ошибки в причине: %q", o.Reason)
		}
	}

	// На месте сокета каталог: удалить нечем — измерить не удалось, клиент не запускался.
	s = newStand(t)
	if err := s.h.FS().Mkdir(SelftestSocket, 0o700, platform.Root()); err != nil {
		t.Fatal(err)
	}
	if r := s.run(t); status(r, CheckSelftest) != StatusError || s.starts.Load() != 0 {
		t.Fatalf("каталог на месте сокета: %+v, запусков %d", r.Observations, s.starts.Load())
	}
}

// Без слушающего порта самопроверка не измеряется: зависимость от reach.listen.
func TestSelftestRequiresListen(t *testing.T) {
	s := newStand(t)
	c := healthy()
	c.net.on = false
	c.selftest = s.deps
	r := c.run(t)
	if status(r, CheckSelftest) != StatusSkip || s.starts.Load() != 0 {
		t.Fatalf("%+v, запусков %d", r.Observations, s.starts.Load())
	}
}
