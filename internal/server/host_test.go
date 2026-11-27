package server

import (
	"slices"
	"testing"

	"github.com/grokki91/xray_core/internal/platform"
)

func TestMemory(t *testing.T) {
	h := newHost(t)
	h.write(t, "/proc/meminfo", "MemTotal: 2000 kB\nMemFree: 1 kB\nMemAvailable: 150 kB\n")
	got, err := h.m.Memory(ctx(t))
	if err != nil || got != (Memory{AvailKiB: 150, TotalKiB: 2000}) {
		t.Errorf("Memory = %+v, %v", got, err)
	}
	h.write(t, "/proc/meminfo", "MemTotal: 2000 kB\n")
	if _, err := h.m.Memory(ctx(t)); err == nil {
		t.Error("нет MemAvailable — нужна ошибка")
	}
}

func TestDisk(t *testing.T) {
	h := newHost(t)
	h.f.SetUsage("/var/lib/xm", platform.DiskUsage{Avail: 5, Total: 10})
	if got, err := h.m.Disk(ctx(t), "/var/lib/xm"); err != nil || got.Avail != 5 || got.Total != 10 {
		t.Errorf("Disk = %+v, %v", got, err)
	}
}

func TestOOMKills(t *testing.T) {
	h := newHost(t)
	var args []string
	out := "xray.service: Failed with result 'oom-kill'.\n\nxray.service: Failed with result 'oom-kill'.\n"
	h.f.Handle("journalctl", func(c platform.Command) (platform.Result, error) {
		args = c.Args
		return platform.Result{Stdout: []byte(out)}, nil
	})
	n, err := h.m.OOMKills(ctx(t))
	if err != nil || n != 2 {
		t.Errorf("OOMKills = %d, %v; нужно 2", n, err)
	}
	// Выборка — только записи самого systemd об этом юните с итогом oom-kill.
	for _, a := range []string{"_PID=1", "UNIT=xray.service", "UNIT_RESULT=oom-kill", "--boot"} {
		if !slices.Contains(args, a) {
			t.Errorf("аргументы journalctl %q без %s", args, a)
		}
	}
	h.f.Handle("journalctl", func(platform.Command) (platform.Result, error) { return platform.Result{ExitCode: 1}, nil })
	if _, err := h.m.OOMKills(ctx(t)); err == nil {
		t.Error("ненулевой код journalctl — нужна ошибка")
	}
}

func TestClockSynced(t *testing.T) {
	for out, want := range map[string]any{"yes\n": true, "no\n": false, "maybe\n": nil, "": nil} {
		h := newHost(t)
		h.f.Handle("timedatectl", func(c platform.Command) (platform.Result, error) {
			if !slices.Equal(c.Args, []string{"show", "--property=NTPSynchronized", "--value"}) {
				t.Errorf("аргументы timedatectl: %q", c.Args)
			}
			return platform.Result{Stdout: []byte(out)}, nil
		})
		got, err := h.m.ClockSynced(ctx(t))
		if want == nil {
			if err == nil {
				t.Errorf("%q: нужна ошибка разбора", out)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: %v, %v; нужно %v", out, got, err, want)
		}
	}
}
