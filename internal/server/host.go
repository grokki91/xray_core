package server

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/grokki91/xray_core/internal/platform"
)

// Измерения узла для категории host диагностики (ADR-0024): только чтение.

// Memory — память узла из /proc/meminfo, в КиБ: Avail — MemAvailable, оценка ядра того, что
// можно занять без подкачки.
type Memory struct {
	AvailKiB, TotalKiB int64
}

// Memory читает MemAvailable и MemTotal.
func (m *Manager) Memory(context.Context) (Memory, error) {
	total, err := m.meminfo("MemTotal")
	if err != nil {
		return Memory{}, err
	}
	avail, err := m.meminfo("MemAvailable")
	if err != nil {
		return Memory{}, err
	}
	return Memory{AvailKiB: avail, TotalKiB: total}, nil
}

// Disk — место файловой системы, на которой лежит path.
func (m *Manager) Disk(_ context.Context, path string) (platform.DiskUsage, error) {
	return m.p.FS().Usage(path)
}

// OOMKills — сколько раз с загрузки служба xray завершилась по нехватке памяти: записи journald
// от самого systemd (_PID=1 — поле, которое ставит journald, процесс его не подделает) с
// UNIT_RESULT=oom-kill для xray.service. Сообщения Xray в выборку не попадают.
func (m *Manager) OOMKills(ctx context.Context) (int, error) {
	res, err := m.p.Exec(ctx, platform.Command{Program: platform.Journalctl, Args: []string{
		"--no-pager", "--quiet", "--boot", "--output=cat",
		"_PID=1", "UNIT=" + platform.ServiceUnit, "UNIT_RESULT=oom-kill",
	}})
	if err != nil {
		return 0, err
	}
	if res.ExitCode != 0 {
		return 0, fmt.Errorf("journalctl: код %d", res.ExitCode)
	}
	n := 0
	for _, line := range bytes.Split(res.Stdout, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			n++
		}
	}
	return n, nil
}

// ClockSynced — синхронизированы ли часы по NTP по данным systemd (timedatectl,
// NTPSynchronized): значение — строго yes или no.
func (m *Manager) ClockSynced(ctx context.Context) (bool, error) {
	res, err := m.p.Exec(ctx, platform.Command{Program: platform.Timedatectl, Args: []string{
		"show", "--property=NTPSynchronized", "--value",
	}})
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, fmt.Errorf("timedatectl: код %d", res.ExitCode)
	}
	switch v := strings.TrimSpace(string(res.Stdout)); v {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	default:
		return false, fmt.Errorf("timedatectl: неожиданное значение NTPSynchronized")
	}
}
