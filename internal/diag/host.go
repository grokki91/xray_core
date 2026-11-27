package diag

import (
	"context"

	"github.com/grokki91/xray_core/internal/platform"
)

// Категория host — ресурсы узла (ADR-0024): место, память, завершения по нехватке памяти, часы.
// Пороги — ответ владельца 2026-11-27.

// HostDeps — измерения узла (server: Disk, Memory, OOMKills, ClockSynced).
type HostDeps struct {
	Disk        func(ctx context.Context, path string) (platform.DiskUsage, error)
	Memory      func(ctx context.Context) (availKiB, totalKiB int64, err error)
	OOMKills    func(ctx context.Context) (int, error)
	ClockSynced func(ctx context.Context) (bool, error)
}

const (
	CheckDisk   = "host.disk"
	CheckMemory = "host.memory"
	CheckOOM    = "host.memory.oom"
	CheckClock  = "host.clock"
)

// diskPaths — где xm держит состояние, снимки и версии Xray (docs/architecture/data-model.md §1).
var diskPaths = []string{"/var/lib/xm", "/usr/local/lib/xm"}

// Мало места — меньше 10 % или меньше 500 МБ: столько нужно на снимок, загрузку релиза и откат.
const (
	diskMinPercent = 10
	diskMinBytes   = 500 << 20
	memMinPercent  = 10
)

type disk struct{ d HostDeps }

func (disk) ID() string         { return CheckDisk }
func (disk) Requires() []string { return nil }

func (c disk) Run(ctx context.Context) []Observation {
	var out []Observation
	for _, p := range diskPaths {
		target := "disk:" + p
		u, err := c.d.Disk(ctx, p)
		if err != nil || u.Total == 0 {
			out = append(out, errObs(target, "не удалось узнать место файловой системы")...)
			continue
		}
		ok := u.Avail >= diskMinBytes && u.Avail*100 >= u.Total*diskMinPercent
		out = append(out, obs(target, ok, map[string]uint64{"avail": u.Avail, "total": u.Total},
			"место доступно непривилегированному процессу; резерв root не учитывается")...)
	}
	return out
}

func (disk) Fact(Observation) Finding {
	return Finding{Code: "host.disk.low", Title: "мало места на диске: снимок или обновление могут не пройти", Impact: ImpactDegraded,
		Actions: []string{"df -h; освободить место (journalctl --vacuum-size=100M, старые файлы)"}}
}

type memory struct{ d HostDeps }

func (memory) ID() string         { return CheckMemory }
func (memory) Requires() []string { return nil }

func (c memory) Run(ctx context.Context) []Observation {
	avail, total, err := c.d.Memory(ctx)
	if err != nil || total <= 0 {
		return errObs("memory", "не удалось прочитать /proc/meminfo")
	}
	return obs("memory", avail*100 >= total*memMinPercent, map[string]int64{"avail_kib": avail, "total_kib": total},
		"снимок в момент проверки: пики нагрузки между прогонами не видны")
}

func (memory) Fact(Observation) Finding {
	return Finding{Code: "host.memory.low", Title: "мало свободной памяти", Impact: ImpactDegraded,
		Actions: []string{"free -m; ps aux --sort=-rss | head"}}
}

type oom struct{ d HostDeps }

func (oom) ID() string         { return CheckOOM }
func (oom) Requires() []string { return nil }

func (c oom) Run(ctx context.Context) []Observation {
	n, err := c.d.OOMKills(ctx)
	if err != nil {
		return errObs("xray.service", "не удалось прочитать журнал systemd")
	}
	return obs("xray.service", n == 0, n,
		"считаются завершения службы xray с загрузки системы; другие процессы и прошлые загрузки — нет")
}

func (oom) Fact(Observation) Finding {
	return Finding{Code: "host.memory.oom", Title: "служба xray завершалась по нехватке памяти", Impact: ImpactDegraded,
		Actions: []string{"xm logs --since 24h; free -m — освободить память или увеличить её у хостера"}}
}

type clock struct{ d HostDeps }

func (clock) ID() string         { return CheckClock }
func (clock) Requires() []string { return nil }

func (c clock) Run(ctx context.Context) []Observation {
	ok, err := c.d.ClockSynced(ctx)
	if err != nil {
		return errObs("clock", "не удалось узнать состояние синхронизации часов")
	}
	return obs("clock", ok, ok,
		"флаг systemd NTPSynchronized; величина расхождения с точным временем не измеряется")
}

func (clock) Fact(Observation) Finding {
	return Finding{Code: "host.clock.unsynced", Title: "часы не синхронизированы по NTP", Impact: ImpactDegraded,
		Actions: []string{"timedatectl status; timedatectl set-ntp true"}}
}
