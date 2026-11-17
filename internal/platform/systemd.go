package platform

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// systemctl — программа управления systemd; путь — в закрытом списке programs.
const systemctl = "systemctl"

// ServiceUnit — единственный юнит, которым управляет xm (docs/architecture/data-model.md §1).
const ServiceUnit = "xray.service"

// ErrNoSystemd — systemd не работает как система инициализации (контейнер, chroot, ранняя загрузка).
var ErrNoSystemd = errors.New("systemd не работает как система инициализации")

// Systemd — управление юнитом ServiceUnit. Других юнитов порт не знает: имя не параметр, как
// у Users (docs/security/policy.md §3). Контекст каждого вызова обязан нести срок.
type Systemd interface {
	// Running проверяет, что система загружена под systemd; иначе ErrNoSystemd.
	Running(ctx context.Context) error
	// Reload перечитывает файлы юнитов (daemon-reload).
	Reload(ctx context.Context) error
	// Enable включает запуск при загрузке; службу не запускает.
	Enable(ctx context.Context) error
	Disable(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context) error
	// Status — состояние юнита; отсутствие файла юнита — не ошибка (Loaded=false).
	Status(ctx context.Context) (UnitStatus, error)
}

// UnitStatus — состояние юнита по systemctl show.
type UnitStatus struct {
	Loaded   bool   // файл юнита найден (LoadState=loaded)
	Active   string // ActiveState: active, inactive, activating, deactivating, failed, reloading
	Sub      string // SubState: running, dead, auto-restart, …
	Enabled  bool   // UnitFileState=enabled
	Restarts int    // NRestarts: авто-перезапуски systemd; когда счётчик сбрасывается — compatibility.md §1
	MainPID  int
}

// systemd работает через Platform.Exec: одна реализация для Real и Fake, подделка отвечает на
// Handle("systemctl", …).
type systemd struct{ p Platform }

// Systemd возвращает управление юнитом.
func (r *Real) Systemd() Systemd { return systemd{r} }

// Systemd возвращает управление юнитом; ответы — обработчик Handle("systemctl", …).
func (f *Fake) Systemd() Systemd { return systemd{f} }

var systemctlBase = []string{"--no-ask-password", "--no-pager"}

func (s systemd) run(ctx context.Context, args ...string) (Result, error) {
	return s.p.Exec(ctx, Command{Program: systemctl, Args: append(append([]string{}, systemctlBase...), args...)})
}

// verb выполняет «systemctl <глагол> xray.service»; ненулевой код — ошибка.
func (s systemd) verb(ctx context.Context, verb string) error {
	res, err := s.run(ctx, verb, ServiceUnit)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("systemctl %s %s: код %d", verb, ServiceUnit, res.ExitCode)
	}
	return nil
}

func (s systemd) Running(ctx context.Context) error {
	res, err := s.run(ctx, "is-system-running")
	if err != nil {
		return err
	}
	// degraded — система работает, но какой-то юнит упал: для управления xray это не помеха.
	switch strings.TrimSpace(string(res.Stdout)) {
	case "running", "degraded":
		return nil
	}
	return ErrNoSystemd
}

func (s systemd) Reload(ctx context.Context) error {
	res, err := s.run(ctx, "daemon-reload")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("systemctl daemon-reload: код %d", res.ExitCode)
	}
	return nil
}

func (s systemd) Enable(ctx context.Context) error  { return s.verb(ctx, "enable") }
func (s systemd) Disable(ctx context.Context) error { return s.verb(ctx, "disable") }
func (s systemd) Start(ctx context.Context) error   { return s.verb(ctx, "start") }
func (s systemd) Stop(ctx context.Context) error    { return s.verb(ctx, "stop") }
func (s systemd) Restart(ctx context.Context) error { return s.verb(ctx, "restart") }

var statusProperties = []string{"LoadState", "ActiveState", "SubState", "UnitFileState", "NRestarts", "MainPID"}

func (s systemd) Status(ctx context.Context) (UnitStatus, error) {
	res, err := s.run(ctx, "show", ServiceUnit, "--property="+strings.Join(statusProperties, ","))
	if err != nil {
		return UnitStatus{}, err
	}
	if res.ExitCode != 0 {
		return UnitStatus{}, fmt.Errorf("systemctl show %s: код %d", ServiceUnit, res.ExitCode)
	}
	kv := map[string]string{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[k] = v
		}
	}
	for _, k := range statusProperties {
		if _, ok := kv[k]; !ok {
			return UnitStatus{}, fmt.Errorf("systemctl show %s: нет свойства %s", ServiceUnit, k)
		}
	}
	restarts, err1 := strconv.Atoi(kv["NRestarts"])
	pid, err2 := strconv.Atoi(kv["MainPID"])
	if err1 != nil || err2 != nil || restarts < 0 || pid < 0 {
		return UnitStatus{}, fmt.Errorf("systemctl show %s: нечисловые NRestarts или MainPID", ServiceUnit)
	}
	return UnitStatus{
		Loaded:   kv["LoadState"] == "loaded",
		Active:   kv["ActiveState"],
		Sub:      kv["SubState"],
		Enabled:  kv["UnitFileState"] == "enabled",
		Restarts: restarts,
		MainPID:  pid,
	}, nil
}
