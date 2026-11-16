// Пакет server — узел как целое: годится ли машина, юнит xray.service и управление службой
// (docs/architecture/components.md, server). Побочные эффекты — только через platform. Состояние
// и конфигурацию Xray пакет не читает: пути и изоляцию юнита приносит вызывающий.
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/grokki91/xray_core/internal/platform"
)

// Label — первая строка юнита xm: по ней отличается своя установка от чужой.
const Label = "# managed-by: xm"

// UnitPath — файл юнита (docs/architecture/data-model.md §1): root:root, 0644.
const UnitPath = "/etc/systemd/system/" + platform.ServiceUnit

// execPath — бинарник активной версии: ссылка current (ADR-0019).
const execPath = platform.CoreDir + "/current/xray"

var (
	// ErrForeign — xray.service или конфигурация Xray без метки xm: ничего не перезаписывается.
	ErrForeign = errors.New("чужая установка Xray: юнит без метки xm")
	// ErrSpec — описание юнита не прошло проверку.
	ErrSpec = errors.New("недопустимое описание юнита")
)

// Manager — узел и служба. Создаёт его cmd/xm.
type Manager struct {
	p      platform.Platform
	config string // путь конфигурации Xray (config.Path); менеджеры друг друга не импортируют
}

// New создаёт менеджер; config — абсолютный путь конфигурации Xray.
func New(p platform.Platform, config string) *Manager { return &Manager{p: p, config: config} }

// UnitOption — директива секции [Service] (от security.UnitHardening).
type UnitOption struct{ Key, Value string }

// UnitSpec — то, что вызывающий задаёт в юните; остальное фиксировано.
type UnitSpec struct {
	Hardening []UnitOption
}

// Service — управление службой xray.service.
type Service struct{ s platform.Systemd }

// Status — состояние службы (platform.UnitStatus).
type Status = platform.UnitStatus

// Service возвращает управление службой.
func (m *Manager) Service() Service { return Service{m.p.Systemd()} }

func (s Service) Start(ctx context.Context) error   { return s.s.Start(ctx) }
func (s Service) Stop(ctx context.Context) error    { return s.s.Stop(ctx) }
func (s Service) Restart(ctx context.Context) error { return s.s.Restart(ctx) }
func (s Service) Status(ctx context.Context) (Status, error) {
	return s.s.Status(ctx)
}

var (
	optionKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	pathRe    = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)
	// reserved — директивы, которые задаёт сам xm: переопределение изоляцией — подмена запуска.
	reserved = map[string]bool{"Type": true, "User": true, "ExecStart": true, "Restart": true, "RestartSec": true}
)

// render строит юнит; одно описание — побайтно один файл.
func (m *Manager) render(spec UnitSpec) ([]byte, error) {
	if !pathRe.MatchString(m.config) || strings.Contains(m.config, "..") {
		return nil, fmt.Errorf("%w: путь конфигурации %q", ErrSpec, m.config)
	}
	var b bytes.Buffer
	b.WriteString(Label + "\n[Unit]\nDescription=Xray (managed by xm)\nAfter=network.target nss-lookup.target\n\n[Service]\n")
	fmt.Fprintf(&b, "Type=simple\nUser=%s\nExecStart=%s run -config %s\nRestart=on-failure\nRestartSec=5s\n", platform.ServiceUser, execPath, m.config)
	for _, o := range spec.Hardening {
		if !optionKey.MatchString(o.Key) || reserved[o.Key] {
			return nil, fmt.Errorf("%w: директива %q", ErrSpec, o.Key)
		}
		if o.Value == "" || strings.ContainsAny(o.Value, "\x00\r\n") || strings.TrimSpace(o.Value) != o.Value {
			return nil, fmt.Errorf("%w: значение директивы %s", ErrSpec, o.Key)
		}
		fmt.Fprintf(&b, "%s=%s\n", o.Key, o.Value)
	}
	b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return b.Bytes(), nil
}

// ours сообщает, что файл юнита есть и это юнит xm; чужой юнит — ErrForeign.
func (m *Manager) ours() (exists bool, err error) {
	data, err := m.p.FS().ReadFile(UnitPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("юнит %s: %w", platform.ServiceUnit, err)
	}
	if first, _, _ := bytes.Cut(data, []byte("\n")); string(first) != Label {
		return true, ErrForeign
	}
	return true, nil
}

// InstallUnit записывает юнит с меткой xm, перечитывает юниты и включает автозапуск; службу не
// запускает. Повтор с тем же описанием даёт тот же файл. Чужой юнит не трогается.
func (m *Manager) InstallUnit(ctx context.Context, spec UnitSpec) error {
	data, err := m.render(spec)
	if err != nil {
		return err
	}
	if _, err := m.ours(); err != nil {
		return err
	}
	if err := m.p.FS().WriteFile(UnitPath, data, 0o644, platform.Root()); err != nil {
		return fmt.Errorf("юнит %s: %w", platform.ServiceUnit, err)
	}
	sd := m.p.Systemd()
	if err := sd.Reload(ctx); err != nil {
		return err
	}
	return sd.Enable(ctx)
}

// RemoveUnit выключает автозапуск и удаляет юнит xm; службу не останавливает (Service().Stop).
// Юнита нет — не ошибка; чужой юнит не трогается.
func (m *Manager) RemoveUnit(ctx context.Context) error {
	exists, err := m.ours()
	if err != nil || !exists {
		return err
	}
	sd := m.p.Systemd()
	if err := sd.Disable(ctx); err != nil {
		return err
	}
	if err := m.p.FS().Remove(UnitPath); err != nil {
		return fmt.Errorf("юнит %s: %w", platform.ServiceUnit, err)
	}
	return sd.Reload(ctx)
}
