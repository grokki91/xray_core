package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// Пороги предусловий. Память — по целевой машине (docs/architecture/overview.md §8: 2 ГБ);
// замер памяти Xray — критерий фазы 2, порог пересматривается по нему. Время — отсчёт здравого
// смысла: часы раньше сборки ломают проверку сертификатов при загрузке релиза.
const (
	minMemMiB  = 512
	clockFloor = "2026-11-01T00:00:00Z"
)

// supportedOS — Ubuntu, версии основного уровня (docs/compatibility.md); прочее — остановка,
// пока не решён Q8.
var supportedOS = map[string]bool{"22.04": true, "24.04": true}

// Коды Issue — стабильные строки контракта (docs/architecture/interfaces.md §2).
const (
	CodeNotRoot        = "preflight.not_root"
	CodeOS             = "preflight.os_unsupported"
	CodeArch           = "preflight.arch_unsupported"
	CodeResources      = "preflight.resources"
	CodeSystemd        = "preflight.no_systemd"
	CodeClock          = "preflight.clock"
	CodeForeignInstall = "preflight.foreign_install"
)

// Issue — невыполненное предусловие; любое останавливает установку (код выхода 3).
type Issue struct{ Code, Message string }

// HostFacts — что узнали о машине; пустое поле — не удалось узнать (причина — в Issue).
type HostFacts struct {
	OS     string // «ubuntu 24.04»
	Arch   string
	MemMiB int64
}

// CheckRoot — единственное предусловие команд, которым не нужна вся проверка машины (`status`,
// `start`, `stop`, `restart`): состояние и systemd доступны только root.
func (m *Manager) CheckRoot() (Issue, bool) {
	if m.p.Users().Effective() != platform.Root() {
		return Issue{CodeNotRoot, "нужен root: команды xm запускаются от root"}, true
	}
	return Issue{}, false
}

// Preflight проверяет машину: root, ОС, архитектуру, память, systemd, время, чужую установку.
// Проверки независимы: возвращаются все найденные проблемы.
func (m *Manager) Preflight(ctx context.Context) (HostFacts, []Issue) {
	var facts HostFacts
	var issues []Issue
	add := func(code, format string, a ...any) { issues = append(issues, Issue{code, fmt.Sprintf(format, a...)}) }

	if issue, bad := m.CheckRoot(); bad {
		issues = append(issues, issue)
	}

	id, ver, err := m.osRelease()
	facts.OS = strings.TrimSpace(id + " " + ver)
	switch {
	case err != nil:
		add(CodeOS, "не удалось определить ОС: %v", err)
	case id != "ubuntu" || !supportedOS[ver]:
		add(CodeOS, "ОС %q не поддерживается: нужна Ubuntu 22.04 или 24.04", facts.OS)
	}

	facts.Arch = runtime.GOARCH
	if facts.Arch != "amd64" {
		add(CodeArch, "архитектура %s не поддерживается: нужна x86_64", facts.Arch)
	}

	if mib, err := m.memMiB(); err != nil {
		add(CodeResources, "не удалось узнать объём памяти: %v", err)
	} else {
		facts.MemMiB = mib
		if mib < minMemMiB {
			add(CodeResources, "памяти %d МиБ, нужно не меньше %d", mib, minMemMiB)
		}
	}

	if err := m.p.Systemd().Running(ctx); err != nil {
		add(CodeSystemd, "systemd недоступен: %v", err)
	}

	floor, _ := time.Parse(time.RFC3339, clockFloor)
	if now := m.p.Clock().Now(); now.Before(floor) {
		add(CodeClock, "часы отстают (%s): проверка сертификатов при загрузке не пройдёт", now.UTC().Format(time.DateOnly))
	}

	if foreign, why := m.foreign(); foreign {
		add(CodeForeignInstall, "%s", why)
	}
	return facts, issues
}

// osRelease разбирает /etc/os-release: ID и VERSION_ID.
func (m *Manager) osRelease() (id, version string, err error) {
	data, err := m.p.FS().ReadFile("/etc/os-release")
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	if id == "" || version == "" {
		return "", "", errors.New("нет ID или VERSION_ID")
	}
	return id, version, nil
}

// memMiB — MemTotal из /proc/meminfo.
func (m *Manager) memMiB() (int64, error) {
	data, err := m.p.FS().ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) != 2 || f[1] != "kB" {
			return 0, errors.New("неожиданный формат MemTotal")
		}
		kb, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil || kb < 0 {
			return 0, errors.New("неожиданный формат MemTotal")
		}
		return kb / 1024, nil
	}
	return 0, errors.New("нет MemTotal")
}

// foreign — чужая установка: файл юнита без метки xm, либо конфигурация Xray при отсутствии
// юнита xm (своя установка всегда начинается с юнита с меткой).
func (m *Manager) foreign() (bool, string) {
	exists, err := m.ours()
	switch {
	case errors.Is(err, ErrForeign):
		return true, "найден " + UnitPath + " без метки xm: чужая установка Xray, ничего не перезаписывается"
	case err != nil:
		return true, fmt.Sprintf("не удалось прочитать юнит: %v", err)
	case exists:
		return false, ""
	}
	if _, err := m.p.FS().ReadFile(m.config); !errors.Is(err, fs.ErrNotExist) {
		return true, "найдена конфигурация Xray " + m.config + " без юнита xm: чужая установка, ничего не перезаписывается"
	}
	return false, ""
}
