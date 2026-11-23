package network

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// FirewallState — состояние входящего порта в локальном фаерволе (A3). Фаервол хостера с
// сервера не виден: Allowed не значит «доступен извне».
type FirewallState string

const (
	FirewallAllowed FirewallState = "allowed" // разрешён локально
	FirewallDenied  FirewallState = "denied"  // запрещён локально
	FirewallUnknown FirewallState = "unknown" // не определено
)

// Firewall — состояние и откуда оно взято: ufw, iptables или пусто (не прочитано).
type Firewall struct {
	State  FirewallState
	Source string
	Note   string
}

const fwTimeout = 10 * time.Second

// firewall: UFW активен — его вердикт по правилам и политике входящих; иначе — цепочка INPUT
// iptables и ip6tables: политика ACCEPT и ни одного правила DROP/REJECT в обоих семействах —
// «разрешён»; иначе запрет не доказан — «не определено». Ничего не меняет (ADR-0036).
// Срок или отмена при чтении — «не определено», а не ошибка фактов: остальное уже собрано.
func (m *Manager) firewall(ctx context.Context, port int) Firewall {
	res, err := m.read(ctx, platform.UFW, "status", "verbose")
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return Firewall{State: FirewallUnknown, Source: "ufw", Note: "ufw не ответил в срок"}
	}
	ufwNote := ""
	switch {
	case err != nil:
		ufwNote = "ufw не прочитан: " + err.Error()
	case res.ExitCode != 0:
		ufwNote = fmt.Sprintf("ufw не прочитан: код %d", res.ExitCode)
	default:
		if active, st, note := ufwVerdict(string(res.Stdout), port); active {
			return Firewall{State: st, Source: "ufw", Note: note}
		}
	}
	var notes []string
	if ufwNote != "" {
		notes = append(notes, ufwNote)
	}
	allowed := true
	for _, prog := range []string{platform.IPTables, platform.IP6Tables} {
		res, err := m.read(ctx, prog, "-S", "INPUT")
		var ok bool
		var note string
		switch {
		case err != nil:
			note = prog + " не прочитан: " + err.Error()
		case res.ExitCode != 0:
			note = fmt.Sprintf("%s не прочитан: код %d", prog, res.ExitCode)
		default:
			ok, note = inputVerdict(string(res.Stdout))
			if note != "" {
				note = prog + ": " + note
			}
		}
		if !ok {
			allowed = false
			notes = append(notes, note)
		}
	}
	if allowed {
		return Firewall{State: FirewallAllowed, Source: "iptables", Note: strings.Join(notes, "; ")}
	}
	return Firewall{State: FirewallUnknown, Source: "iptables", Note: strings.Join(notes, "; ")}
}

// read запускает утилиту чтения со своим сроком.
func (m *Manager) read(ctx context.Context, program string, args ...string) (platform.Result, error) {
	c, cancel := context.WithTimeout(ctx, fwTimeout)
	defer cancel()
	return m.p.Exec(c, platform.Command{Program: program, Args: args})
}

// ufwVerdict разбирает ufw status verbose. Первое подходящее правило для порта/tcp или порта
// без протокола с источником Anywhere решает; правила с ограничением источника или
// интерфейса — «не определено»; правила нет — политика входящих по умолчанию.
func ufwVerdict(out string, port int) (active bool, st FirewallState, note string) {
	p := strconv.Itoa(port)
	var def string
	for line := range strings.Lines(out) {
		line = strings.TrimSpace(line)
		switch {
		case line == "Status: active":
			active = true
			continue
		case strings.HasPrefix(line, "Status:"):
			return false, "", ""
		case strings.HasPrefix(line, "Default:"):
			v, _, _ := strings.Cut(strings.TrimPrefix(line, "Default:"), "(incoming)")
			def = strings.TrimSpace(v)
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || (f[0] != p+"/tcp" && f[0] != p) {
			continue
		}
		rest := f[1:]
		if len(rest) > 0 && rest[0] == "(v6)" {
			rest = rest[1:]
		}
		if len(rest) < 2 {
			continue
		}
		action := rest[0]
		from := strings.Join(rest[2:], " ")
		if rest[1] != "IN" {
			from = strings.Join(rest[1:], " ")
		}
		if from != "Anywhere" && from != "Anywhere (v6)" {
			return active, FirewallUnknown, "правило UFW для порта ограничено источником или интерфейсом"
		}
		switch action {
		case "ALLOW", "LIMIT":
			return active, FirewallAllowed, ""
		case "DENY", "REJECT":
			return active, FirewallDenied, "правило UFW запрещает порт"
		}
		return active, FirewallUnknown, "правило UFW не разобрано"
	}
	switch def {
	case "allow":
		return active, FirewallAllowed, ""
	case "deny", "reject":
		return active, FirewallDenied, "UFW запрещает входящие по умолчанию, правила для порта нет"
	}
	return active, FirewallUnknown, "политика UFW не разобрана"
}

// inputVerdict — вывод iptables -S INPUT: первая строка «-P INPUT ACCEPT|DROP», дальше только
// «-A INPUT …». Разрешён — политика ACCEPT и нет цели DROP/REJECT; незнакомый формат — не разрешён.
func inputVerdict(out string) (bool, string) {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	switch lines[0] {
	case "-P INPUT ACCEPT":
	case "-P INPUT DROP":
		return false, "политика INPUT — DROP; правила не разбираются"
	default:
		return false, "вывод не разобран"
	}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] != "-A" || f[1] != "INPUT" {
			return false, "вывод не разобран"
		}
		for k := 2; k+1 < len(f); k++ {
			if f[k] == "-j" && (f[k+1] == "DROP" || f[k+1] == "REJECT") {
				return false, "в INPUT есть правило " + f[k+1]
			}
		}
	}
	return true, ""
}
