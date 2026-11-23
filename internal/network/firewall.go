package network

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

// FirewallState — состояние входящего порта в локальном фаерволе (A3). Фаервол хостера с
// сервера не виден: Allowed не значит «доступен извне».
type FirewallState string

const (
	FirewallAllowed FirewallState = "allowed" // разрешён локально
	FirewallDenied  FirewallState = "denied"  // запрещён локально
	FirewallUnknown FirewallState = "unknown" // не определено
)

// Firewall — состояние и откуда оно взято: ufw, nftables или пусто (не прочитано).
type Firewall struct {
	State  FirewallState
	Source string
	Note   string
}

const fwTimeout = 10 * time.Second

// firewall: UFW активен — его вердикт по правилам и политике входящих; иначе — политики цепочек
// netfilter на хуке input (nft видит и iptables-nft). Правила netfilter не разбираются: при
// политике drop вердикт зависит от них — «не определено». Ничего не меняет (ADR-0036).
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
	join := func(n string) string { return strings.TrimPrefix(ufwNote+"; "+n, "; ") }
	res, err = m.read(ctx, platform.NFT, "-j", "list", "chains")
	if err != nil || res.ExitCode != 0 {
		return Firewall{State: FirewallUnknown, Note: join("nft не прочитал цепочки")}
	}
	st, note := nftVerdict(res.Stdout)
	if note == "" && ufwNote == "" {
		return Firewall{State: st, Source: "nftables"}
	}
	return Firewall{State: st, Source: "nftables", Note: join(note)}
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

// nftVerdict — политики цепочек с хуком input: нет таких или все accept — разрешён.
func nftVerdict(out []byte) (FirewallState, string) {
	var doc struct {
		Nftables []struct {
			Chain *struct {
				Hook   string `json:"hook"`
				Policy string `json:"policy"`
			} `json:"chain"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return FirewallUnknown, "вывод nft не разобран"
	}
	for _, o := range doc.Nftables {
		if o.Chain == nil || o.Chain.Hook != "input" {
			continue
		}
		switch o.Chain.Policy {
		case "accept":
		case "drop":
			return FirewallUnknown, "политика input — drop; правила netfilter не разбираются"
		default:
			return FirewallUnknown, fmt.Sprintf("политика input %q не разобрана", o.Chain.Policy)
		}
	}
	return FirewallAllowed, ""
}
