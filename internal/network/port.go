package network

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// Holder — кто держит порт. Пустое имя — не определено (нет прав или ss не ответил).
type Holder struct {
	Name string
	PID  int
}

// ssUser — процесс в выводе ss -p: users:(("имя",pid=N,fd=M)). Имя — только печатные символы
// без пробелов и кавычек: оно уходит человеку, а имя процесса задаёт кто угодно.
var ssUser = regexp.MustCompile(`users:\(\("([!#-~]{1,64})",pid=([0-9]{1,10}),`)

// ssTimeout — срок ss: таблица сокетов читается мгновенно.
const ssTimeout = 5 * time.Second

// PortFree сообщает, свободен ли TCP-порт; занят — кем, если это определимо. Факт занятости —
// по таблицам ядра; имя процесса — из ss, его сбой не делает занятость неизвестной.
func (m *Manager) PortFree(ctx context.Context, port int) (bool, Holder, error) {
	if err := checkPort(port); err != nil {
		return false, Holder{}, err
	}
	on, err := m.p.Net().Listening(ctx, port)
	if err != nil {
		return false, Holder{}, fmt.Errorf("порт %d: %w", port, err)
	}
	if !on {
		return true, Holder{}, nil
	}
	c, cancel := context.WithTimeout(ctx, ssTimeout)
	defer cancel()
	res, err := m.p.Exec(c, platform.Command{Program: platform.SS,
		Args: []string{"-H", "-t", "-l", "-n", "-p", "sport", "=", ":" + strconv.Itoa(port)}})
	if err != nil || res.ExitCode != 0 {
		return false, Holder{}, nil
	}
	g := ssUser.FindSubmatch(res.Stdout)
	if g == nil {
		return false, Holder{}, nil
	}
	pid, _ := strconv.Atoi(string(g[2]))
	return false, Holder{Name: string(g[1]), PID: pid}, nil
}
