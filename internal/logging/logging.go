// Пакет logging — журнал самого xm и раздел log конфигурации Xray (docs/architecture/
// components.md, ADR-0022). Журнал xm — slog поверх редактора: каждая запись целиком проходит
// redact.Text до записи в journald через platform. Журнал доступа Xray выключен — в нём адреса
// клиентов. Чтение журнала — journalctl через platform.Stream (ADR-0044).
package logging

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
	"github.com/grokki91/xray_core/internal/redact"
)

// writeTimeout — срок одной записи в journald.
const writeTimeout = 2 * time.Second

// Параметры раздела log Xray: журнал доступа выключен, ошибки — на уровне warning в
// стандартный вывод юнита (journald).
const (
	xrayAccess = "none"
	xrayLevel  = "warning"
)

// Settings — настройки журналов.
type Settings struct {
	Level      slog.Level // уровень журнала xm
	XrayAccess string     // журнал доступа Xray; "none" — выключен
	XrayLevel  string     // loglevel Xray
}

// Manager — журнал xm и раздел log Xray.
type Manager struct {
	h     *handler
	level slog.Level
	p     platform.Platform
	r     *redact.Redactor
}

// New возвращает менеджер: записи журнала идут через r в journald платформы p.
func New(p platform.Platform, r *redact.Redactor, level slog.Level) *Manager {
	return &Manager{h: &handler{j: p.Journal(), r: r, level: level}, level: level, p: p, r: r}
}

// Logger возвращает журнал xm; всегда поверх редактора.
func (m *Manager) Logger() *slog.Logger { return slog.New(m.h) }

func (m *Manager) now() time.Time { return m.p.Clock().Now() }

// Settings возвращает действующие настройки.
func (m *Manager) Settings() Settings {
	return Settings{Level: m.level, XrayAccess: xrayAccess, XrayLevel: xrayLevel}
}

// XraySection возвращает раздел log конфигурации Xray — одни и те же байты при каждом вызове
// (конфигурация детерминирована).
func (m *Manager) XraySection() []byte {
	return []byte(`{"access":"` + xrayAccess + `","loglevel":"` + xrayLevel + `"}`)
}

// handler — slog.Handler: строка «сообщение ключ=значение …», целиком через редактор.
type handler struct {
	j      platform.Journal
	r      *redact.Redactor
	level  slog.Level
	prefix string // группы: «a.b.»
	attrs  string // готовые « ключ=значение» из WithAttrs
}

func (h *handler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *handler) Handle(ctx context.Context, rec slog.Record) error {
	var b strings.Builder
	b.WriteString(rec.Message)
	b.WriteString(h.attrs)
	rec.Attrs(func(a slog.Attr) bool {
		appendAttr(&b, h.prefix, a)
		return true
	})
	// Запись не зависит от отмены контекста вызывающего: срок — свой.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	return h.j.Write(ctx, priority(rec.Level), h.r.Text(b.String()))
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	var b strings.Builder
	for _, a := range as {
		appendAttr(&b, h.prefix, a)
	}
	c := *h
	c.attrs = h.attrs + b.String()
	return &c
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.prefix += name + "."
	return &c
}

// appendAttr дописывает « ключ=значение»; группа раскрывается в «группа.ключ».
func appendAttr(b *strings.Builder, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, g := range a.Value.Group() {
			appendAttr(b, p, g)
		}
		return
	}
	v := a.Value.String()
	if v == "" || strings.ContainsAny(v, " \t\r\n\"=") {
		v = strconv.Quote(v)
	}
	b.WriteString(" " + prefix + a.Key + "=" + v)
}

func priority(l slog.Level) platform.Priority {
	switch {
	case l >= slog.LevelError:
		return platform.PriErr
	case l >= slog.LevelWarn:
		return platform.PriWarning
	case l >= slog.LevelInfo:
		return platform.PriInfo
	}
	return platform.PriDebug
}
