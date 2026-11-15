// Пакет redact — редактор чувствительных данных на границе «система → человек или файл»
// (docs/security/secrets.md §3): реестр точных значений из состояния плюс шаблоны для
// значений, которых в состоянии нет. Замена — стабильная метка «<вид:N>»: одинаковое значение
// даёт одинаковую метку в пределах одного редактора (отчёта).
package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Kind — вид значения; входит в метку.
type Kind string

// Виды точных значений (Register) и шаблонов.
const (
	UUID     Kind = "uuid"
	Key      Kind = "key"
	ShortID  Kind = "short-id"
	ServerIP Kind = "server-ip"
	Domain   Kind = "domain"
	Path     Kind = "path"
	IP       Kind = "ip"  // шаблон: публичный IPv4 или IPv6
	URI      Kind = "uri" // шаблон: ссылка клиента вида vless://
)

// Шаблоны. Ключ — ровно 43 символа base64url (X25519 REALITY); проверяется длиной слова, а не
// регулярным выражением: в RE2 нет просмотра границ.
var (
	uriRe  = regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s"'<>]+`)
	uuidRe = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	ipv6Re = regexp.MustCompile(`(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:\.\d{1,3}){0,3}`)
	ipv4Re = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	wordRe = regexp.MustCompile(`[A-Za-z0-9_-]+`)
)

// Redactor заменяет чувствительные значения метками. Безопасен для параллельного вызова.
type Redactor struct {
	mu     sync.Mutex
	labels map[string]string // значение → метка
	count  map[Kind]int
	exact  *regexp.Regexp // зарегистрированные значения; nil — пересобрать
	values []string
}

// New возвращает пустой редактор. Один редактор — один отчёт или одна сессия вывода.
func New() *Redactor {
	return &Redactor{labels: map[string]string{}, count: map[Kind]int{}}
}

// Register добавляет точное значение. Пустое значение игнорируется; короткое — нет: лишняя
// замена безопаснее пропущенного секрета.
func (r *Redactor) Register(kind Kind, value string) {
	if value == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.labels[value]; ok {
		return
	}
	r.label(kind, value)
	r.values = append(r.values, value)
	r.exact = nil
}

// label возвращает метку значения, назначая новую при первой встрече. Вызывается под mu.
func (r *Redactor) label(kind Kind, value string) string {
	if l, ok := r.labels[value]; ok {
		return l
	}
	r.count[kind]++
	l := fmt.Sprintf("<%s:%d>", kind, r.count[kind])
	r.labels[value] = l
	return l
}

// Text возвращает s без зарегистрированных значений и без значений, подходящих под шаблоны.
func (r *Redactor) Text(s string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.values) > 0 {
		if r.exact == nil {
			r.exact = r.compile()
		}
		s = r.exact.ReplaceAllStringFunc(s, func(v string) string { return r.labels[v] })
	}
	s = uriRe.ReplaceAllStringFunc(s, func(v string) string { return r.label(URI, v) })
	s = uuidRe.ReplaceAllStringFunc(s, func(v string) string { return r.label(UUID, strings.ToLower(v)) })
	s = ipv6Re.ReplaceAllStringFunc(s, r.ip)
	s = ipv4Re.ReplaceAllStringFunc(s, r.ip)
	return wordRe.ReplaceAllStringFunc(s, func(v string) string {
		if len(v) == 43 {
			return r.label(Key, v)
		}
		return v
	})
}

// compile собирает одно выражение из всех значений: длинные — первыми, чтобы значение,
// содержащее другое, заменялось целиком. Один проход не заменяет текст внутри меток.
func (r *Redactor) compile() *regexp.Regexp {
	vs := append([]string(nil), r.values...)
	sort.Slice(vs, func(i, j int) bool { return len(vs[i]) > len(vs[j]) })
	for i, v := range vs {
		vs[i] = regexp.QuoteMeta(v)
	}
	return regexp.MustCompile(strings.Join(vs, "|"))
}

// ip заменяет публичный адрес; частные, петлевые и служебные адреса — не данные установки.
func (r *Redactor) ip(v string) string {
	a, err := netip.ParseAddr(strings.TrimRight(v, ":"))
	if err != nil || !a.IsGlobalUnicast() || a.IsPrivate() {
		return v
	}
	return strings.Replace(v, strings.TrimRight(v, ":"), r.label(IP, a.Unmap().String()), 1)
}

// JSON возвращает копию v, в которой каждая строка — и значения, и ключи — прошла Text.
// Результат — дерево из map[string]any, []any, строк, json.Number, bool и nil.
func (r *Redactor) JSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	return r.walk(tree), nil
}

func (r *Redactor) walk(v any) any {
	switch x := v.(type) {
	case string:
		return r.Text(x)
	case []any:
		for i := range x {
			x[i] = r.walk(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[r.Text(k)] = r.walk(e)
		}
		return out
	}
	return v
}
