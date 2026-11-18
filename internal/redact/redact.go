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
	Token    Kind = "token" // токен API GitHub из окружения (ADR-0031)
	IP       Kind = "ip"    // шаблон: публичный IPv4 или IPv6
	URI      Kind = "uri"   // шаблон: ссылка клиента вида vless://
)

// Шаблоны. Ключ — 43 символа base64url или 43 символа base64 с «=» (X25519 REALITY);
// проверяется длиной слова: в RE2 нет просмотра границ. Адрес ищется в слове из букв, цифр,
// «:» и «.» (адрес) — разбором netip на каждом отрезке между двоеточиями, а не регулярным
// выражением: так «tcp:2001:db8::5» и «203.0.113.5:443» находятся целиком.
var (
	uriRe  = regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s"'<>]+`)
	uuidRe = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	addrRe = regexp.MustCompile(`[0-9A-Za-z:.]+`)
	ipv4Re = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	wordRe = regexp.MustCompile(`[A-Za-z0-9_+/-]+=?`)
)

// Redactor заменяет чувствительные значения метками. Безопасен для параллельного вызова.
type Redactor struct {
	mu     sync.Mutex
	labels map[string]string // значение в нижнем регистре → метка
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
	if _, ok := r.labels[strings.ToLower(value)]; ok {
		return
	}
	r.label(kind, value)
	r.values = append(r.values, value)
	r.exact = nil
}

// label возвращает метку значения, назначая новую при первой встрече. Вызывается под mu.
func (r *Redactor) label(kind Kind, value string) string {
	key := strings.ToLower(value)
	if l, ok := r.labels[key]; ok {
		return l
	}
	r.count[kind]++
	l := fmt.Sprintf("<%s:%d>", kind, r.count[kind])
	r.labels[key] = l
	return l
}

// Text возвращает s без зарегистрированных значений и без значений, подходящих под шаблоны.
// Ссылка заменяется первой и целиком: после замены её частей она бы уже не распозналась.
// Регистр не важен: домен и hex в другом регистре — то же значение.
func (r *Redactor) Text(s string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s = uriRe.ReplaceAllStringFunc(s, func(v string) string { return r.label(URI, v) })
	if len(r.values) > 0 {
		if r.exact == nil {
			r.exact = r.compile()
		}
		s = r.exact.ReplaceAllStringFunc(s, func(v string) string { return r.labels[strings.ToLower(v)] })
	}
	s = uuidRe.ReplaceAllStringFunc(s, func(v string) string { return r.label(UUID, v) })
	s = addrRe.ReplaceAllStringFunc(s, r.addrs)
	return wordRe.ReplaceAllStringFunc(s, func(v string) string {
		if len(v) == 43 && !strings.ContainsAny(v, "=") || len(v) == 44 && strings.HasSuffix(v, "=") {
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
	return regexp.MustCompile("(?i)" + strings.Join(vs, "|"))
}

// addrs заменяет публичные адреса в слове. Кандидат — отрезок слова от его начала или от
// двоеточия до его конца или до двоеточия; берётся самый ранний и самый длинный разбираемый.
// Частные, петлевые и служебные адреса — не данные установки и остаются.
func (r *Redactor) addrs(w string) string {
	var out strings.Builder
	for start := 0; start < len(w); {
		end, a := longestAddr(w, start)
		if end < 0 {
			next := strings.IndexByte(w[start:], ':')
			if next < 0 {
				out.WriteString(w[start:])
				break
			}
			out.WriteString(w[start : start+next+1])
			start += next + 1
			continue
		}
		if a.IsGlobalUnicast() && !a.IsPrivate() {
			out.WriteString(r.label(IP, a.Unmap().String()))
		} else {
			out.WriteString(w[start:end])
		}
		start = end
	}
	return out.String()
}

// longestAddr ищет адрес, начинающийся в w[start:]: возвращает его конец или -1.
func longestAddr(w string, start int) (int, netip.Addr) {
	ends := []int{len(w)}
	for i := len(w) - 1; i > start; i-- {
		if w[i] == ':' {
			ends = append(ends, i)
		}
	}
	for _, end := range ends {
		cand := strings.TrimRight(w[start:end], ".")
		if a, ok := parseAddr(cand); ok {
			return start + len(cand), a
		}
	}
	return -1, netip.Addr{}
}

// parseAddr разбирает IPv6 и IPv4, в том числе IPv4 с ведущими нулями в октетах.
func parseAddr(s string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a, true
	}
	if !ipv4Re.MatchString(s) {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, part := range strings.Split(s, ".") {
		n := 0
		for _, c := range part {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(n)
	}
	return netip.AddrFrom4(b), true
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
