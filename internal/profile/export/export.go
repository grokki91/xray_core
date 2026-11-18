// Пакет export — единственное место форматов клиентских артефактов. Экспортёр получает
// профиль и один адрес сервера с параметрами пресета и возвращает готовый артефакт; состояние
// не читает и не меняет. Артефакт — секрет S1 (docs/security/secrets.md §1): в ошибках нет ни
// идентификатора клиента, ни ключа, ни других значений ввода — только имя поля.
package export

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/grokki91/xray_core/internal/store"
)

var (
	// ErrInput — поле профиля или адреса не по закрытому правилу.
	ErrInput = errors.New("недопустимый ввод экспорта")
	// ErrPreset — формат не умеет этот пресет.
	ErrPreset = errors.New("пресет не поддерживается форматом")
)

// Exporter — один формат клиентского артефакта.
type Exporter interface {
	Format() string
	Export(p store.Profile, e Endpoint) (Artifact, error)
}

// Endpoint — один адрес сервера и параметры пресета для клиента. Пакет config/preset сюда не
// импортируется (repository.md §3): значения передаёт app из состояния.
type Endpoint struct {
	Host      string // IPv4, IPv6 без скобок и без зоны, или домен
	Port      int
	Preset    string // ID пресета, например "reality-xhttp"
	SNI       string // одно из server_names
	PublicKey string // открытый ключ REALITY, base64url без дополнения
	ShortID   string // один из short_ids
	Path      string // путь XHTTP
}

// Artifact — готовый результат: строка, которую показывают владельцу как есть.
type Artifact struct {
	Format string
	Text   string
}

var reLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// hostPort — адрес в виде для authority ссылки: IPv6 в квадратных скобках.
func hostPort(host string, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", errors.New("порт: нужен 1–65535")
	}
	p := strconv.Itoa(port)
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return "", errors.New("адрес: IPv6 с зоной не годится для клиента")
		}
		if a.Is4() {
			return a.String() + ":" + p, nil
		}
		return "[" + a.String() + "]:" + p, nil
	}
	if !validDomain(host) {
		return "", errors.New("адрес: нужен IPv4, IPv6 без скобок или домен")
	}
	return host + ":" + p, nil
}

// validDomain — простое правило: метки по LDH через точку, хотя бы две, последняя не из одних
// цифр (иначе клиент прочтёт строку как IPv4).
func validDomain(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !reLabel.MatchString(l) {
			return false
		}
	}
	return strings.IndexFunc(labels[len(labels)-1], func(r rune) bool { return r < '0' || r > '9' }) >= 0
}

// escape — %-кодирование всего, кроме unreserved RFC 3986; пробел — %20, «+» — %2B: клиенты
// оставляют «+» как есть (docs/compatibility.md §3).
func escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}
