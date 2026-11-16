// Пакет preset — каталог пресетов входящего Xray (docs/architecture/components.md, config;
// ADR-0008). Пресет — именованная готовая комбинация «протокол + транспорт + защита»; поля,
// от которых зависит работа, задаются явно, а не берутся из умолчаний upstream. В ошибках —
// только имена полей: значения Params содержат секреты.
package preset

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrUnknown — пресета с таким именем нет в каталоге.
var ErrUnknown = errors.New("неизвестный пресет")

// Params — всё, что нужно пресету для входящего. Заполняет config из состояния.
type Params struct {
	Port        int
	Target      string   // цель REALITY, host:port
	ServerNames []string // допустимые SNI
	PrivateKey  string   // закрытый ключ REALITY, base64 RawURL
	ShortIDs    []string // hex, до 16 символов
	ClientIDs   []string // UUID включённых профилей
	Options     map[string]string
}

// Requirements — что пресет требует от сервера.
type Requirements struct {
	MinXray     string // минимальная версия Xray (N.N.N)
	Port        int    // порт по умолчанию
	NeedsTarget bool   // нужна ли цель REALITY
}

// Preset — один пресет каталога.
type Preset interface {
	ID() string
	Inbound(p Params) (json.RawMessage, error)
	Requires() Requirements
}

var catalog = []Preset{realityXHTTP{}}

// Get возвращает пресет по имени.
func Get(id string) (Preset, error) {
	for _, p := range catalog {
		if p.ID() == id {
			return p, nil
		}
	}
	return nil, fmt.Errorf("%w %q", ErrUnknown, id)
}

// IDs — имена пресетов каталога.
func IDs() []string {
	ids := make([]string, 0, len(catalog))
	for _, p := range catalog {
		ids = append(ids, p.ID())
	}
	return ids
}

var (
	reUUID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reShortID = regexp.MustCompile(`^([0-9a-f]{2}){0,8}$`)
	rePath    = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,128}$`)
	reHost    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

// checkPort — порт TCP 1…65535.
func checkPort(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("port: вне 1…65535")
	}
	return nil
}

// checkTarget — host:port без схемы и путей.
func checkTarget(t string) error {
	i := strings.LastIndexByte(t, ':')
	if i <= 0 || !reHost.MatchString(t[:i]) {
		return errors.New("target: нужен вид host:port")
	}
	var port int
	if _, err := fmt.Sscanf(t[i+1:], "%d", &port); err != nil || fmt.Sprint(port) != t[i+1:] {
		return errors.New("target: порт не число")
	}
	if err := checkPort(port); err != nil {
		return errors.New("target: " + err.Error())
	}
	return nil
}

// checkPrivateKey — 32 байта в base64 RawURL.
func checkPrivateKey(k string) error {
	b, err := base64.RawURLEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return errors.New("private_key: нужны 32 байта в base64 RawURL")
	}
	return nil
}
