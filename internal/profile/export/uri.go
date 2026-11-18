package export

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/grokki91/xray_core/internal/store"
)

// presetRealityXHTTP — ID пресета строкой: config/preset сюда не импортируется.
const presetRealityXHTTP = "reality-xhttp"

var (
	reUUID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reShortID = regexp.MustCompile(`^([0-9a-f]{2}){1,8}$`)
	rePath    = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,128}$`)
)

// URI — ссылка vless:// (share link) для v2rayN и Hiddify; разбор у клиентов —
// docs/compatibility.md §3.
type URI struct{}

var _ Exporter = URI{}

func (URI) Format() string { return "uri" }

// Export строит ссылку. Имя профиля проверено правилом пакета profile до вызова; здесь оно
// только %-кодируется, поэтому никакое значение не ломает ссылку. Порядок параметров
// фиксирован для эталонов; fp всегда chrome; flow для XHTTP не пишется; encryption none и
// mode auto — значения пресета reality-xhttp.
func (URI) Export(p store.Profile, e Endpoint) (Artifact, error) {
	if e.Preset != presetRealityXHTTP {
		return Artifact{}, fmt.Errorf("%w: uri: известен только %s", ErrPreset, presetRealityXHTTP)
	}
	if p.Name == "" {
		return Artifact{}, fmt.Errorf("%w: uri: имя профиля пусто", ErrInput)
	}
	if !reUUID.MatchString(p.ID) {
		return Artifact{}, fmt.Errorf("%w: uri: идентификатор клиента не UUID", ErrInput)
	}
	hp, err := hostPort(e.Host, e.Port)
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: uri: %v", ErrInput, err)
	}
	if _, err := netip.ParseAddr(e.SNI); err == nil || !validDomain(e.SNI) {
		return Artifact{}, fmt.Errorf("%w: uri: sni: нужен домен", ErrInput)
	}
	if k, err := base64.RawURLEncoding.Strict().DecodeString(e.PublicKey); err != nil || len(k) != 32 {
		return Artifact{}, fmt.Errorf("%w: uri: pbk: нужен base64url 32 байт", ErrInput)
	}
	if !reShortID.MatchString(e.ShortID) {
		return Artifact{}, fmt.Errorf("%w: uri: sid: нужен hex чётной длины 2–16", ErrInput)
	}
	if !rePath.MatchString(e.Path) {
		return Artifact{}, fmt.Errorf("%w: uri: path: нужен вид /сегмент без запроса и пробелов", ErrInput)
	}
	params := [][2]string{
		{"encryption", "none"},
		{"security", "reality"},
		{"sni", e.SNI},
		{"fp", "chrome"},
		{"pbk", e.PublicKey},
		{"sid", e.ShortID},
		{"type", "xhttp"},
		{"path", e.Path},
		{"mode", "auto"},
	}
	var b strings.Builder
	b.WriteString("vless://" + p.ID + "@" + hp + "?")
	for i, kv := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(kv[0] + "=" + escape(kv[1]))
	}
	b.WriteString("#" + escape(p.Name))
	return Artifact{Format: "uri", Text: b.String()}, nil
}
