package export

import (
	"strings"

	"github.com/grokki91/xray_core/internal/store"
	"rsc.io/qr"
)

const (
	// Уровень L: код меньше, а с экрана терминала он не повреждается; ссылка ~250 знаков.
	qrLevel = qr.L
	// Поле тишины — 4 модуля по стандарту ISO/IEC 18004.
	quietZone = 4
	// Чёрное на белом задано явно: на тёмной теме терминала инвертированный код читают не все
	// сканеры.
	qrOn  = "\x1b[30;47m"
	qrOff = "\x1b[0m"
)

// QR — QR-код для терминала. Кодирует ровно ту строку, которую строит экспортёр uri: другого
// источника у кода нет. Две строки модулей — одна строка терминала (знаки ▀ ▄ █).
type QR struct{}

var _ Exporter = QR{}

func (QR) Format() string { return "qr" }

// Export строит ссылку экспортёром uri и рисует её; отказ ссылки — отказ QR.
func (QR) Export(p store.Profile, e Endpoint) (Artifact, error) {
	link, err := (URI{}).Export(p, e)
	if err != nil {
		return Artifact{}, err
	}
	c, err := qr.Encode(link.Text, qrLevel)
	if err != nil {
		return Artifact{}, err
	}
	// Ошибка qr.Encode — слишком длинный текст; значения ввода в неё не входят.
	black := func(x, y int) bool {
		x, y = x-quietZone, y-quietZone
		return x >= 0 && y >= 0 && x < c.Size && y < c.Size && c.Black(x, y)
	}
	total := c.Size + 2*quietZone
	var b strings.Builder
	for y := 0; y < total; y += 2 {
		b.WriteString(qrOn)
		for x := 0; x < total; x++ {
			top, bottom := black(x, y), black(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteString(qrOff + "\n")
	}
	return Artifact{Format: "qr", Text: b.String()}, nil
}
