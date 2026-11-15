// Пакет contract — типы машинных выводов (CLI --json, HTTP API, мост) и общий конверт со схемой.
// Только данные и их кодирование, без логики. Правила версий — docs/architecture/interfaces.md §2:
// новое поле — minor+1; удаление, переименование, смена смысла — major+1 и ADR.
package contract

import (
	"encoding/json"
	"io"
	"time"
)

// Schema — имя и версия схемы документа.
type Schema struct {
	Name  string `json:"name"`
	Major int    `json:"major"`
	Minor int    `json:"minor"`
}

// XM — сведения о выдавшем документ xm.
type XM struct {
	Version string `json:"version"`
}

// Envelope — общий конверт любого машинного вывода. У документа ровно одно из Data и Error.
type Envelope struct {
	Schema Schema `json:"schema"`
	XM     XM     `json:"xm"`
	Time   int64  `json:"time"`
	Data   Data   `json:"data,omitempty"`
	Error  *Error `json:"error,omitempty"`
}

// Data — полезная нагрузка документа; каждая схема знает своё имя и версию.
type Data interface {
	Schema() Schema
}

// Error — ошибка в машинном виде. Code — стабильная строка вида «preflight.foreign_install».
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// ErrorSchema — схема документа с ошибкой.
func ErrorSchema() Schema { return Schema{Name: "error", Major: 1, Minor: 0} }

// Version — данные схемы version. Версия Xray добавится полем в фазе 2 (minor+1).
type Version struct {
	XM string `json:"xm"`
}

// Schema возвращает схему version.
func (Version) Schema() Schema { return Schema{Name: "version", Major: 1, Minor: 0} }

// New заворачивает данные в конверт.
func New(xmVersion string, at time.Time, d Data) Envelope {
	return Envelope{Schema: d.Schema(), XM: XM{Version: xmVersion}, Time: at.Unix(), Data: d}
}

// NewError заворачивает ошибку в конверт схемы error.
func NewError(xmVersion string, at time.Time, e Error) Envelope {
	return Envelope{Schema: ErrorSchema(), XM: XM{Version: xmVersion}, Time: at.Unix(), Error: &e}
}

// Encode пишет конверт одним документом JSON с переводом строки в конце.
func Encode(w io.Writer, e Envelope) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(e)
}
