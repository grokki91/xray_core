package contract

// Update — данные схемы update: итог `xm update`. Current — версия до команды; Target —
// выбранная версия; Latest — последний стабильный релиз (пусто при --to); Range — проверенный
// диапазон; InRange — Target в нём; Held — удержание, ничего не сделано; Updated — версия
// переключена; Checked — время проверки (RFC 3339); Unchecked — чего контроль не доказывает.
type Update struct {
	Current   string `json:"current"`
	Target    string `json:"target"`
	Latest    string `json:"latest"`
	Range     Range  `json:"range"`
	InRange   bool   `json:"in_range"`
	Held      bool   `json:"held"`
	Updated   bool   `json:"updated"`
	Checked   string `json:"checked"`
	Unchecked string `json:"unchecked"`
}

// Range — проверенный диапазон версий Xray, границы включительно.
type Range struct {
	Min string `json:"min"`
	Max string `json:"max"`
}

// Schema возвращает схему update.
func (Update) Schema() Schema { return Schema{Name: "update", Major: 1, Minor: 0} }

// Available — доступное обновление в status (minor 3) по итогу последней проверки, без сети:
// Version пусто — новее в диапазоне нет; Checked пусто — проверки не было.
type Available struct {
	Version string `json:"version"`
	Checked string `json:"checked"`
}
