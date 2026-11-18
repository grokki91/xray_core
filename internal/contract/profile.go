package contract

// ProfileItem — профиль без секретов: строка списка.
type ProfileItem struct {
	Name    string `json:"name"`
	Created int64  `json:"created"` // секунды Unix, UTC
	Enabled bool   `json:"enabled"`
}

// Profiles — данные схемы profiles: список профилей (`xm list`). Секретов в нём нет.
type Profiles struct {
	Profiles []ProfileItem `json:"profiles"`
}

// Schema возвращает схему profiles.
func (Profiles) Schema() Schema { return Schema{Name: "profiles", Major: 1, Minor: 0} }

// ProfileLink — ссылка профиля на один адрес сервера. URI — секрет S1.
type ProfileLink struct {
	Address string `json:"address"`
	URI     string `json:"uri"`
}

// UnfitClient — клиент, которому ссылка не подойдёт, и причина из таблицы совместимости.
type UnfitClient struct {
	Client string `json:"client"`
	Reason string `json:"reason"`
}

// Profile — данные схемы profile: профиль со ссылками (`xm add`, `xm show`). Содержит секреты:
// печатают его только команды, чьё назначение — их показать. QR в документ не входит — он
// строится из ссылки для терминала.
type Profile struct {
	ProfileItem
	Links []ProfileLink `json:"links"`
	// QRAddress — адрес, для которого построен QR терминала.
	QRAddress string        `json:"qr_address"`
	Unfit     []UnfitClient `json:"unfit"`
}

// Schema возвращает схему profile.
func (Profile) Schema() Schema { return Schema{Name: "profile", Major: 1, Minor: 0} }
