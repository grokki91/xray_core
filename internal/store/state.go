package store

import "time"

// State — содержимое /etc/xm/state.json, источник правды об установке
// (docs/architecture/data-model.md §2). Новое поле или смена смысла — новая версия схемы и
// миграция в migrations.
type State struct {
	SchemaVersion int       `json:"schema_version"`
	Server        Server    `json:"server"`
	Inbounds      []Inbound `json:"inbounds"`
	Profiles      []Profile `json:"profiles"`
	Selftest      Selftest  `json:"selftest"`
	DNS           DNS       `json:"dns"`
	Firewall      Firewall  `json:"firewall"`
	Core          Core      `json:"core"`
	Applied       Applied   `json:"applied"`
}

type Server struct {
	Addresses Addresses `json:"addresses"`
	Port      int       `json:"port"`
}

type Addresses struct {
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
	Domain string `json:"domain"`
}

// Inbound — входящий по пресету; в MVP ровно один.
type Inbound struct {
	Preset  string            `json:"preset"`
	Reality Reality           `json:"reality"`
	Params  map[string]string `json:"params"`
}

type Reality struct {
	Target      string   `json:"target"`
	ServerNames []string `json:"server_names"`
	PrivateKey  string   `json:"private_key"`
	PublicKey   string   `json:"public_key"`
	ShortIDs    []string `json:"short_ids"`
}

// Profile — пользователь сервера, присутствует во всех входящих.
type Profile struct {
	Name    string    `json:"name"`
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	Enabled bool      `json:"enabled"`
}

// Selftest — служебный клиент самопроверки (ADR-0032): не профиль, в списки и экспорт не
// попадает. Пустой id — клиента ещё нет; его создаёт транзакция app.
type Selftest struct {
	ID string `json:"id"`
}

// Firewall — что xm изменил в фаерволе (ADR-0041). UFWRule — правило «allow порт/tcp» поставил
// xm: только такое правило он снимает при откате и удалении; чужое правило с тем же портом — нет.
type Firewall struct {
	UFWRule bool `json:"ufw_rule"`
}

type DNS struct {
	DoH      []string `json:"doh"`
	Strategy string   `json:"strategy"`
}

type Core struct {
	Version  string `json:"version"`
	Previous string `json:"previous"`
	Hold     bool   `json:"hold"`
}

// Applied — что последним применено к Xray: сравнение суммы с файлом выявляет дрейф.
type Applied struct {
	ConfigSHA256 string    `json:"config_sha256"`
	At           time.Time `json:"at"`
}
