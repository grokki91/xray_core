package contract

// Status — данные схемы status: состояние установки. Не установлено — Installed=false, прочие
// поля пусты. Число профилей, доступное обновление и вердикт здоровья добавятся полями
// (minor+1) в своих фазах.
type Status struct {
	Installed bool          `json:"installed"`
	Service   ServiceState  `json:"service"`
	Versions  Versions      `json:"versions"`
	Addresses ServerAddress `json:"addresses"`
	Port      int           `json:"port"`
	// Drift — конфигурация Xray на диске расходится с отрисованной из состояния (ADR-0004).
	Drift bool `json:"drift"`
}

// ServiceState — состояние службы xray.service глазами systemd.
type ServiceState struct {
	Loaded   bool   `json:"loaded"`
	Active   string `json:"active"`
	Sub      string `json:"sub"`
	Enabled  bool   `json:"enabled"`
	Restarts int    `json:"restarts"`
}

// Versions — версии xm и установленного Xray (пусто — ядро не установлено).
type Versions struct {
	XM   string `json:"xm"`
	Xray string `json:"xray"`
}

// ServerAddress — адреса сервера из состояния; пустое поле — не задано.
type ServerAddress struct {
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
	Domain string `json:"domain"`
}

// Schema возвращает схему status.
func (Status) Schema() Schema { return Schema{Name: "status", Major: 1, Minor: 0} }
