package contract

// Status — данные схемы status: состояние установки. Не установлено — Installed=false, прочие
// поля пусты.
type Status struct {
	Installed bool          `json:"installed"`
	Service   ServiceState  `json:"service"`
	Versions  Versions      `json:"versions"`
	Addresses ServerAddress `json:"addresses"`
	Port      int           `json:"port"`
	// Drift — конфигурация Xray на диске расходится с отрисованной из состояния (ADR-0004).
	Drift bool `json:"drift"`
	// Profiles — число клиентских профилей (minor 1).
	Profiles int `json:"profiles"`
	// Clients — таблица совместимости клиентов с пресетом сервера (minor 1); пусто — таблица о
	// таком сервере не говорит.
	Clients []ClientSupport `json:"clients"`
	// Health — вердикт здоровья по набору control (minor 2, ADR-0024).
	Health Health `json:"health"`
	// Update — доступное обновление Xray по итогу последней проверки (minor 3).
	Update Available `json:"update"`
}

// Health — вердикт: ok, degraded, down или unknown. Cause и Action — первопричина и действие
// (только при не-ok); Unchecked — что вердикт ok не проверял. Не установлено — Verdict пуст.
type Health struct {
	Verdict   string `json:"verdict"`
	Cause     string `json:"cause"`
	Action    string `json:"action"`
	Unchecked string `json:"unchecked"`
}

// ClientSupport — строка таблицы совместимости: подключится ли клиент к серверу и при каком
// условии. Reason — только когда не подключится.
type ClientSupport struct {
	Name      string `json:"name"`
	Works     bool   `json:"works"`
	Condition string `json:"condition"`
	Reason    string `json:"reason"`
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
func (Status) Schema() Schema { return Schema{Name: "status", Major: 1, Minor: 3} }
