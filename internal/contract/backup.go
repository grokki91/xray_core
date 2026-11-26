package contract

// Backups — данные схемы backups: снимки от старого к новому (`xm backup --list`) или один
// созданный (`xm backup`). Created — секунды Unix; Kind — auto или manual; XM и Xray — версии из
// манифеста; Valid — снимок прошёл проверку манифеста и сумм; у непрошедшего версии пусты, а
// restore его не примет. Секретов нет: только идентификаторы и версии.
type Backups struct {
	Backups []BackupItem `json:"backups"`
}

// BackupItem — один снимок.
type BackupItem struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Kind    string `json:"kind"`
	XM      string `json:"xm"`
	Xray    string `json:"xray"`
	Valid   bool   `json:"valid"`
}

// Schema возвращает схему backups.
func (Backups) Schema() Schema { return Schema{Name: "backups", Major: 1, Minor: 0} }
