package contract

// DiagReport — данные схемы diag-report: отчёт `xm diag` (docs/operations/diagnostics.md §3).
// Документ уже прошёл редактор: в истории и в экспорте — тот же. ID — время прогона UTC вида
// 20260101T000000Z; Health — вердикт по прогону: ok, degraded, down, unknown.
type DiagReport struct {
	ID           string            `json:"id"`
	Vantage      DiagVantage       `json:"vantage"`
	Env          DiagEnv           `json:"env"`
	Health       string            `json:"health"`
	Observations []DiagObservation `json:"observations"`
	Findings     []DiagFinding     `json:"findings"`
	Summary      DiagSummary       `json:"summary"`
}

// DiagVantage — точка наблюдения: kind — local; id — server.
type DiagVantage struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// DiagEnv — версии и ОС, при которых снят отчёт; не определено — пусто.
type DiagEnv struct {
	XM   string `json:"xm"`
	Xray string `json:"xray"`
	OS   string `json:"os"`
}

// DiagObservation — наблюдение: status — ok, fail, skip, error; reason — у skip и error;
// limits — чего измерение не различает.
type DiagObservation struct {
	Check  string   `json:"check"`
	Target string   `json:"target,omitempty"`
	Status string   `json:"status"`
	Value  any      `json:"value,omitempty"`
	Reason string   `json:"reason,omitempty"`
	Limits []string `json:"limits,omitempty"`
}

// DiagFinding — вывод: class — fact, probable, hypothesis; impact — только у fact (down,
// degraded); alternatives — у probable; confirm и refute — у hypothesis.
type DiagFinding struct {
	Code         string   `json:"code"`
	Class        string   `json:"class"`
	Title        string   `json:"title"`
	Evidence     []string `json:"evidence"`
	Alternatives []string `json:"alternatives,omitempty"`
	Confirm      string   `json:"confirm,omitempty"`
	Refute       string   `json:"refute,omitempty"`
	Actions      []string `json:"actions,omitempty"`
	Impact       string   `json:"impact,omitempty"`
}

// DiagSummary — число наблюдений по исходам.
type DiagSummary struct {
	OK    int `json:"ok"`
	Fail  int `json:"fail"`
	Skip  int `json:"skip"`
	Error int `json:"error"`
}

// Schema возвращает схему diag-report.
func (DiagReport) Schema() Schema { return Schema{Name: "diag-report", Major: 1, Minor: 0} }
