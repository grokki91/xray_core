// Пакет compat — таблица совместимости клиентов с пресетами данными (ADR-0008). Строки
// повторяют docs/compatibility.md §3 с датой и источником; тест сверки ловит расхождение.
// Экспорт под пару, которой нет в таблице как рабочей, — ошибка с причиной, а не
// «приблизительная» ссылка.
package compat

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/grokki91/xray_core/internal/platform"
)

var (
	// ErrIncompatible — клиент не подключится к пресету; причина — из таблицы.
	ErrIncompatible = errors.New("клиент несовместим с пресетом")
	// ErrUnknown — клиента или пресета нет в таблице.
	ErrUnknown = errors.New("нет в таблице совместимости")
)

// PresetRealityXHTTP — пресет MVP; ID строкой, config/preset не импортируется.
const PresetRealityXHTTP = "reality-xhttp"

// minServer — версия Xray сервера, с которой верна таблица: с неё сервер отвергает ClientHello
// без X25519MLKEM768 (docs/compatibility.md §3).
const minServer = "26.9.9"

// ClientSupport — строка таблицы: клиент × пресет.
type ClientSupport struct {
	Client    string // закрытый ID: v2rayn, v2rayng, hiddify-5, hiddify-4, sing-box
	Name      string // имя клиента, как в docs/compatibility.md §3
	Core      string // ядро клиента
	Preset    string // ID пресета
	Works     bool   // подключается ли
	Condition string // условие, при котором подключается; пусто — без условий
	Reason    string // почему не подключается; только при Works == false
	Checked   string // дата проверки, ГГГГ-ММ-ДД
	Source    string // статус и источник
}

// table — данные; каждый вызов строит новый срез, поэтому изменить таблицу снаружи нельзя.
func table() []ClientSupport {
	return []ClientSupport{
		{
			Client: "v2rayn", Name: "v2rayN (Windows, Linux, macOS)", Core: "Xray-core",
			Preset: PresetRealityXHTTP, Works: true,
			Condition: "ядро Xray клиента не старше v25.7.26, отпечаток chrome",
			Checked:   "2026-11-23",
			Source:    "на устройстве: 7.25.6 (Windows), по ссылке, сервер Xray v26.11.9, 2026-11-23; версия ядра клиента не записана; предшественник, 2026-10-28",
		},
		{
			Client: "v2rayng", Name: "v2rayNG (Android)", Core: "Xray-core",
			Preset: PresetRealityXHTTP, Works: true,
			Condition: "ядро Xray клиента не старше v25.7.26, отпечаток chrome",
			Checked:   "2026-10-28",
			Source:    "предшественник, 2026-10-28",
		},
		{
			Client: "hiddify-5", Name: "Hiddify 5.x", Core: "форк sing-box",
			Preset: PresetRealityXHTTP, Works: true,
			Checked: "2026-11-23",
			Source:  "на устройстве: 5.2.1 (Android), по QR, сервер Xray v26.11.9, 2026-11-23; предшественник, 2026-11-06; последний стабильный — v5.5.5, 5.9.x — предварительные (2026-11-17)",
		},
		{
			Client: "hiddify-4", Name: "Hiddify 4.x", Core: "форк sing-box 1.13",
			Preset: PresetRealityXHTTP, Works: false,
			Reason:  "вырезает X25519MLKEM768 из ClientHello",
			Checked: "2026-10-28",
			Source:  "предшественник, 2026-10-28",
		},
		{
			Client: "sing-box", Name: "sing-box (upstream) 1.14.4 и 1.15.0-alpha.13", Core: "sing-box",
			Preset: PresetRealityXHTTP, Works: false,
			Reason:  "REALITY-клиент вырезает X25519MLKEM768; транспорта XHTTP нет",
			Checked: "2026-11-13",
			Source:  "по исходникам, 2026-11-13: common/tls/reality_client.go, каталог transport/",
		},
	}
}

// Clients — строки пресета presetID для сервера Xray версии core (N.N.N). Пресета нет, версия
// не N.N.N или ниже той, с которой верна таблица, — nil: таблица о таком сервере не говорит.
func Clients(presetID, core string) []ClientSupport {
	if !atLeast(core, minServer) {
		return nil
	}
	var out []ClientSupport
	for _, r := range table() {
		if r.Preset == presetID {
			out = append(out, r)
		}
	}
	return out
}

// Check — nil, если клиент подключается к пресету; иначе ErrIncompatible с причиной или ErrUnknown. Ввод в ошибку не попадает.
func Check(client, presetID string) error {
	knownClient, knownPreset := false, false
	for _, r := range table() {
		knownClient = knownClient || r.Client == client
		knownPreset = knownPreset || r.Preset == presetID
		if r.Client != client || r.Preset != presetID {
			continue
		}
		if r.Works {
			return nil
		}
		return fmt.Errorf("%w: %s не подключится к %s: %s", ErrIncompatible, r.Name, r.Preset, r.Reason)
	}
	switch {
	case !knownClient:
		return fmt.Errorf("%w: клиент", ErrUnknown)
	case !knownPreset:
		return fmt.Errorf("%w: пресет", ErrUnknown)
	}
	return fmt.Errorf("%w: пара клиент × пресет", ErrUnknown)
}

// atLeast — v и min вида N.N.N и v >= min.
func atLeast(v, min string) bool {
	if !platform.ValidVersion(v) || !platform.ValidVersion(min) {
		return false
	}
	a, b := strings.Split(v, "."), strings.Split(min, ".")
	for i := range a {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x > y
		}
	}
	return true
}
