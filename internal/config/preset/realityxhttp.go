package preset

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ID пресета по умолчанию (ADR-0008): VLESS + REALITY + XHTTP.
const RealityXHTTP = "reality-xhttp"

const defaultPath = "/"

type realityXHTTP struct{}

func (realityXHTTP) ID() string { return RealityXHTTP }

// Requires: версия — нижняя граница проверенного диапазона (docs/compatibility.md §2).
func (realityXHTTP) Requires() Requirements {
	return Requirements{MinXray: "26.10.21", Port: 443, NeedsTarget: true}
}

// Inbound строит входящий. Поля — по docs/compatibility.md §2: decryption "none", flow пустой,
// XHTTP mode auto, REALITY с target, serverNames, privateKey и shortIds. Опция пресета одна:
// path (по умолчанию "/").
func (realityXHTTP) Inbound(p Params) (json.RawMessage, error) {
	path := defaultPath
	for k, v := range p.Options {
		if k != "path" {
			return nil, fmt.Errorf("reality-xhttp: неизвестная опция %q", k)
		}
		path = v
	}
	if !rePath.MatchString(path) {
		return nil, errors.New("reality-xhttp: path: нужен вид /сегмент без запроса и пробелов")
	}
	if err := checkPort(p.Port); err != nil {
		return nil, fmt.Errorf("reality-xhttp: %w", err)
	}
	if err := checkTarget(p.Target); err != nil {
		return nil, fmt.Errorf("reality-xhttp: %w", err)
	}
	if len(p.ServerNames) == 0 {
		return nil, errors.New("reality-xhttp: server_names: пусто")
	}
	for _, n := range p.ServerNames {
		if !reHost.MatchString(n) {
			return nil, errors.New("reality-xhttp: server_names: недопустимое имя")
		}
	}
	if err := checkPrivateKey(p.PrivateKey); err != nil {
		return nil, fmt.Errorf("reality-xhttp: %w", err)
	}
	if len(p.ShortIDs) == 0 {
		return nil, errors.New("reality-xhttp: short_ids: пусто")
	}
	for _, s := range p.ShortIDs {
		if !reShortID.MatchString(s) {
			return nil, errors.New("reality-xhttp: short_ids: нужен hex чётной длины до 16 символов")
		}
	}
	clients := make([]client, 0, len(p.ClientIDs))
	for _, id := range p.ClientIDs {
		if !reUUID.MatchString(id) {
			return nil, errors.New("reality-xhttp: id клиента не UUID")
		}
		clients = append(clients, client{ID: id, Flow: ""})
	}
	return json.Marshal(inbound{
		Tag:      "in-" + RealityXHTTP,
		Port:     p.Port,
		Protocol: "vless",
		Settings: settings{Clients: clients, Decryption: "none"},
		Stream: stream{
			Network:  "xhttp",
			Security: "reality",
			Reality: reality{
				Target: p.Target, ServerNames: p.ServerNames, PrivateKey: p.PrivateKey, ShortIDs: p.ShortIDs,
			},
			XHTTP: xhttp{Path: path, Mode: "auto"},
		},
	})
}

// Порядок полей структур — порядок в файле: отрисовка побайтно детерминирована.
type inbound struct {
	Tag      string   `json:"tag"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Settings settings `json:"settings"`
	Stream   stream   `json:"streamSettings"`
}

type settings struct {
	Clients    []client `json:"clients"`
	Decryption string   `json:"decryption"`
}

type client struct {
	ID   string `json:"id"`
	Flow string `json:"flow"`
}

type stream struct {
	Network  string  `json:"network"`
	Security string  `json:"security"`
	Reality  reality `json:"realitySettings"`
	XHTTP    xhttp   `json:"xhttpSettings"`
}

type reality struct {
	Target      string   `json:"target"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

type xhttp struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}
