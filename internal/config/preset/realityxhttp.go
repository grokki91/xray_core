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
	path, err := pathOption(p.Options)
	if err != nil {
		return nil, err
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

// pathOption — единственная опция пресета: path.
func pathOption(opts map[string]string) (string, error) {
	path := defaultPath
	for k, v := range opts {
		if k != "path" {
			return "", fmt.Errorf("reality-xhttp: неизвестная опция %q", k)
		}
		path = v
	}
	if !rePath.MatchString(path) {
		return "", errors.New("reality-xhttp: path: нужен вид /сегмент без запроса и пробелов")
	}
	return path, nil
}

// Outbound строит исходящий клиента: те же значения, что в ссылке (fp chrome, flow пустой,
// encryption none, mode auto) — L3 сверяет их с экспортированной ссылкой.
func (realityXHTTP) Outbound(p ClientParams) (json.RawMessage, error) {
	path, err := pathOption(p.Options)
	if err != nil {
		return nil, err
	}
	if p.Host == "" || !reHostOrIP.MatchString(p.Host) {
		return nil, errors.New("reality-xhttp: host: нужен адрес или домен")
	}
	if err := checkPort(p.Port); err != nil {
		return nil, fmt.Errorf("reality-xhttp: %w", err)
	}
	if !reUUID.MatchString(p.ID) {
		return nil, errors.New("reality-xhttp: id клиента не UUID")
	}
	if !reHost.MatchString(p.SNI) {
		return nil, errors.New("reality-xhttp: sni: недопустимое имя")
	}
	if err := checkPrivateKey(p.PublicKey); err != nil { // тот же вид: 32 байта base64 RawURL
		return nil, errors.New("reality-xhttp: public_key: нужны 32 байта в base64 RawURL")
	}
	if !reShortID.MatchString(p.ShortID) || p.ShortID == "" {
		return nil, errors.New("reality-xhttp: short_id: нужен hex чётной длины 2–16 символов")
	}
	return json.Marshal(outbound{
		Tag:      "proxy",
		Protocol: "vless",
		Settings: outSettings{Vnext: []vnext{{
			Address: p.Host, Port: p.Port, Users: []user{{ID: p.ID, Encryption: "none", Flow: ""}},
		}}},
		Stream: outStream{
			Network:  "xhttp",
			Security: "reality",
			Reality:  outReality{ServerName: p.SNI, Fingerprint: "chrome", PublicKey: p.PublicKey, ShortID: p.ShortID},
			XHTTP:    xhttp{Path: path, Mode: "auto"},
		},
	})
}

type outbound struct {
	Tag      string      `json:"tag"`
	Protocol string      `json:"protocol"`
	Settings outSettings `json:"settings"`
	Stream   outStream   `json:"streamSettings"`
}

type outSettings struct {
	Vnext []vnext `json:"vnext"`
}

type vnext struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Users   []user `json:"users"`
}

type user struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow"`
}

type outStream struct {
	Network  string     `json:"network"`
	Security string     `json:"security"`
	Reality  outReality `json:"realitySettings"`
	XHTTP    xhttp      `json:"xhttpSettings"`
}

type outReality struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
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
