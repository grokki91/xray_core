package profile

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/grokki91/xray_core/internal/profile/compat"
	"github.com/grokki91/xray_core/internal/profile/export"
	"github.com/grokki91/xray_core/internal/store"
)

var (
	// ErrIncompatible — выбранный клиент не подключится к пресету сервера; причина — из таблицы.
	ErrIncompatible = compat.ErrIncompatible
	// ErrUnknownClient — клиента или пресета нет в таблице совместимости.
	ErrUnknownClient = compat.ErrUnknown
)

// defaultPath — путь XHTTP, если пресет его не переопределил (docs/compatibility.md §2).
const defaultPath = "/"

// Link — ссылка профиля на один адрес сервера. Секрет S1 (docs/security/secrets.md §1).
type Link struct{ Address, URI string }

// Unfit — клиент, который к серверу не подключится, и причина из таблицы совместимости.
type Unfit struct{ Client, Reason string }

// Share — всё, что владелец получает по профилю: ссылка на каждый адрес сервера, QR одного из
// адресов и клиенты, которым эта ссылка не подойдёт.
type Share struct {
	Links     []Link
	QRAddress string
	QR        string // для терминала, с ANSI; не для файла и журнала
	Unfit     []Unfit
}

// ClientInfo — строка таблицы совместимости для показа в `xm status`.
type ClientInfo struct {
	Name      string
	Works     bool
	Condition string
	Reason    string
	MinClient string
}

// Share строит ссылки профиля name по состоянию. client — необязательный ID клиента из таблицы:
// несовместимый клиент — ErrIncompatible без ссылок, неизвестный — ErrUnknownClient. address —
// адрес сервера для QR; пусто — первый из порядка «домен, IPv4, IPv6».
func (m *Manager) Share(st store.State, name, client, address string) (Share, error) {
	p, err := m.Get(st, name)
	if err != nil {
		return Share{}, err
	}
	if len(st.Inbounds) == 0 || len(st.Inbounds[0].Reality.ServerNames) == 0 || len(st.Inbounds[0].Reality.ShortIDs) == 0 {
		return Share{}, errors.New("в состоянии нет входящего подключения: ссылку не построить")
	}
	in := st.Inbounds[0]
	path := in.Params["path"]
	if path == "" {
		path = defaultPath
	}
	addrs := serverAddresses(st.Server.Addresses)
	if len(addrs) == 0 {
		return Share{}, errors.New("в состоянии нет адреса сервера: ссылку не построить")
	}
	if address == "" {
		address = addrs[0]
	} else if !slices.Contains(addrs, address) {
		return Share{}, fmt.Errorf("%w: --address: адреса сервера — %v", ErrInput, addrs)
	}
	endpoint := func(host string) export.Endpoint {
		return export.Endpoint{
			Host: host, Port: st.Server.Port, Preset: in.Preset, SNI: in.Reality.ServerNames[0],
			PublicKey: in.Reality.PublicKey, ShortID: in.Reality.ShortIDs[0], Path: path,
		}
	}
	// С клиентом путь один — Export с проверкой совместимости; без клиента проверка не нужна.
	build := func(x export.Exporter, host string) (export.Artifact, error) {
		if client == "" {
			return x.Export(p, endpoint(host))
		}
		return m.Export(p, endpoint(host), client, x)
	}
	var sh Share
	for _, a := range addrs {
		l, err := build(export.URI{}, a)
		if err != nil {
			return Share{}, err
		}
		sh.Links = append(sh.Links, Link{Address: a, URI: l.Text})
	}
	q, err := build(export.QR{}, address)
	if err != nil {
		return Share{}, err
	}
	sh.QRAddress, sh.QR = address, q.Text
	for _, c := range m.Clients(st) {
		if !c.Works {
			reason := c.Reason
			if c.MinClient != "" {
				reason += "; нужен " + c.MinClient
			}
			sh.Unfit = append(sh.Unfit, Unfit{Client: c.Name, Reason: reason})
		}
	}
	return sh, nil
}

// Clients — таблица совместимости для пресета и ядра сервера из состояния. Пресета или версии
// нет в таблице — пусто: таблица о таком сервере не говорит.
func (m *Manager) Clients(st store.State) []ClientInfo {
	if len(st.Inbounds) == 0 {
		return nil
	}
	var out []ClientInfo
	for _, c := range compat.Clients(st.Inbounds[0].Preset, st.Core.Version) {
		out = append(out, ClientInfo{Name: c.Name, Works: c.Works, Condition: c.Condition, Reason: c.Reason, MinClient: c.MinClient})
	}
	return out
}

// NextName — первое свободное имя вида profile-N для `xm add` без имени.
func (m *Manager) NextName(st store.State) string {
	for n := 1; ; n++ {
		name := "profile-" + strconv.Itoa(n)
		if !slices.ContainsFunc(st.Profiles, func(p store.Profile) bool { return p.Name == name }) {
			return name
		}
	}
}

// serverAddresses — заданные адреса сервера в порядке «домен, IPv4, IPv6».
func serverAddresses(a store.Addresses) []string {
	var out []string
	for _, v := range []string{a.Domain, a.IPv4, a.IPv6} {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
