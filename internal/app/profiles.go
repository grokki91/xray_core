package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/contract"
	"github.com/grokki91/xray_core/internal/profile"
	"github.com/grokki91/xray_core/internal/store"
)

const profileTimeout = 2 * time.Minute

// ErrIncompatible — выбранный клиент не подключится к серверу (причина из таблицы совместимости).
// Код выхода 1: аргументы верны, сервер клиенту не подходит.
var ErrIncompatible = profile.ErrIncompatible

// ShareOptions — как показать профиль: для какого клиента проверить совместимость (пусто — не
// проверять) и для какого адреса сервера построить QR (пусто — первый).
type ShareOptions struct{ Client, Address string }

// ProfileView — профиль со ссылками и QR. Содержит секреты: получают его только команды, чьё
// назначение — их показать (`install`, `add`, `show`).
type ProfileView struct {
	contract.Profile
	// QR — для терминала, с ANSI; в машинный документ не входит, в файл и журнал не пишется.
	QR string
}

// profileErr сводит ошибки profile к ErrInput (код 2), сохраняя причину. Несовместимый клиент —
// не ошибка ввода: аргументы верны, но сервер этому клиенту не подойдёт (код 1).
func profileErr(err error) error {
	if errors.Is(err, profile.ErrInput) || errors.Is(err, profile.ErrExists) || errors.Is(err, profile.ErrNotFound) ||
		errors.Is(err, profile.ErrUnknownClient) {
		return fmt.Errorf("%w: %w", ErrInput, err)
	}
	return err
}

// ProfileAdd создаёт включённый профиль транзакцией и возвращает его ссылки. Пустое имя —
// profile-N. Имя проверяется до любых действий; повтор имени — под блокировкой: две команды не
// создадут один профиль дважды. Несовместимый клиент отказывает до изменения: профиль не
// создаётся.
func (a *App) ProfileAdd(ctx context.Context, name string, o ShareOptions) (ProfileView, error) {
	if name != "" && !profile.ValidName(name) {
		return ProfileView{}, fmt.Errorf("%w: имя профиля: [a-z0-9][a-z0-9_-]{0,31}", ErrInput)
	}
	if err := a.needRoot(); err != nil {
		return ProfileView{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, profileTimeout)
	defer cancel()
	id, err := a.s.Security.NewClientID()
	if err != nil {
		return ProfileView{}, err
	}
	a.s.Redactor.Register("uuid", id)
	var view ProfileView
	err = a.Apply(ctx, Change{Reason: "profile-add", Edit: func(st store.State) (store.State, error) {
		n := name
		if n == "" {
			n = a.s.Profile.NextName(st)
		}
		st, p, err := a.s.Profile.Add(st, n, id, a.s.Now())
		if err != nil {
			return st, profileErr(err)
		}
		sh, err := a.s.Profile.Share(st, p.Name, o.Client, o.Address)
		if err != nil {
			return st, profileErr(err)
		}
		view = newView(p, sh)
		return st, nil
	}})
	if err != nil {
		return ProfileView{}, err
	}
	return view, nil
}

// newView собирает документ профиля из состояния и ссылок.
func newView(p store.Profile, sh profile.Share) ProfileView {
	v := ProfileView{QR: sh.QR, Profile: contract.Profile{
		ProfileItem: item(p), Links: []contract.ProfileLink{}, QRAddress: sh.QRAddress, Unfit: []contract.UnfitClient{},
	}}
	for _, l := range sh.Links {
		v.Links = append(v.Links, contract.ProfileLink{Address: l.Address, URI: l.URI})
	}
	for _, u := range sh.Unfit {
		v.Unfit = append(v.Unfit, contract.UnfitClient{Client: u.Client, Reason: u.Reason})
	}
	return v
}

func item(p store.Profile) contract.ProfileItem {
	return contract.ProfileItem{Name: p.Name, Created: p.Created.Unix(), Enabled: p.Enabled}
}

// ProfileRemove удаляет профиль транзакцией: после фиксации клиент с его ключом не принимается.
func (a *App) ProfileRemove(ctx context.Context, name string) error {
	if !profile.ValidName(name) {
		return fmt.Errorf("%w: имя профиля: [a-z0-9][a-z0-9_-]{0,31}", ErrInput)
	}
	if err := a.needRoot(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, profileTimeout)
	defer cancel()
	return a.Apply(ctx, Change{Reason: "profile-rm", Edit: func(st store.State) (store.State, error) {
		st, err := a.s.Profile.Remove(st, name)
		return st, profileErr(err)
	}})
}

// ProfileList — профили установки в порядке создания, без секретов.
func (a *App) ProfileList(context.Context) (contract.Profiles, error) {
	st, err := a.profileState()
	if err != nil {
		return contract.Profiles{}, err
	}
	out := contract.Profiles{Profiles: []contract.ProfileItem{}}
	for _, p := range a.s.Profile.List(st) {
		out.Profiles = append(out.Profiles, item(p))
	}
	return out, nil
}

// ProfileShow — профиль со ссылками на каждый адрес сервера и QR.
func (a *App) ProfileShow(_ context.Context, name string, o ShareOptions) (ProfileView, error) {
	st, err := a.profileState()
	if err != nil {
		return ProfileView{}, err
	}
	p, err := a.s.Profile.Get(st, name)
	if err != nil {
		return ProfileView{}, profileErr(err)
	}
	sh, err := a.s.Profile.Share(st, name, o.Client, o.Address)
	if err != nil {
		return ProfileView{}, profileErr(err)
	}
	return newView(p, sh), nil
}

// profileState — состояние для чтения профилей: root, установка есть.
func (a *App) profileState() (store.State, error) {
	if err := a.needRoot(); err != nil {
		return store.State{}, err
	}
	st, ok, err := a.installed()
	if err != nil {
		return store.State{}, err
	}
	if !ok {
		return store.State{}, ErrNotInstalled
	}
	return st, nil
}
