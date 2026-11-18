package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/profile"
	"github.com/grokki91/xray_core/internal/store"
)

const profileTimeout = 2 * time.Minute

// profileErr сводит ошибки profile к ErrInput (код 2), сохраняя причину.
func profileErr(err error) error {
	if errors.Is(err, profile.ErrInput) || errors.Is(err, profile.ErrExists) || errors.Is(err, profile.ErrNotFound) {
		return fmt.Errorf("%w: %w", ErrInput, err)
	}
	return err
}

// ProfileAdd создаёт включённый профиль транзакцией. Имя проверяется до любых действий;
// повтор имени проверяется под блокировкой — две команды не создадут один профиль дважды.
func (a *App) ProfileAdd(ctx context.Context, name string) (store.Profile, error) {
	if !profile.ValidName(name) {
		return store.Profile{}, fmt.Errorf("%w: имя профиля: [a-z0-9][a-z0-9_-]{0,31}", ErrInput)
	}
	if err := a.needRoot(); err != nil {
		return store.Profile{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, profileTimeout)
	defer cancel()
	id, err := a.s.Security.NewClientID()
	if err != nil {
		return store.Profile{}, err
	}
	a.s.Redactor.Register("uuid", id)
	var added store.Profile
	err = a.Apply(ctx, Change{Reason: "profile-add", Edit: func(st store.State) (store.State, error) {
		st, p, err := a.s.Profile.Add(st, name, id, a.s.Now())
		added = p
		return st, profileErr(err)
	}})
	if err != nil {
		return store.Profile{}, err
	}
	return added, nil
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

// ProfileList — профили установки в порядке создания.
func (a *App) ProfileList(context.Context) ([]store.Profile, error) {
	st, err := a.profileState()
	if err != nil {
		return nil, err
	}
	return a.s.Profile.List(st), nil
}

// ProfileShow — один профиль по имени.
func (a *App) ProfileShow(_ context.Context, name string) (store.Profile, error) {
	st, err := a.profileState()
	if err != nil {
		return store.Profile{}, err
	}
	p, err := a.s.Profile.Get(st, name)
	return p, profileErr(err)
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
