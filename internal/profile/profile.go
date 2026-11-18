// Пакет profile — клиентские профили в состоянии: проверка имени, добавление, список, показ,
// удаление. Работает над store.State и ничего не пишет: изменение проводит транзакция app.
// Учётные данные создаёт security; их передаёт app — менеджеры друг друга не импортируют.
package profile

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/grokki91/xray_core/internal/store"
)

var (
	// ErrInput — имя или идентификатор не по закрытому правилу.
	ErrInput = errors.New("недопустимый ввод профиля")
	// ErrExists — профиль с таким именем уже есть.
	ErrExists = errors.New("профиль уже есть")
	// ErrNotFound — профиля с таким именем нет.
	ErrNotFound = errors.New("профиля нет")
)

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	idRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// ValidName — имя профиля по правилу [a-z0-9][a-z0-9_-]{0,31}; оно же метка в ссылке.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Manager — профили над состоянием.
type Manager struct{}

func New() *Manager { return &Manager{} }

// Add возвращает состояние с новым включённым профилем. id — UUID v4 от security.
func (m *Manager) Add(st store.State, name, id string, now time.Time) (store.State, store.Profile, error) {
	if !ValidName(name) {
		return st, store.Profile{}, fmt.Errorf("%w: имя %q", ErrInput, name)
	}
	if !idRe.MatchString(id) {
		return st, store.Profile{}, fmt.Errorf("%w: идентификатор клиента", ErrInput)
	}
	for _, p := range st.Profiles {
		if p.Name == name {
			return st, store.Profile{}, fmt.Errorf("%w: %s", ErrExists, name)
		}
		// Совпадение UUID — сбой источника случайности; два профиля с одним ключом неразличимы.
		if p.ID == id {
			return st, store.Profile{}, fmt.Errorf("%w: идентификатор клиента повторяется", ErrInput)
		}
	}
	p := store.Profile{Name: name, ID: id, Created: now.UTC().Truncate(time.Second), Enabled: true}
	st.Profiles = append(slices.Clone(st.Profiles), p)
	return st, p, nil
}

// List — профили в порядке создания (копия).
func (m *Manager) List(st store.State) []store.Profile { return slices.Clone(st.Profiles) }

// Get — профиль по имени.
func (m *Manager) Get(st store.State, name string) (store.Profile, error) {
	if !ValidName(name) {
		return store.Profile{}, fmt.Errorf("%w: имя %q", ErrInput, name)
	}
	for _, p := range st.Profiles {
		if p.Name == name {
			return p, nil
		}
	}
	return store.Profile{}, fmt.Errorf("%w: %s", ErrNotFound, name)
}

// Remove возвращает состояние без профиля name.
func (m *Manager) Remove(st store.State, name string) (store.State, error) {
	if _, err := m.Get(st, name); err != nil {
		return st, err
	}
	st.Profiles = slices.DeleteFunc(slices.Clone(st.Profiles), func(p store.Profile) bool { return p.Name == name })
	return st, nil
}
