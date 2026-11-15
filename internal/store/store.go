// Пакет store — состояние state.json: загрузка с проверкой схемы и миграциями, атомарная запись
// с правами 0600, межпроцессная блокировка. Все файловые операции — через platform.FS.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/grokki91/xray_core/internal/platform"
)

// Пути и права — docs/architecture/data-model.md §1.
const (
	StatePath = "/etc/xm/state.json"
	runDir    = "/run/xm"
	LockPath  = runDir + "/lock"
)

// schemaVersion — версия схемы, которую пишет эта сборка.
const schemaVersion = 1

var (
	ErrNoState     = errors.New("состояния нет: xm не установлен")
	ErrSchema      = errors.New("состояние не соответствует схеме")
	ErrNewerSchema = errors.New("состояние записано более новой версией xm: обновите xm")
)

// migration переводит документ с версии N на N+1. Работает с разобранным JSON, а не с State:
// старый документ в текущую структуру не ложится.
type migration func(doc map[string]any) (map[string]any, error)

// migrations — шаги миграции по исходной версии. Пусто, пока схема одна.
func migrations() map[int]migration { return map[int]migration{} }

// Store — доступ к состоянию.
type Store struct {
	fs         platform.FS
	current    int
	migrations map[int]migration
}

// New возвращает Store поверх файлов порта.
func New(fs platform.FS) *Store {
	return &Store{fs: fs, current: schemaVersion, migrations: migrations()}
}

// Load читает состояние, переводит его на текущую схему и проверяет. Мигрированное состояние
// на диск не пишется: это делает следующий Save внутри транзакции.
func (s *Store) Load() (State, error) {
	data, err := s.fs.ReadFile(StatePath)
	if errors.Is(err, platform.ErrNotFound) {
		return State{}, ErrNoState
	}
	if err != nil {
		return State{}, err
	}
	data, err = s.migrate(data)
	if err != nil {
		return State{}, err
	}
	var st State
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrSchema, err)
	}
	if dec.More() {
		return State{}, fmt.Errorf("%w: после документа есть данные", ErrSchema)
	}
	if err := s.check(st); err != nil {
		return State{}, err
	}
	return st, nil
}

// migrate возвращает документ в текущей схеме.
func (s *Store) migrate(data []byte) ([]byte, error) {
	var head struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSchema, err)
	}
	if head.SchemaVersion == nil {
		return nil, fmt.Errorf("%w: нет schema_version", ErrSchema)
	}
	v := *head.SchemaVersion
	switch {
	case v > s.current:
		return nil, fmt.Errorf("%w (версия схемы %d, эта сборка знает до %d)", ErrNewerSchema, v, s.current)
	case v == s.current:
		return data, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSchema, err)
	}
	for ; v < s.current; v++ {
		m, ok := s.migrations[v]
		if !ok {
			return nil, fmt.Errorf("%w: нет миграции с версии %d", ErrSchema, v)
		}
		var err error
		if doc, err = m(doc); err != nil {
			return nil, fmt.Errorf("миграция с версии %d: %w", v, err)
		}
		doc["schema_version"] = v + 1
	}
	return json.Marshal(doc)
}

func (s *Store) check(st State) error {
	if st.SchemaVersion != s.current {
		return fmt.Errorf("%w: schema_version %d, нужна %d", ErrSchema, st.SchemaVersion, s.current)
	}
	return nil
}

// Save атомарно записывает состояние с правами 0600 и владельцем root. Вызывается только
// внутри транзакции app (ADR-0005), под блокировкой Lock.
func (s *Store) Save(st State) error {
	if err := s.check(st); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return s.fs.WriteFile(StatePath, append(data, '\n'), 0o600, platform.Root())
}

// Lock берёт межпроцессную блокировку состояния и ждёт её до конца срока ctx. /run — tmpfs,
// поэтому каталог блокировки создаётся при необходимости.
func (s *Store) Lock(ctx context.Context) (unlock func(), err error) {
	if err := s.fs.Mkdir(runDir, 0o700, platform.Root()); err != nil {
		return nil, err
	}
	return s.fs.Lock(ctx, LockPath)
}
