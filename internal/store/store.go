// Пакет store — состояние state.json: загрузка с проверкой схемы и миграциями, атомарная запись
// с правами 0600, межпроцессная блокировка. Все файловые операции — через platform.FS.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"

	"github.com/grokki91/xray_core/internal/platform"
)

// Пути и права — docs/architecture/data-model.md §1.
const (
	StatePath = "/etc/xm/state.json"
	runDir    = "/run/xm"
	LockPath  = runDir + "/lock"
)

// SchemaVersion — версия схемы, которую пишет эта сборка.
const SchemaVersion = 3

var (
	ErrNoState     = errors.New("состояния нет: xm не установлен")
	ErrSchema      = errors.New("состояние не соответствует схеме")
	ErrNewerSchema = errors.New("состояние записано более новой версией xm: обновите xm")
)

// migration переводит документ с версии N на N+1. Работает с разобранным JSON, а не с State:
// старый документ в текущую структуру не ложится.
type migration func(doc map[string]any) (map[string]any, error)

// migrations — шаги миграции по исходной версии.
func migrations() map[int]migration { return map[int]migration{1: addSelftest, 2: addFirewall} }

// addSelftest: версия 2 добавляет служебного клиента самопроверки; поле пустое, id создаёт
// следующая транзакция app (ADR-0032).
func addSelftest(doc map[string]any) (map[string]any, error) {
	if _, ok := doc["selftest"]; ok {
		return nil, errors.New("в версии 1 уже есть selftest")
	}
	doc["selftest"] = map[string]any{"id": ""}
	return doc, nil
}

// addFirewall: версия 3 добавляет метку правила UFW (ADR-0041); у прежних установок правила
// от xm не было.
func addFirewall(doc map[string]any) (map[string]any, error) {
	if _, ok := doc["firewall"]; ok {
		return nil, errors.New("в версии 2 уже есть firewall")
	}
	doc["firewall"] = map[string]any{"ufw_rule": false}
	return doc, nil
}

var reUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Store — доступ к состоянию.
type Store struct {
	fs         platform.FS
	current    int
	migrations map[int]migration
}

// New возвращает Store поверх файлов порта.
func New(fs platform.FS) *Store {
	return &Store{fs: fs, current: SchemaVersion, migrations: migrations()}
}

// Load читает состояние, переводит его на текущую схему и проверяет (Parse). Мигрированное состояние
// на диск не пишется: это делает следующий Save внутри транзакции.
func (s *Store) Load() (State, error) {
	data, err := s.fs.ReadFile(StatePath)
	if errors.Is(err, platform.ErrNotFound) {
		return State{}, ErrNoState
	}
	if err != nil {
		return State{}, err
	}
	return s.Parse(data)
}

// Parse переводит документ состояния на текущую схему и проверяет его так же, как Load: нужен
// восстановлению из снимка, где документ приходит не с диска.
func (s *Store) Parse(data []byte) (State, error) {
	data, err := s.migrate(data)
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
	if err := canonical(data, st); err != nil {
		return State{}, err
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

// canonical требует, чтобы документ совпадал со своей записью из State: encoding/json
// сопоставляет ключи без учёта регистра и берёт последний из повторов, а пропущенное поле
// оставляет нулевым. Файл пишет только xm, поэтому любое расхождение — порча, а не вариант
// формы.
func canonical(data []byte, st State) error {
	if err := noDuplicateKeys(data); err != nil {
		return err
	}
	again, err := json.Marshal(st)
	if err != nil {
		return err
	}
	var a, b any
	if err := json.Unmarshal(data, &a); err != nil {
		return fmt.Errorf("%w: %v", ErrSchema, err)
	}
	if err := json.Unmarshal(again, &b); err != nil {
		return err
	}
	if !reflect.DeepEqual(a, b) {
		return fmt.Errorf("%w: поля отсутствуют, null или ключи не в точном написании", ErrSchema)
	}
	return nil
}

// noDuplicateKeys отвергает объект с повтором ключа на любом уровне.
func noDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				if seen[k.(string)] {
					return fmt.Errorf("%w: повтор ключа %q", ErrSchema, k)
				}
				seen[k.(string)] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		case json.Delim('['):
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		}
		return err
	}
	return walk()
}

// check — правила содержимого, которые не выражает форма JSON.
func (s *Store) check(st State) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrSchema}, a...)...)
	}
	switch {
	case st.SchemaVersion != s.current:
		return bad("schema_version %d, нужна %d", st.SchemaVersion, s.current)
	case st.Server.Port < 1 || st.Server.Port > 65535:
		return bad("порт %d вне 1…65535", st.Server.Port)
	case st.Server.Addresses == (Addresses{}):
		return bad("у сервера нет ни адреса, ни домена")
	case len(st.Inbounds) == 0:
		return bad("нет входящих")
	case st.Profiles == nil:
		return bad("нет списка профилей")
	case st.Selftest.ID != "" && !reUUID.MatchString(st.Selftest.ID):
		return bad("selftest.id не UUID")
	}
	for i, in := range st.Inbounds {
		r := in.Reality
		if in.Preset == "" || in.Params == nil || r.Target == "" || len(r.ServerNames) == 0 || r.PrivateKey == "" ||
			r.PublicKey == "" || len(r.ShortIDs) == 0 {
			return bad("входящий %d: не заполнены пресет, параметры, цель, имена, ключи или shortId", i)
		}
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
