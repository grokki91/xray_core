package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

// TxPath — журнал незавершённой транзакции (docs/architecture/data-model.md §1). Файл есть, пока
// транзакция идёт; следующий запуск xm сначала откатывает её (ADR-0005, ADR-0023).
const TxPath = "/var/lib/xm/tx/pending.json"

const txVersion = 1

// ErrTx — журнал транзакции нельзя прочитать: откат по нему невозможен.
var ErrTx = errors.New("журнал транзакции повреждён")

// Tx — что нужно для отката помимо снимка состояния и конфигурации (ADR-0023). Секретов нет:
// юнит и версия ядра их не содержат.
type Tx struct {
	Version    int       `json:"version"`
	Snapshot   string    `json:"snapshot"`    // идентификатор снимка backup
	CoreBefore string    `json:"core_before"` // активная версия Xray до транзакции; пусто — не было
	UnitBefore []byte    `json:"unit_before"` // файл юнита до транзакции; nil — юнита не было
	WasActive  bool      `json:"was_active"`  // служба была активна
	PortBefore int       `json:"port_before"` // порт до транзакции; 0 — состояния не было
	Started    time.Time `json:"started"`
	// UFWPort — порт, для которого эта транзакция добавляет правило UFW (ADR-0041); 0 — не
	// добавляет. Откат снимает такое правило: до транзакции его не было — иначе его бы не
	// добавляли.
	UFWPort int `json:"ufw_port"`
}

// WriteTx записывает журнал; существующий журнал не перезаписывается — это незавершённая
// транзакция, её сначала откатывают.
func (s *Store) WriteTx(t Tx) error {
	if _, err := s.fs.ReadFile(TxPath); err == nil {
		return fmt.Errorf("%w: уже есть незавершённая транзакция", ErrTx)
	} else if !errors.Is(err, platform.ErrNotFound) {
		return err
	}
	t.Version = txVersion
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return s.fs.WriteFile(TxPath, append(data, '\n'), 0o600, platform.Root())
}

// ReadTx возвращает журнал; ok=false — незавершённой транзакции нет.
func (s *Store) ReadTx() (t Tx, ok bool, err error) {
	data, err := s.fs.ReadFile(TxPath)
	if errors.Is(err, platform.ErrNotFound) {
		return Tx{}, false, nil
	}
	if err != nil {
		return Tx{}, false, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil || t.Version != txVersion || t.Snapshot == "" {
		return Tx{}, false, ErrTx
	}
	return t, true, nil
}

// ClearTx удаляет журнал: транзакция зафиксирована или откачена. Журнала нет — не ошибка.
func (s *Store) ClearTx() error {
	if err := s.fs.Remove(TxPath); err != nil && !errors.Is(err, platform.ErrNotFound) {
		return err
	}
	return nil
}

// Restore записывает state.json байтами снимка (backup.Read уже сверил их с манифестом).
// nil — состояния в снимке не было: файл удаляется. Проверки схемы нет намеренно: снимок мог
// быть снят с повреждённого состояния, а откат обязан вернуть именно его.
func (s *Store) Restore(data []byte) error {
	if data == nil {
		if err := s.fs.Remove(StatePath); err != nil && !errors.Is(err, platform.ErrNotFound) {
			return err
		}
		return nil
	}
	return s.fs.WriteFile(StatePath, data, 0o600, platform.Root())
}
