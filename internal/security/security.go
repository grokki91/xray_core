// Пакет security — ключи, права и изоляция службы. Единственный источник случайных секретов
// (docs/security/secrets.md §3): ключи REALITY, идентификатор клиента и shortId берутся из
// crypto/rand только здесь. Аудит — после MVP.
package security

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"

	"github.com/grokki91/xray_core/internal/platform"
)

// ServiceUser — системный пользователь, от которого работает Xray.
const ServiceUser = platform.ServiceUser

// RealityKeys — пара X25519 в формате Xray: base64 RawURL, 32 байта.
type RealityKeys struct {
	Private, Public string
}

// UnitOption — директива секции [Service] юнита.
type UnitOption struct{ Key, Value string }

// Manager — ключи, права, изоляция.
type Manager struct {
	p platform.Platform
}

func New(p platform.Platform) *Manager { return &Manager{p: p} }

// NewRealityKeys создаёт пару ключей REALITY.
func (m *Manager) NewRealityKeys(context.Context) (RealityKeys, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return RealityKeys{}, fmt.Errorf("ключи REALITY: %w", err)
	}
	enc := base64.RawURLEncoding
	return RealityKeys{Private: enc.EncodeToString(k.Bytes()), Public: enc.EncodeToString(k.PublicKey().Bytes())}, nil
}

// NewClientID создаёт идентификатор клиента — UUID версии 4.
func (m *Manager) NewClientID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("идентификатор клиента: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// NewShortID создаёт shortId — 16 шестнадцатеричных знаков (предел Xray — 8 байт).
func (m *Manager) NewShortID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("shortId: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// dir — строка манифеста прав (docs/architecture/data-model.md §1) для каталога.
type dir struct {
	path  string
	perm  fs.FileMode
	group bool // группа xray вместо root
}

// manifest — каталоги по порядку создания: родитель раньше потомка. Файлы создают их
// владельцы-менеджеры сразу с правами манифеста.
var manifest = []dir{
	{"/usr/local/lib/xm", 0o755, false},
	{platform.CoreDir, 0o755, false},
	{"/etc/xm", 0o700, false},
	{"/usr/local/etc/xray", 0o750, true},
	{"/var/lib/xm", 0o700, false},
	{"/var/lib/xm/backups", 0o700, false},
	{"/var/lib/xm/tx", 0o700, false},
	{"/var/lib/xm/diag", 0o700, false},
	{"/var/lib/xm/monitor", 0o700, false},
	{"/var/lib/xm/cache", 0o700, false},
	{"/run/xm", 0o700, false},
}

// EnsureBaseline заводит пользователя xray и каталоги манифеста с их владельцами и правами.
// Существующий каталог с другими правами — ошибка: чужие права не исправляются молча.
func (m *Manager) EnsureBaseline(ctx context.Context) error {
	svc, err := m.p.Users().Ensure(ctx, ServiceUser)
	if err != nil {
		return fmt.Errorf("базовая защита: %w", err)
	}
	for _, d := range manifest {
		owner := platform.Root()
		if d.group {
			owner.GID = svc.GID
		}
		if err := m.p.FS().Mkdir(d.path, d.perm, owner); err != nil {
			return fmt.Errorf("базовая защита: %w", err)
		}
	}
	return nil
}

// UnitHardening — директивы изоляции юнита (docs/security/policy.md §3). Точный набор на
// каждой поддерживаемой ОС подтверждает системный тест L4.
func (m *Manager) UnitHardening() []UnitOption {
	return []UnitOption{
		{"NoNewPrivileges", "true"},
		{"ProtectSystem", "strict"},
		{"ProtectHome", "true"},
		{"PrivateTmp", "true"},
		{"PrivateDevices", "true"},
		{"ProtectKernelTunables", "true"},
		{"ProtectKernelModules", "true"},
		{"ProtectControlGroups", "true"},
		{"RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX"},
		{"RestrictNamespaces", "true"},
		{"LockPersonality", "true"},
		{"MemoryDenyWriteExecute", "true"},
		{"SystemCallArchitectures", "native"},
		{"CapabilityBoundingSet", "CAP_NET_BIND_SERVICE"},
		{"AmbientCapabilities", "CAP_NET_BIND_SERVICE"},
	}
}
