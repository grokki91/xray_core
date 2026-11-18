// Пакет redacttest — канареечный помощник для тестов (docs/testing.md §4): узнаваемые фиктивные
// значения секретов и проверка, что ни одно не встретилось в выводе. Сценарий заводит
// состояние из Canaries, прогоняет себя и передаёт в AssertClean весь вывод, журналы, отчёты,
// экспорт и тексты ошибок. Только для тестов.
package redacttest

import (
	"crypto/rand"
	"encoding/base64"
	"sort"
	"strings"
	"testing"
)

// Canaries — значения S1 и S2 одной установки. Фиктивные по docs/security/secrets.md §4;
// ключи создаются при каждом вызове New.
type Canaries struct {
	UUID, PrivateKey, PublicKey, ShortID, IPv4, IPv6, Domain, Path string
	GitHubToken                                                    string // из окружения xm, не из состояния
}

// New возвращает набор канареек со свежими ключами.
func New(t testing.TB) Canaries {
	t.Helper()
	return Canaries{
		UUID:        "00000000-0000-4000-8000-0000000ca4a1",
		PrivateKey:  key(t),
		PublicKey:   key(t),
		ShortID:     "0123456789abcdef",
		IPv4:        "203.0.113.77",
		IPv6:        "2001:db8::77",
		Domain:      "canary.example.com",
		Path:        "/canary-path-7f3a",
		GitHubToken: "xm_fake_github_token_000000000000000000001",
	}
}

func key(t testing.TB) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// All возвращает канарейки по именам.
func (c Canaries) All() map[string]string {
	return map[string]string{
		"UUID": c.UUID, "PrivateKey": c.PrivateKey, "PublicKey": c.PublicKey, "ShortID": c.ShortID,
		"IPv4": c.IPv4, "IPv6": c.IPv6, "Domain": c.Domain, "Path": c.Path,
		"GitHubToken": c.GitHubToken,
	}
}

// AssertClean проваливает тест, если канарейка встретилась в одном из выводов (имя → текст).
// Сам вывод в сообщение не попадает — только имена вывода и канарейки.
func AssertClean(t testing.TB, c Canaries, outputs map[string]string) {
	t.Helper()
	var found []string
	for out, text := range outputs {
		for name, v := range c.All() {
			if strings.Contains(text, v) {
				found = append(found, out+": "+name)
			}
		}
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("канарейка в выводе — %s", f)
	}
}
