package main

import (
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/redact"
	"github.com/grokki91/xray_core/internal/redact/redacttest"
	"github.com/grokki91/xray_core/internal/update"
)

// Токен из окружения попадает в редактор: в выводе вместо него метка (ADR-0031, канарейка).
func TestGitHubTokenRedacted(t *testing.T) {
	c := redacttest.New(t)
	env := func(token string) func(string) string {
		return func(name string) string {
			if name == update.TokenEnv {
				return token
			}
			return ""
		}
	}

	reg := redact.New()
	if got := githubToken(env(c.GitHubToken), reg); got != c.GitHubToken {
		t.Fatalf("токен не передан источнику")
	}
	out := reg.Text("загрузка api.github.com: Authorization: Bearer " + c.GitHubToken)
	redacttest.AssertClean(t, c, map[string]string{"вывод": out})
	if !strings.Contains(out, "<token:1>") {
		t.Errorf("нет метки токена: %q", out)
	}

	// Значение не по формату не регистрируется: иначе «a» стало бы меткой во всём выводе.
	reg = redact.New()
	githubToken(env("a"), reg)
	if got := reg.Text("a b a"); got != "a b a" {
		t.Errorf("неверный токен зарегистрирован: %q", got)
	}
}
