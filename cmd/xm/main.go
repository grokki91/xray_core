// Команда xm — менеджер Xray-core. Здесь только сборка зависимостей: логика живёт в internal.
package main

import (
	"os"

	"github.com/grokki91/xray_core/internal/cli"
	"github.com/grokki91/xray_core/internal/platform"
)

// version подставляется при сборке: -ldflags "-X main.version=<версия>". Пакетная переменная —
// единственный способ принять значение от компоновщика; после старта она не меняется.
var version = "dev"

func main() {
	p := platform.New()
	os.Exit(cli.Run(os.Args[1:], cli.Env{
		Stdout: os.Stdout, Stderr: os.Stderr, Version: version, Clock: p.Clock(),
	}))
}
