// Команда xm — менеджер Xray-core. Здесь только сборка зависимостей: логика живёт в internal.
package main

import (
	"os"
	"time"

	"github.com/grokki91/xray_core/internal/cli"
)

// version подставляется при сборке: -ldflags "-X main.version=<версия>". Пакетная переменная —
// единственный способ принять значение от компоновщика; после старта она не меняется.
var version = "dev"

// systemClock — системные часы; заменяются часами platform, когда появится порт.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.Env{
		Stdout: os.Stdout, Stderr: os.Stderr, Version: version, Clock: systemClock{},
	}))
}
