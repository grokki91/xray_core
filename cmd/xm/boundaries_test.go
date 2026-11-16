package main

// Тест графа импортов: правила docs/architecture/repository.md §3. Проверяются исходники без
// _test.go — тестам пакета нужны общие помощники (канареечный тест redact, поддельный platform).

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// layers — слой каждого пакета верхнего уровня в internal/.
var layers = map[string]string{
	"cli": "interface", "api": "interface", "webui": "interface", "bridge": "interface",
	"app":  "app",
	"core": "manager", "config": "manager", "profile": "manager", "server": "manager",
	"network": "manager", "dns": "manager", "security": "manager", "diag": "manager",
	"logging": "manager", "update": "manager", "backup": "manager", "monitor": "manager",
	"store":    "store",
	"platform": "base", "redact": "base", "contract": "base",
}

// mayImport — какие пакеты internal/ импортирует слой (по имени верхнего уровня или слою).
var mayImport = map[string][]string{
	"interface": {"app", "contract"},
	"app":       {"manager", "contract", "store"},
	"manager":   {"platform", "store", "redact", "contract"},
	"store":     {"platform", "contract"},
	"base":      {},
}

// checkImports возвращает нарушения правил в дереве модуля root с путём module.
func checkImports(root, module string) ([]string, error) {
	var bad []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		if dir != "cmd/xm" && !strings.HasPrefix(dir, "internal/") {
			bad = append(bad, fmt.Sprintf("%s: Go-код вне cmd/xm и internal/", rel))
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			target, _ := strconv.Unquote(imp.Path.Value)
			if why := forbidden(dir, target, module); why != "" {
				bad = append(bad, fmt.Sprintf("%s: импорт %s — %s", rel, target, why))
			}
			if target == module+"/internal/redact/redacttest" || target == module+"/internal/platform/xraytest" {
				bad = append(bad, fmt.Sprintf("%s: импорт %s — помощник только для _test.go", rel, target))
			}
		}
		if usesFake(f, module) && dir != "internal/platform" {
			bad = append(bad, fmt.Sprintf("%s: platform.NewFake — только в _test.go", rel))
		}
		return nil
	})
	sort.Strings(bad)
	return bad, err
}

// usesFake сообщает, вызывает ли файл поддельную реализацию platform: она лежит в самом
// пакете platform (подпакет platform/fake не может импортировать platform по таблице слоёв),
// поэтому её экспорт закрывается этим правилом, а не границей пакета.
func usesFake(f *ast.File, module string) bool {
	name := ""
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == module+"/internal/platform" {
			name = "platform"
			if imp.Name != nil {
				name = imp.Name.Name
			}
		}
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok && name != "" {
			if x, ok := s.X.(*ast.Ident); ok && x.Name == name && s.Sel.Name == "NewFake" {
				found = true
			}
		}
		return !found
	})
	return found
}

// forbidden возвращает причину запрета импорта target из каталога dir или пустую строку.
func forbidden(dir, target, module string) string {
	from := strings.Split(strings.TrimPrefix(dir, "internal/"), "/")
	fromLayer := layers[from[0]]
	if dir != "cmd/xm" && fromLayer == "" {
		return "пакет internal/" + from[0] + " не описан в repository.md §3"
	}
	if !strings.HasPrefix(target+"/", module+"/") {
		if strings.Contains(strings.Split(target, "/")[0], ".") {
			return "сторонний модуль: нужны согласие владельца и строка в dependencies.md"
		}
		if (target == "os/exec" || target == "syscall") && from[0] != "platform" {
			return "процессы и системные вызовы — только в platform"
		}
		return ""
	}
	if dir == "cmd/xm" {
		return ""
	}
	to := strings.Split(strings.TrimPrefix(target, module+"/internal/"), "/")
	if !strings.HasPrefix(target, module+"/internal/") || layers[to[0]] == "" {
		return "пакет не описан в repository.md §3"
	}
	if len(to) > 1 && layers[to[0]] == "manager" {
		if len(from) == 1 && from[0] == to[0] {
			return ""
		}
		return "подпакет менеджера импортирует только его менеджер"
	}
	for _, ok := range mayImport[fromLayer] {
		if ok == to[0] || (ok == layers[to[0]] && to[0] != from[0]) {
			return ""
		}
	}
	return fmt.Sprintf("слой %s не импортирует %s", fromLayer, to[0])
}

func moduleRoot(t *testing.T) (root, module string) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if m, ok := strings.CutPrefix(s.Text(), "module "); ok {
			return root, strings.TrimSpace(m)
		}
	}
	t.Fatal("в go.mod нет строки module")
	return "", ""
}

func TestRepositoryImports(t *testing.T) {
	root, module := moduleRoot(t)
	bad, err := checkImports(root, module)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// Правила проверяются на временных деревьях: каждое либо нарушение, либо разрешённый импорт.
func TestImportRules(t *testing.T) {
	const m = "example.org/xm"
	cases := []struct {
		dir, imp string
		bad      bool
	}{
		{"cmd/xm", m + "/internal/platform", false},
		{"internal/cli", m + "/internal/app", false},
		{"internal/cli", m + "/internal/contract", false},
		{"internal/cli", m + "/internal/platform", true},
		{"internal/cli", m + "/internal/core", true},
		{"internal/app", m + "/internal/core", false},
		{"internal/app", m + "/internal/store", false},
		{"internal/app", m + "/internal/platform", true},
		{"internal/app", m + "/internal/config/preset", true},
		{"internal/core", m + "/internal/platform", false},
		{"internal/core", m + "/internal/redact", false},
		{"internal/core", m + "/internal/config", true},
		{"internal/core", m + "/internal/app", true},
		{"internal/config", m + "/internal/config/preset", false},
		{"internal/profile", m + "/internal/config/preset", true},
		{"internal/config/preset", m + "/internal/contract", false},
		{"internal/config/preset", m + "/internal/config", true},
		{"internal/store", m + "/internal/platform", false},
		{"internal/store", m + "/internal/redact", true},
		{"internal/platform", m + "/internal/contract", true},
		{"internal/redact", m + "/internal/platform", true},
		{"internal/platform", "os/exec", false},
		{"internal/store", "os/exec", true},
		{"internal/core", "syscall", true},
		{"internal/platform", "syscall", false},
		{"internal/store", m + "/internal/platform/fake", false},
		{"internal/cli", m + "/internal/platform/fake", true},
		{"internal/contract", "encoding/json", false},
		{"internal/contract", "github.com/some/module", true},
		{"internal/cli", m + "/internal/unknown", true},
		{"internal/unknown", "fmt", true},
		{"tools", "fmt", true},
	}
	for _, tc := range cases {
		t.Run(tc.dir+" → "+tc.imp, func(t *testing.T) {
			pkg := filepath.Base(tc.dir)
			src := fmt.Sprintf("package %s\n\nimport _ %q\n", pkg, tc.imp)
			assertViolation(t, tc.dir, src, m, tc.bad)
		})
	}
}

// Помощники тестов недоступны рабочему коду: redacttest, xraytest и platform.NewFake.
func TestTestHelpersOnlyInTests(t *testing.T) {
	const m = "example.org/xm"
	cases := []struct {
		dir, src string
		bad      bool
	}{
		{"internal/core", "package core\n\nimport _ \"" + m + "/internal/redact/redacttest\"\n", true},
		{"internal/core", "package core\n\nimport _ \"" + m + "/internal/platform/xraytest\"\n", true},
		{"internal/core", "package core\n\nimport \"" + m + "/internal/platform\"\n\nvar _ = platform.New\n", false},
		{"internal/core", "package core\n\nimport \"" + m + "/internal/platform\"\n\nvar _ = platform.NewFake\n", true},
		{"internal/core", "package core\n\nimport p \"" + m + "/internal/platform\"\n\nvar _ = p.NewFake\n", true},
		{"cmd/xm", "package main\n\nimport \"" + m + "/internal/platform\"\n\nvar _ = platform.NewFake\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.src, func(t *testing.T) { assertViolation(t, tc.dir, tc.src, m, tc.bad) })
	}
}

func assertViolation(t *testing.T, dir, src, m string, want bool) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(dir), "x.go")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	bad, err := checkImports(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(bad) > 0; got != want {
		t.Fatalf("нарушение: %v, ожидалось %v; %v", got, want, bad)
	}
}
