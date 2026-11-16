// Пакет xraytest — стенд L3 (docs/testing.md §2, §5): архив настоящего Xray-core закреплённой
// версии со сверкой SHA-256 и кэшем по версии. Загружает вызывающий тест через platform.Net
// (Get): подпакет platform не импортирует platform по таблице слоёв. Архив передаётся в
// core.Stage, бинарник запускается поддельным platform через RunUnderRoot. Только для тестов с
// тегом сборки l3.
package xraytest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// sums — SHA-256 архива Xray-linux-64.zip нижней и верхней границ проверенного диапазона
// (выбор владельца 2026-11-16): строка SHA2-256 из .dgst релиза совпала с суммой загрузки
// (docs/compatibility.md §2).
var sums = map[string]string{
	"26.10.21": "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978",
	"26.11.9":  "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82",
}

// Versions возвращает границы проверенного диапазона по возрастанию.
func Versions() []string { return []string{"26.10.21", "26.11.9"} }

// Get — загрузка по адресу с закрытым списком узлов и пределом: platform.Net.Get.
type Get func(ctx context.Context, url string, hosts []string) ([]byte, error)

// Hosts — узлы загрузки: github.com перенаправляет на release-assets
// (docs/dev/dependencies.md §3).
var Hosts = []string{"github.com", "release-assets.githubusercontent.com"}

const (
	asset   = "Xray-linux-64.zip"
	timeout = 5 * time.Minute
)

// Archive возвращает архив версии v: из кэша, если его сумма верна, иначе загружает через get
// и кладёт в кэш. Версия вне закреплённого списка, ошибка загрузки или неверная сумма —
// провал теста.
func Archive(t testing.TB, get Get, v string) []byte {
	t.Helper()
	sum, ok := sums[v]
	if !ok {
		t.Fatalf("xraytest: версия %q не закреплена", v)
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("xraytest: каталог кэша: %v", err)
	}
	file := filepath.Join(dir, "xm-test", "xray", v, asset)
	if b, err := os.ReadFile(file); err == nil && check(b, sum) == nil {
		return b
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	b, err := get(ctx, "https://github.com/XTLS/Xray-core/releases/download/v"+v+"/"+asset, Hosts)
	if err != nil {
		t.Fatalf("xraytest: %s: %v", v, err)
	}
	if err := check(b, sum); err != nil {
		t.Fatalf("xraytest: %s: %v", v, err)
	}
	if err := store(file, b); err != nil {
		t.Fatalf("xraytest: кэш: %v", err)
	}
	return b
}

func check(b []byte, sum string) error {
	got := sha256.Sum256(b)
	if hex.EncodeToString(got[:]) != sum {
		return errors.New("SHA-256 архива не совпадает с закреплённой")
	}
	return nil
}

// store пишет кэш атомарно: временный файл, fsync, rename — параллельные пакеты тестов не
// видят половину архива.
func store(file string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), asset+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), file)
}
