package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

const (
	tag      = "v26.11.9"
	zipURL   = downloadURL + tag + "/Xray-linux-64.zip"
	assetURL = "https://" + hostAssets + "/github-production-release-asset/fake-zip"
	dgstURL  = zipURL + ".dgst"
)

// archive — фиктивный архив: содержимое не предмет проверки, только суммы.
var archive = []byte("PK\x03\x04 фиктивный архив релиза")

func sums(data []byte) (string, string) {
	a, b := sha256.Sum256(data), sha512.Sum512(data)
	return hex.EncodeToString(a[:]), hex.EncodeToString(b[:])
}

func dgstFor(data []byte) []byte {
	s256, s512 := sums(data)
	return fmt.Appendf(nil, "MD5= 00\nSHA1= 00\nSHA2-256= %s\nSHA2-512= %s\n", s256, s512)
}

func releaseJSON(tag string, pre bool, digest string) []byte {
	return fmt.Appendf(nil, `{"tag_name":%q,"prerelease":%v,"draft":false,"assets":[
		{"name":"Xray-linux-64.zip","digest":%q},
		{"name":"Xray-linux-64.zip.dgst","digest":"sha256:00"}]}`, tag, pre, digest)
}

// env — поддельная машина с каталогом /var/lib и релизом, который отвечает как GitHub:
// архив — перенаправлением на узел раздачи файлов.
func env(t *testing.T) (*platform.Fake, *GitHub) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(root+"/var/lib", 0o755); err != nil {
		t.Fatal(err)
	}
	f := platform.NewFake(root, time.Time{})
	s256, _ := sums(archive)
	f.Serve(latestURL, releaseJSON(tag, false, "sha256:"+s256))
	f.Serve(dgstURL, dgstFor(archive))
	f.Redirect(zipURL, assetURL)
	f.Serve(assetURL, archive)
	return f, NewGitHub(f, "")
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func latest(t *testing.T, g *GitHub) Release {
	t.Helper()
	r, err := g.Latest(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const cached = cacheDir + "/" + tag + "-Xray-linux-64.zip"

func TestFetchVerifiesAndCaches(t *testing.T) {
	f, g := env(t)
	r := latest(t, g)
	if r.Tag != tag || r.Version() != "26.11.9" {
		t.Fatalf("релиз %+v", r)
	}
	a, err := g.Fetch(ctx(t), r, ArchAMD64)
	if err != nil {
		t.Fatal(err)
	}
	s256, s512 := sums(archive)
	if !bytes.Equal(a.Data, archive) || a.Digests != (Digests{s256, s512}) {
		t.Fatalf("архив %q, суммы %+v", a.Data, a.Digests)
	}
	fi, err := os.Stat(f.Path(cached))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("кэш: %v, %v", fi, err)
	}
	for _, dir := range []string{dataDir, cacheDir} {
		if fi, err := os.Stat(f.Path(dir)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v, %v", dir, fi, err)
		}
	}

	// Повтор берёт архив из кэша: узел раздачи больше не отвечает.
	f.Serve(assetURL, nil)
	f.Redirect(assetURL, "https://"+hostAssets+"/gone")
	if a, err := g.Fetch(ctx(t), r, ArchAMD64); err != nil || !bytes.Equal(a.Data, archive) {
		t.Fatalf("из кэша: %q, %v", a.Data, err)
	}

	// Испорченный кэш не используется: без загрузки — ошибка, с загрузкой — свежий архив.
	if err := os.WriteFile(f.Path(cached), []byte("испорчен"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Fetch(ctx(t), r, ArchAMD64); err == nil {
		t.Fatal("испорченный кэш принят")
	}
	f.Serve(assetURL, archive)
	if a, err := g.Fetch(ctx(t), r, ArchAMD64); err != nil || !bytes.Equal(a.Data, archive) {
		t.Fatalf("после испорченного кэша: %q, %v", a.Data, err)
	}
	if got, _ := os.ReadFile(f.Path(cached)); !bytes.Equal(got, archive) {
		t.Errorf("кэш не заменён: %q", got)
	}

	// Файл кэша, который не читается (больше предела), тоже заменяется свежим архивом.
	if err := os.WriteFile(f.Path(cached), make([]byte, platform.MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, err := g.Fetch(ctx(t), r, ArchAMD64); err != nil || !bytes.Equal(a.Data, archive) {
		t.Fatalf("после нечитаемого кэша: %v", err)
	}
}

// Испорченный вход отвергается до того, как архив попадает в кэш.
func TestFetchRejects(t *testing.T) {
	s256, s512 := sums(archive)
	cases := []struct {
		name  string
		setup func(f *platform.Fake)
		want  error
	}{
		{"испорченный архив", func(f *platform.Fake) { f.Serve(assetURL, append([]byte("x"), archive...)) }, ErrIntegrity},
		{"неверная SHA2-512", func(f *platform.Fake) {
			f.Serve(dgstURL, fmt.Appendf(nil, "SHA2-256= %s\nSHA2-512= %s\n", s256, strings.Repeat("0", 128)))
		}, ErrIntegrity},
		{"неверная SHA2-256", func(f *platform.Fake) {
			f.Serve(dgstURL, fmt.Appendf(nil, "SHA2-256= %s\nSHA2-512= %s\n", strings.Repeat("0", 64), s512))
		}, ErrIntegrity},
		{"нет SHA2-512", func(f *platform.Fake) { f.Serve(dgstURL, fmt.Appendf(nil, "SHA2-256= %s\n", s256)) }, ErrIntegrity},
		{"повтор ключа", func(f *platform.Fake) {
			f.Serve(dgstURL, fmt.Appendf(nil, "SHA2-256= %s\nSHA2-512= %s\nSHA2-512= %s\n", s256, s512, s512))
		}, ErrIntegrity},
		{"короткая сумма", func(f *platform.Fake) {
			f.Serve(dgstURL, fmt.Appendf(nil, "SHA2-256= %s\nSHA2-512= %s\n", s256[:10], s512))
		}, ErrIntegrity},
		{"хэш API не совпал с .dgst", func(f *platform.Fake) {
			f.Serve(latestURL, releaseJSON(tag, false, "sha256:"+strings.Repeat("0", 64)))
		}, ErrIntegrity},
		{"API без хэша", func(f *platform.Fake) { f.Serve(latestURL, releaseJSON(tag, false, "")) }, ErrIntegrity},
		{"перенаправление на чужой узел", func(f *platform.Fake) { f.Redirect(zipURL, "https://evil.test/x.zip") }, platform.ErrURL},
		{"архив больше предела", func(f *platform.Fake) {
			big := make([]byte, maxArchive+1)
			f.Serve(dgstURL, dgstFor(big))
			b256, _ := sums(big)
			f.Serve(latestURL, releaseJSON(tag, false, "sha256:"+b256))
			f.Serve(assetURL, big)
		}, platform.ErrTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, g := env(t)
			c.setup(f)
			_, err := g.Fetch(ctx(t), latest(t, g), ArchAMD64)
			if !errors.Is(err, c.want) {
				t.Fatalf("ошибка %v, нужна %v", err, c.want)
			}
			if _, err := os.Stat(f.Path(cached)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("отвергнутый архив в кэше: %v", err)
			}
		})
	}
}

// Архив размера Xray-linux-64.zip v26.11.9 (docs/compatibility.md §2) скачивается и читается из
// кэша: предел с запасом выше реального размера.
func TestFetchRealSizeArchive(t *testing.T) {
	const v26_11_9 = 16754078
	f, g := env(t)
	big := make([]byte, v26_11_9)
	copy(big, archive)
	b256, _ := sums(big)
	f.Serve(latestURL, releaseJSON(tag, false, "sha256:"+b256))
	f.Serve(dgstURL, dgstFor(big))
	f.Serve(assetURL, big)
	r := latest(t, g)
	for _, step := range []string{"загрузка", "кэш"} {
		if a, err := g.Fetch(ctx(t), r, ArchAMD64); err != nil || len(a.Data) != v26_11_9 {
			t.Fatalf("%s: %d байт, %v", step, len(a.Data), err)
		}
		f.Serve(assetURL, nil) // второй проход — только из кэша
	}
	if maxArchive < 3*v26_11_9 {
		t.Errorf("предел %d байт: запас меньше трёхкратного к реальному размеру", maxArchive)
	}
}

func TestFetchRejectsInput(t *testing.T) {
	_, g := env(t)
	r := latest(t, g)
	if _, err := g.Fetch(ctx(t), r, "arm64"); err == nil {
		t.Error("неподдерживаемая архитектура принята")
	}
	bad := r
	bad.Tag = "v26.11.9/../../evil"
	if _, err := g.Fetch(ctx(t), bad, ArchAMD64); err == nil {
		t.Error("тег с путём принят")
	}
}

func TestLatestRejects(t *testing.T) {
	cases := map[string][]byte{
		"предварительный": releaseJSON(tag, true, ""),
		"черновик":        []byte(`{"tag_name":"v26.11.9","draft":true}`),
		"тег не vX.Y.Z":   releaseJSON("v26.11.9-rc1", false, ""),
		"тег с путём":     releaseJSON("../v1.2.3", false, ""),
		"не JSON":         []byte("<html>"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			f, g := env(t)
			f.Serve(latestURL, body)
			if r, err := g.Latest(ctx(t)); err == nil {
				t.Errorf("принят релиз %+v", r)
			}
		})
	}
}

// Токен API (ADR-0031) уходит только в запрос к API, не в загрузку файлов релиза.
func TestTokenOnlyForAPI(t *testing.T) {
	f, g := env(t)
	g = NewGitHub(f, "xm_fake_github_token_000000000000000000001")
	r := latest(t, g)
	if _, err := g.Fetch(ctx(t), r, ArchAMD64); err != nil {
		t.Fatal(err)
	}
	var gets int
	for _, c := range f.Calls() {
		if c.Op != "get" {
			continue
		}
		gets++
		if want := c.Path == latestURL; c.Auth != want {
			t.Errorf("%s: токен %v, нужен %v", c.Path, c.Auth, want)
		}
	}
	if gets != 3 {
		t.Errorf("загрузок %d, нужно 3: API, .dgst, архив", gets)
	}
}

// Токен не по правилу отвергается до сети, и его значения нет в ошибке.
func TestTokenRejected(t *testing.T) {
	long, short := strings.Repeat("a", 256), strings.Repeat("a", 39)
	for _, token := range []string{"xm_fake_github token_00000000000000000001", "xm_fake_github_token_000000000000\r\nX-Evil: 1",
		"xm-fake-github-token-000000000000000000001", "тoken_fake_github_token_00000000000000001", short, long} {
		f, _ := env(t)
		_, err := NewGitHub(f, token).Latest(ctx(t))
		if err == nil {
			t.Errorf("%q принят", token)
			continue
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("значение токена в ошибке: %v", err)
		}
		if len(f.Calls()) != 0 {
			t.Errorf("%q: обращение к сети до проверки: %+v", token, f.Calls())
		}
	}
}
