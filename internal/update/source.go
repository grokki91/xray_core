// Пакет update — источник релизов Xray-core и (фаза 5) план обновления. Порядок проверки —
// docs/operations/updates.md §1, §3; решение — ADR-0009.
package update

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/grokki91/xray_core/internal/platform"
)

// Закрытый список узлов (docs/dev/dependencies.md §5): API, страница релизов и узел раздачи
// файлов, на который она перенаправляет.
const (
	hostAPI    = "api.github.com"
	hostGitHub = "github.com"
	hostAssets = "release-assets.githubusercontent.com"

	latestURL   = "https://" + hostAPI + "/repos/XTLS/Xray-core/releases/latest"
	downloadURL = "https://" + hostGitHub + "/XTLS/Xray-core/releases/download/"
)

var (
	apiHosts      = []string{hostAPI}
	downloadHosts = []string{hostGitHub, hostAssets}
)

// Пределы загрузки. Архив читается из кэша через platform.FS, поэтому его предел — предел
// ReadFile.
const (
	maxRelease = 4 << 20
	maxDgst    = 64 << 10
	maxArchive = platform.MaxFileSize
)

// Каталоги кэша — docs/architecture/data-model.md §1.
const (
	dataDir  = "/var/lib/xm"
	cacheDir = dataDir + "/cache"
)

// Arch — архитектура машины. Поддерживается только amd64 (docs/compatibility.md §1).
type Arch string

const ArchAMD64 Arch = "amd64"

// assetName — имя архива релиза для архитектуры.
func assetName(a Arch) (string, error) {
	if a != ArchAMD64 {
		return "", fmt.Errorf("архитектура %q не поддерживается", a)
	}
	return "Xray-linux-64.zip", nil
}

// Release — стабильный релиз: тег и хэши SHA-256 файлов из API GitHub (имя → hex).
type Release struct {
	Tag    string
	sha256 map[string]string
}

// Version — версия без «v», как её называет `xray version`.
func (r Release) Version() string { return strings.TrimPrefix(r.Tag, "v") }

// Digests — суммы архива из `.dgst`, сверенные с архивом.
type Digests struct {
	SHA256, SHA512 string
}

// Archive — проверенный архив релиза.
type Archive struct {
	Data    []byte
	Digests Digests
}

// ErrIntegrity — суммы не совпали: архив не используется.
var ErrIntegrity = errors.New("целостность архива не подтверждена")

// GitHub — единственная реализация источника: релизы XTLS/Xray-core.
type GitHub struct {
	p platform.Platform
}

func NewGitHub(p platform.Platform) *GitHub { return &GitHub{p: p} }

var (
	tagRe = regexp.MustCompile(`^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`)
	hexRe = regexp.MustCompile(`^[0-9a-f]+$`)
)

// Latest возвращает последний стабильный релиз.
func (g *GitHub) Latest(ctx context.Context) (Release, error) {
	body, err := g.p.Net().Get(ctx, platform.Request{URL: latestURL, Hosts: apiHosts, Max: maxRelease})
	if err != nil {
		return Release{}, fmt.Errorf("последний релиз: %w", err)
	}
	var resp struct {
		Tag        string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
		Draft      bool   `json:"draft"`
		Assets     []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return Release{}, fmt.Errorf("последний релиз: ответ API не разобран: %w", err)
	}
	if !tagRe.MatchString(resp.Tag) {
		return Release{}, fmt.Errorf("последний релиз: тег %q не вида vX.Y.Z", resp.Tag)
	}
	if resp.Prerelease || resp.Draft {
		return Release{}, fmt.Errorf("последний релиз %s: не стабильный", resp.Tag)
	}
	r := Release{Tag: resp.Tag, sha256: map[string]string{}}
	for _, a := range resp.Assets {
		if sum, ok := strings.CutPrefix(a.Digest, "sha256:"); ok {
			r.sha256[a.Name] = sum
		}
	}
	return r, nil
}

// Fetch возвращает архив релиза для архитектуры, сверенный по SHA2-256 и SHA2-512 из `.dgst`
// и по SHA-256 из API. `.dgst` скачивается каждый раз; архив берётся из кэша, если проходит
// ту же сверку, иначе скачивается и кладётся в кэш.
func (g *GitHub) Fetch(ctx context.Context, r Release, a Arch) (Archive, error) {
	if !tagRe.MatchString(r.Tag) {
		return Archive{}, fmt.Errorf("релиз: тег %q не вида vX.Y.Z", r.Tag)
	}
	name, err := assetName(a)
	if err != nil {
		return Archive{}, err
	}
	apiSum, ok := r.sha256[name]
	if !ok {
		return Archive{}, fmt.Errorf("%s %s: API не отдал хэш файла: %w", r.Tag, name, ErrIntegrity)
	}
	url := downloadURL + r.Tag + "/" + name
	dgst, err := g.p.Net().Get(ctx, platform.Request{URL: url + ".dgst", Hosts: downloadHosts, Max: maxDgst})
	if err != nil {
		return Archive{}, fmt.Errorf("%s %s.dgst: %w", r.Tag, name, err)
	}
	d, err := parseDgst(dgst)
	if err != nil {
		return Archive{}, fmt.Errorf("%s %s.dgst: %w", r.Tag, name, err)
	}
	if d.SHA256 != apiSum {
		return Archive{}, fmt.Errorf("%s %s: SHA2-256 в .dgst и в API различаются: %w", r.Tag, name, ErrIntegrity)
	}

	cached := cacheDir + "/" + r.Tag + "-" + name
	data, err := g.p.FS().ReadFile(cached)
	if err == nil && verify(data, d) == nil {
		return Archive{Data: data, Digests: d}, nil
	}
	// Нет в кэше, не читается или не прошёл сверку: тот же путь, что при первой загрузке.
	// Ссылку или каталог на месте файла WriteFile ниже отвергнет.
	data, err = g.p.Net().Get(ctx, platform.Request{URL: url, Hosts: downloadHosts, Max: maxArchive})
	if err != nil {
		return Archive{}, fmt.Errorf("%s %s: %w", r.Tag, name, err)
	}
	if err := verify(data, d); err != nil {
		return Archive{}, fmt.Errorf("%s %s: %w", r.Tag, name, err)
	}
	if err := g.ensureCache(); err != nil {
		return Archive{}, err
	}
	if err := g.p.FS().WriteFile(cached, data, 0o600, platform.Root()); err != nil {
		return Archive{}, fmt.Errorf("кэш: %w", err)
	}
	return Archive{Data: data, Digests: d}, nil
}

// ensureCache создаёт каталоги кэша по манифесту (data-model.md §1): загрузка идёт до
// security.EnsureBaseline (overview.md §6); существующие с другими правами — ошибка.
func (g *GitHub) ensureCache() error {
	for _, dir := range []string{dataDir, cacheDir} {
		if err := g.p.FS().Mkdir(dir, 0o700, platform.Root()); err != nil {
			return fmt.Errorf("кэш: %w", err)
		}
	}
	return nil
}

// parseDgst берёт из `.dgst` строки SHA2-256= и SHA2-512=; MD5 и SHA1 не используются.
// Повтор ключа или значение не того вида — ошибка.
func parseDgst(b []byte) (Digests, error) {
	var d Digests
	for _, line := range strings.Split(string(b), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		var dst *string
		var size int
		switch strings.TrimSpace(key) {
		case "SHA2-256":
			dst, size = &d.SHA256, sha256.Size
		case "SHA2-512":
			dst, size = &d.SHA512, sha512.Size
		default:
			continue
		}
		val = strings.ToLower(strings.TrimSpace(val))
		if *dst != "" {
			return Digests{}, fmt.Errorf("ключ %s повторяется: %w", key, ErrIntegrity)
		}
		if len(val) != 2*size || !hexRe.MatchString(val) {
			return Digests{}, fmt.Errorf("значение %s не hex длины %d: %w", key, 2*size, ErrIntegrity)
		}
		*dst = val
	}
	if d.SHA256 == "" || d.SHA512 == "" {
		return Digests{}, fmt.Errorf("нет SHA2-256 или SHA2-512: %w", ErrIntegrity)
	}
	return d, nil
}

// verify сверяет SHA2-256 и SHA2-512 данных с ожидаемыми.
func verify(data []byte, d Digests) error {
	s256 := sha256.Sum256(data)
	s512 := sha512.Sum512(data)
	if hex.EncodeToString(s256[:]) != d.SHA256 || hex.EncodeToString(s512[:]) != d.SHA512 {
		return ErrIntegrity
	}
	return nil
}
