package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/grokki91/xray_core/internal/platform"
)

// Релизы самого xm (ADR-0045): тот же репозиторий, файлы и проверка, что у install.sh.
const (
	selfLatestURL   = "https://" + hostAPI + "/repos/grokki91/xray_core/releases/latest"
	selfDownloadURL = "https://" + hostGitHub + "/grokki91/xray_core/releases/download/"
	selfAsset       = "xm-linux-amd64"
	selfSums        = "SHA256SUMS"
	maxSums         = 64 << 10

	// BinPath — действующий xm; PrevPath — прежний после `xm update --self`
	// (docs/architecture/data-model.md §1).
	BinPath  = "/usr/local/bin/xm"
	PrevPath = "/usr/local/bin/xm.previous"
	libDir   = "/usr/local/lib/xm"
)

// ErrNoPreviousXM — прежнего бинарника xm нет: возвращать нечего.
var ErrNoPreviousXM = errors.New("прежнего бинарника xm нет")

var reSelfVersion = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,64}$`)

// ValidSelfVersion — допустимая строка версии xm в аргументах и состоянии: сборка без тега
// («dev») тоже допустима.
func ValidSelfVersion(s string) bool { return reSelfVersion.MatchString(s) }

// NewerSelf — релиз target новее сборки cur; сборка без версии N.N.N («dev») старше любого.
func NewerSelf(target, cur string) bool {
	if !platform.ValidVersion(cur) {
		return true
	}
	return Compare(target, cur) > 0
}

// Self — релизы и бинарник самого xm.
type Self struct {
	p     platform.Platform
	token string
}

// NewSelf — источник релизов xm; token — как у NewGitHub (ADR-0031).
func NewSelf(p platform.Platform, token string) *Self { return &Self{p: p, token: token} }

// Latest возвращает последний стабильный релиз xm.
func (s *Self) Latest(ctx context.Context) (Release, error) {
	return fetchRelease(ctx, s.p, s.token, selfLatestURL, "последний релиз xm")
}

// Stage скачивает бинарник релиза и SHA256SUMS того же релиза, сверяет SHA-256 и кладёт файл в
// platform.XMNextPath (0755, root). Несовпадение — ErrIntegrity, файл не пишется.
func (s *Self) Stage(ctx context.Context, r Release) error {
	if !validTag(r.Tag) {
		return fmt.Errorf("релиз xm: тег %q не вида vX.Y.Z", r.Tag)
	}
	base := selfDownloadURL + r.Tag + "/"
	sums, err := s.p.Net().Get(ctx, platform.Request{URL: base + selfSums, Hosts: downloadHosts, Max: maxSums})
	if err != nil {
		return fmt.Errorf("xm %s %s: %w", r.Tag, selfSums, err)
	}
	want, err := sumFor(sums, selfAsset)
	if err != nil {
		return fmt.Errorf("xm %s: %w", r.Tag, err)
	}
	data, err := s.p.Net().Get(ctx, platform.Request{URL: base + selfAsset, Hosts: downloadHosts, Max: maxArchive})
	if err != nil {
		return fmt.Errorf("xm %s %s: %w", r.Tag, selfAsset, err)
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("xm %s: SHA-256 %s не совпадает с %s: %w", r.Tag, selfAsset, selfSums, ErrIntegrity)
	}
	if err := s.p.FS().Mkdir(libDir, 0o755, platform.Root()); err != nil {
		return err
	}
	return s.p.FS().WriteFile(platform.XMNextPath, data, 0o755, platform.Root())
}

// sumFor — сумма файла из SHA256SUMS: строка «<64 hex> <имя>» или «<64 hex> *<имя>», как читает install.sh.
func sumFor(sums []byte, name string) (string, error) {
	for line := range strings.SplitSeq(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && (f[1] == name || f[1] == "*"+name) {
			if len(f[0]) == 64 && hexRe.MatchString(f[0]) {
				return f[0], nil
			}
		}
	}
	return "", fmt.Errorf("в %s нет суммы %s: %w", selfSums, name, ErrIntegrity)
}

// Probe — версия выложенного бинарника по `xm-next version --json`.
func (s *Self) Probe(ctx context.Context) (string, error) {
	out, err := s.run(ctx, "version", "--json")
	if err != nil {
		return "", err
	}
	if out.ExitCode != 0 {
		return "", fmt.Errorf("новый xm: version завершился с кодом %d", out.ExitCode)
	}
	var doc struct {
		Data struct {
			XM string `json:"xm"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Stdout, &doc); err != nil || !ValidSelfVersion(doc.Data.XM) {
		return "", errors.New("новый xm: версия не разобрана")
	}
	return doc.Data.XM, nil
}

// Apply запускает `xm-next self-apply --previous <prev> --json` и возвращает его документ и код
// выхода: транзакцию ведёт новый xm (ADR-0045).
func (s *Self) Apply(ctx context.Context, prev string) ([]byte, int, error) {
	if !ValidSelfVersion(prev) {
		return nil, 0, fmt.Errorf("версия xm %q недопустима", prev)
	}
	out, err := s.run(ctx, "self-apply", "--previous", prev, "--json")
	if err != nil {
		return nil, 0, err
	}
	return out.Stdout, out.ExitCode, nil
}

func (s *Self) run(ctx context.Context, args ...string) (platform.Result, error) {
	return s.p.Exec(ctx, platform.Command{Program: platform.XMNext, Args: args})
}

// Install ставит выложенный бинарник на место действующего, действующий — в PrevPath. Каждая
// запись атомарна; запущенный процесс файл не держит.
func (s *Self) Install() error {
	next, err := s.p.FS().ReadFile(platform.XMNextPath)
	if err != nil {
		return fmt.Errorf("новый xm: %w", err)
	}
	cur, err := s.p.FS().ReadFile(BinPath)
	if err != nil {
		return fmt.Errorf("действующий xm: %w", err)
	}
	if err := s.p.FS().WriteFile(PrevPath, cur, 0o755, platform.Root()); err != nil {
		return err
	}
	return s.p.FS().WriteFile(BinPath, next, 0o755, platform.Root())
}

// Restore возвращает прежний бинарник на место действующего; повтор безопасен.
func (s *Self) Restore() error {
	prev, err := s.p.FS().ReadFile(PrevPath)
	if errors.Is(err, platform.ErrNotFound) {
		return ErrNoPreviousXM
	}
	if err != nil {
		return err
	}
	cur, err := s.p.FS().ReadFile(BinPath)
	if err == nil && bytes.Equal(cur, prev) {
		return nil
	}
	return s.p.FS().WriteFile(BinPath, prev, 0o755, platform.Root())
}

// Discard убирает выложенный бинарник; его нет — не ошибка.
func (s *Self) Discard() error {
	if err := s.p.FS().Remove(platform.XMNextPath); err != nil && !errors.Is(err, platform.ErrNotFound) {
		return err
	}
	return nil
}
