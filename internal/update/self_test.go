package update

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/grokki91/xray_core/internal/platform"
)

var selfBin = []byte("\x7fELF фиктивный xm")

func selfEnv(t *testing.T, sums string) (*platform.Fake, *Self) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(root+"/usr/local/lib", 0o755); err != nil {
		t.Fatal(err)
	}
	f := platform.NewFake(root, time.Time{})
	base := selfDownloadURL + "v0.2.0/"
	f.Serve(base+selfSums, []byte(sums))
	f.Serve(base+selfAsset, selfBin)
	return f, NewSelf(f, "")
}

func selfSum() string {
	s := sha256.Sum256(selfBin)
	return hex.EncodeToString(s[:])
}

// Файл, чья сумма совпала с SHA256SUMS, выкладывается с правами 0755; в обеих записях, что
// читает install.sh.
func TestSelfStageVerifies(t *testing.T) {
	for _, line := range []string{"%s  xm-linux-amd64\n", "%s *xm-linux-amd64\n"} {
		f, s := selfEnv(t, "00  other\n"+fmt.Sprintf(line, selfSum()))
		if err := s.Stage(ctx(t), Release{Tag: "v0.2.0"}); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(f.Path(platform.XMNextPath))
		if err != nil || fi.Mode().Perm() != 0o755 {
			t.Fatalf("файл: %v %v", fi, err)
		}
	}
}

// Сумма не совпала или её нет — ErrIntegrity, файл не выложен.
func TestSelfStageRejects(t *testing.T) {
	for name, sums := range map[string]string{
		"чужая сумма": fmt.Sprintf("%064d  xm-linux-amd64\n", 0),
		"нет строки":  selfSum() + "  xm-linux-arm64\n",
		"не hex":      fmt.Sprintf("%064s  xm-linux-amd64\n", "z"),
	} {
		t.Run(name, func(t *testing.T) {
			f, s := selfEnv(t, sums)
			if err := s.Stage(ctx(t), Release{Tag: "v0.2.0"}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("ошибка %v", err)
			}
			if _, err := os.Stat(f.Path(platform.XMNextPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("файл выложен: %v", err)
			}
		})
	}
}

func TestNewerSelf(t *testing.T) {
	for _, c := range []struct {
		target, cur string
		want        bool
	}{{"0.2.0", "0.1.0", true}, {"0.1.0", "0.1.0", false}, {"0.1.0", "0.2.0", false}, {"0.1.0", "dev", true}} {
		if got := NewerSelf(c.target, c.cur); got != c.want {
			t.Errorf("%s над %s: %v", c.target, c.cur, got)
		}
	}
}
