package redact

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/grokki91/xray_core/internal/redact/redacttest"
)

// register заводит в редакторе значения установки — так, как это сделает загрузка состояния.
func register(r *Redactor, c redacttest.Canaries) {
	r.Register(UUID, c.UUID)
	r.Register(Key, c.PrivateKey)
	r.Register(Key, c.PublicKey)
	r.Register(ShortID, c.ShortID)
	r.Register(ServerIP, c.IPv4)
	r.Register(ServerIP, c.IPv6)
	r.Register(Domain, c.Domain)
	r.Register(Path, c.Path)
}

// Канареечный тест: сценарий с узнаваемыми значениями — журнал, ошибка, отчёт в JSON — после
// редактора не содержит ни одного из них.
func TestCanary(t *testing.T) {
	c := redacttest.New(t)
	r := New()
	register(r, c)

	log := "accepted tcp:" + c.IPv4 + ":443 [" + c.IPv6 + "]:443 email=" + c.UUID +
		" sni=" + c.Domain + " path=" + c.Path + " sid=" + c.ShortID
	errText := "render: reality key " + c.PrivateKey + " / " + c.PublicKey + " rejected for " + c.Domain
	report := map[string]any{
		"server": map[string]any{"ipv4": c.IPv4, "ipv6": c.IPv6, "sni": []string{c.Domain}},
		"link":   "vless://" + c.UUID + "@" + c.Domain + ":443?sid=" + c.ShortID + "&path=" + c.Path,
		c.UUID:   true, // значение в ключе объекта
	}
	tree, err := r.JSON(report)
	if err != nil {
		t.Fatal(err)
	}
	reportJSON, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	redacttest.AssertClean(t, c, map[string]string{
		"журнал": r.Text(log), "ошибка": r.Text(errText), "отчёт": string(reportJSON),
	})
}

// Одинаковое значение — одинаковая метка, разные — разные; метка вида «<вид:N>».
func TestStableLabels(t *testing.T) {
	r := New()
	a, b := "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"
	r.Register(UUID, a)
	r.Register(UUID, b)
	r.Register(UUID, a)
	got := r.Text(a + " " + b + " " + a)
	if got != "<uuid:1> <uuid:2> <uuid:1>" {
		t.Fatalf("метки: %q", got)
	}
}

// Значение, содержащее другое, заменяется целиком, а не по частям.
func TestLongestValueWins(t *testing.T) {
	r := New()
	r.Register(Domain, "example.com")
	r.Register(Domain, "cdn.example.com")
	if got := r.Text("cdn.example.com example.com"); got != "<domain:2> <domain:1>" {
		t.Fatalf("%q", got)
	}
}

// Шаблоны ловят незарегистрированное и не трогают открытое.
func TestPatterns(t *testing.T) {
	key := strings.Repeat("A", 43)
	cases := []struct{ in, want string }{
		{"from 203.0.113.5:51000", "from <ip:1>:51000"},
		{"from [2001:db8::5]:443", "from [<ip:1>]:443"},
		{"id 00000000-0000-4000-8000-0000000000AA", "id <uuid:1>"},
		{"pbk=" + key + "&x", "pbk=<key:1>&x"},
		{"link vless://00000000-0000-4000-8000-000000000001@example.com:443?x=1 end", "link <uri:1> end"},
		{"local 127.0.0.1 10.0.0.1 192.168.1.1 ::1 fe80::1", "local 127.0.0.1 10.0.0.1 192.168.1.1 ::1 fe80::1"},
		{"time 12:34:56 version 26.11.9 code preflight.foreign_install", "time 12:34:56 version 26.11.9 code preflight.foreign_install"},
		{"word " + strings.Repeat("A", 44), "word " + strings.Repeat("A", 44)},
	}
	for _, tc := range cases {
		if got := New().Text(tc.in); got != tc.want {
			t.Errorf("Text(%q) = %q, нужно %q", tc.in, got, tc.want)
		}
	}
}

func TestJSONKeepsShape(t *testing.T) {
	r := New()
	r.Register(Domain, "example.com")
	tree, err := r.JSON(struct {
		Port  int      `json:"port"`
		Names []string `json:"names"`
		Hold  bool     `json:"hold"`
	}{443, []string{"example.com"}, true})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tree)
	if string(b) != `{"hold":true,"names":["\u003cdomain:1\u003e"],"port":443}` {
		t.Fatalf("%s", b)
	}
}

// Фаззинг: зарегистрированное значение не переживает редактор ни в каком окружении. Значение —
// шестнадцатеричное: такие символы не встречаются в разметке меток, поэтому совпадение в выводе
// возможно только с непрошедшим замену текстом.
func FuzzText(f *testing.F) {
	f.Add("prefix ", " suffix", []byte{1, 2, 3, 4})
	f.Add("", "", []byte{0xde, 0xad, 0xbe, 0xef, 0})
	f.Add("<uuid:1>", "203.0.113.1", []byte{0xab, 0xab, 0xab, 0xab})
	f.Fuzz(func(t *testing.T, before, after string, raw []byte) {
		if len(raw) < 4 {
			return
		}
		secret := hex.EncodeToString(raw)
		r := New()
		r.Register(ShortID, secret)
		if out := r.Text(before + secret + after); strings.Contains(out, secret) {
			t.Fatalf("значение осталось: %q", out)
		}
	})
}
