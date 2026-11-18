package export

import (
	"errors"
	"strings"
	"testing"

	"rsc.io/qr"
)

// decode читает вывод QR обратно в матрицу модулей без поля тишины: пара строк терминала —
// две строки модулей.
func decode(t *testing.T, art string) [][]bool {
	t.Helper()
	var rows [][]bool
	for _, line := range strings.Split(strings.TrimSuffix(art, "\n"), "\n") {
		line = strings.TrimSuffix(strings.TrimPrefix(line, qrOn), qrOff)
		var top, bottom []bool
		for _, r := range line {
			switch r {
			case ' ':
				top, bottom = append(top, false), append(bottom, false)
			case '▀':
				top, bottom = append(top, true), append(bottom, false)
			case '▄':
				top, bottom = append(top, false), append(bottom, true)
			case '█':
				top, bottom = append(top, true), append(bottom, true)
			default:
				t.Fatalf("неожиданный знак %q", r)
			}
		}
		rows = append(rows, top, bottom)
	}
	// снять поле тишины
	rows = rows[quietZone : len(rows)-quietZone]
	for i, r := range rows {
		rows[i] = r[quietZone : len(r)-quietZone]
	}
	return rows
}

func sameMatrix(t *testing.T, got [][]bool, text string) bool {
	t.Helper()
	c, err := qr.Encode(text, qrLevel)
	if err != nil {
		t.Fatal(err)
	}
	n := c.Size
	// нечётное число строк модулей даёт пустую нижнюю строку-добавку
	if len(got) != n && len(got) != n+1 {
		return false
	}
	for y := 0; y < n; y++ {
		if len(got[y]) != n {
			return false
		}
		for x := 0; x < n; x++ {
			if got[y][x] != c.Black(x, y) {
				return false
			}
		}
	}
	return true
}

// QR кодирует ровно ту же строку, что показана ссылкой: вывод читается обратно в матрицу, и она
// совпадает с матрицей ссылки и не совпадает с матрицей любой другой строки.
func TestQRMatchesLink(t *testing.T) {
	for _, host := range []string{"192.0.2.10", "2001:db8::10", "vpn.example.com"} {
		p, e := testProfile(), testEndpoint(host)
		link, err := (URI{}).Export(p, e)
		if err != nil {
			t.Fatal(err)
		}
		a, err := (QR{}).Export(p, e)
		if err != nil {
			t.Fatal(err)
		}
		if a.Format != "qr" {
			t.Fatalf("формат %q", a.Format)
		}
		got := decode(t, a.Text)
		if !sameMatrix(t, got, link.Text) {
			t.Fatalf("%s: QR не кодирует ссылку", host)
		}
		if sameMatrix(t, got, link.Text+"x") {
			t.Fatalf("%s: матрица не различает строки", host)
		}
	}
}

func TestQRFormat(t *testing.T) {
	if (QR{}).Format() != "qr" {
		t.Fatal("Format() не qr")
	}
}

// Отказ ссылки — отказ QR: ни рисунка, ни значений ввода в ошибке.
func TestQRRejects(t *testing.T) {
	p, e := testProfile(), testEndpoint("192.0.2.10")
	e.Preset = "reality-vision"
	a, err := (QR{}).Export(p, e)
	if !errors.Is(err, ErrPreset) {
		t.Fatalf("ошибка %v", err)
	}
	if a != (Artifact{}) {
		t.Fatal("при отказе артефакт пуст")
	}
	p, e = testProfile(), testEndpoint("192.0.2.10")
	e.PublicKey = testPBK + "B"
	if _, err := (QR{}).Export(p, e); !errors.Is(err, ErrInput) || strings.Contains(err.Error(), testPBK) {
		t.Fatalf("ошибка %v", err)
	}
}

// Цвета заданы явно: чёрные модули на белом независимо от темы терминала.
func TestQRColors(t *testing.T) {
	a, err := (QR{}).Export(testProfile(), testEndpoint("192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(strings.TrimSuffix(a.Text, "\n"), "\n") {
		if !strings.HasPrefix(line, qrOn) || !strings.HasSuffix(line, qrOff) {
			t.Fatalf("строка %d без явных цветов", i)
		}
	}
}
