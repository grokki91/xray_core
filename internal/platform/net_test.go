package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// netCase — реализация сети и адрес её «своего» узла, на котором заданы ответы:
// /ok — тело, /hop — перенаправление на /ok, /out — перенаправление на чужой узел,
// /loop — перенаправление на себя, /chainN — цепочка из N перенаправлений до /ok.
type netCase struct {
	name string
	net  Net
	base string // https://узел
	host string
}

const foreign = "https://foreign.test/ok"

var netBody = []byte("архив")

func netCases(t *testing.T) []netCase {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/chain%d", &n); err == nil {
			to := "/ok"
			if n > 1 {
				to = fmt.Sprintf("/chain%d", n-1)
			}
			http.Redirect(w, r, to, http.StatusFound)
			return
		}
		switch r.URL.Path {
		case "/ok":
			w.Write(netBody)
		case "/hop":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/out":
			http.Redirect(w, r, foreign, http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	real := newReal(nil, srv.Client().Transport)

	fake := newFake(t.TempDir(), time.Time{}, nil)
	const fb = "https://own.test"
	fake.Serve(fb+"/ok", netBody)
	fake.Redirect(fb+"/hop", fb+"/ok")
	fake.Redirect(fb+"/out", foreign)
	fake.Redirect(fb+"/loop", fb+"/loop")
	fake.Serve(foreign, []byte("чужое"))
	for n := 1; n <= maxRedirects+1; n++ {
		to := fb + "/ok"
		if n > 1 {
			to = fmt.Sprintf("%s/chain%d", fb, n-1)
		}
		fake.Redirect(fmt.Sprintf("%s/chain%d", fb, n), to)
	}

	return []netCase{
		{"real", real.Net(), srv.URL, strings.TrimPrefix(srv.URL, "https://")},
		{"fake", fake.Net(), fb, "own.test"},
	}
}

// Обе реализации одинаково применяют правила адреса, перенаправлений и предела.
func TestNetAgree(t *testing.T) {
	for _, c := range netCases(t) {
		t.Run(c.name, func(t *testing.T) {
			ctx := deadline(t, 5*time.Second)
			req := func(path string) Request {
				return Request{URL: c.base + path, Hosts: []string{c.host}, Max: 1 << 10}
			}
			for _, path := range []string{"/ok", "/hop", fmt.Sprintf("/chain%d", maxRedirects)} {
				got, err := c.net.Get(ctx, req(path))
				if err != nil || !bytes.Equal(got, netBody) {
					t.Errorf("%s: %q, %v", path, got, err)
				}
			}
			if _, err := c.net.Get(ctx, req("/out")); !errors.Is(err, ErrURL) {
				t.Errorf("перенаправление на чужой узел: %v, нужен ErrURL", err)
			}
			if _, err := c.net.Get(ctx, req(fmt.Sprintf("/chain%d", maxRedirects+1))); err == nil {
				t.Errorf("цепочка из %d перенаправлений принята", maxRedirects+1)
			}
			if _, err := c.net.Get(ctx, req("/loop")); err == nil {
				t.Error("бесконечное перенаправление принято")
			}
			if _, err := c.net.Get(ctx, req("/missing")); err == nil {
				t.Error("ответ 404 принят")
			}
			small := req("/ok")
			small.Max = int64(len(netBody)) - 1
			if _, err := c.net.Get(ctx, small); !errors.Is(err, ErrTooLarge) {
				t.Error("тело сверх предела принято")
			}
			if _, err := c.net.Get(context.Background(), req("/ok")); !errors.Is(err, ErrDeadline) {
				t.Errorf("без срока: %v, нужен ErrDeadline", err)
			}
			bad := []string{
				"http://" + c.host + "/ok",
				foreign,
				"https://user@" + c.host + "/ok",
				"https://" + c.host + ":1/ok",
				"//" + c.host + "/ok",
			}
			for _, u := range bad {
				r := req("")
				r.URL = u
				if _, err := c.net.Get(ctx, r); !errors.Is(err, ErrURL) {
					t.Errorf("%s: %v, нужен ErrURL", u, err)
				}
			}
		})
	}
}
