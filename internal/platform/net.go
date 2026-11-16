package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
)

// maxRedirects — предел цепочки перенаправлений: релизы GitHub дают одно.
const maxRedirects = 5

// checkURL — общие для обеих реализаций правила адреса: https, узел из закрытого списка, без
// учётных данных в адресе.
func checkURL(raw string, hosts []string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: адрес не разобран", ErrURL)
	}
	if u.Scheme != "https" || u.User != nil || u.Host == "" || !slices.Contains(hosts, u.Host) {
		return fmt.Errorf("%w: %s://%s", ErrURL, u.Scheme, u.Host)
	}
	return nil
}

// checkGet — общие предусловия загрузки.
func checkGet(ctx context.Context, r Request) error {
	if _, ok := ctx.Deadline(); !ok {
		return ErrDeadline
	}
	if r.Max <= 0 {
		return errors.New("загрузка: предел тела не задан")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return checkURL(r.URL, r.Hosts)
}

// readLimited читает тело не больше max байт; больше — ошибка, а не обрезка.
func readLimited(body io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: больше %d байт", ErrTooLarge, max)
	}
	return data, nil
}

type realNet struct{ transport http.RoundTripper }

func (n realNet) Get(ctx context.Context, r Request) ([]byte, error) {
	if err := checkGet(ctx, r); err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: n.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects { // via — уже выполненные запросы: N-е перенаправление при len(via) == N
				return fmt.Errorf("больше %d перенаправлений", maxRedirects)
			}
			return checkURL(req.URL.String(), r.Hosts)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("загрузка: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		// url.Error несёт полный адрес с параметрами — у файлов релиза в них подписанный
		// одноразовый токен узла раздачи; наружу — только узел.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("загрузка %s: %w", req.URL.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("загрузка %s: ответ %d", resp.Request.URL.Host, resp.StatusCode)
	}
	data, err := readLimited(resp.Body, r.Max)
	if err != nil {
		return nil, fmt.Errorf("загрузка %s: %w", resp.Request.URL.Host, err)
	}
	return data, nil
}

// fakeRoute — ответ поддельной сети на адрес: тело или перенаправление.
type fakeRoute struct {
	body     []byte
	location string
}

type fakeNet struct{ f *Fake }

func (n fakeNet) Get(ctx context.Context, r Request) ([]byte, error) {
	if err := checkGet(ctx, r); err != nil {
		return nil, err
	}
	n.f.mu.Lock()
	n.f.calls = append(n.f.calls, Call{Op: "get", Path: r.URL})
	n.f.mu.Unlock()
	cur := r.URL
	for hop := 0; ; hop++ {
		n.f.mu.Lock()
		route, ok := n.f.routes[cur]
		n.f.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("загрузка %s: ответ 404", cur)
		}
		if route.location == "" {
			data, err := readLimited(bytes.NewReader(route.body), r.Max)
			if err != nil {
				return nil, fmt.Errorf("загрузка %s: %w", cur, err)
			}
			return data, nil
		}
		if hop >= maxRedirects {
			return nil, fmt.Errorf("загрузка %s: больше %d перенаправлений", r.URL, maxRedirects)
		}
		if err := checkURL(route.location, r.Hosts); err != nil {
			return nil, fmt.Errorf("загрузка %s: %w", cur, err)
		}
		cur = route.location
	}
}
