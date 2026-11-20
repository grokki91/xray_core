package platform

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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
	if r.Proxy != "" && (!filepath.IsAbs(r.Proxy) || filepath.Clean(r.Proxy) != r.Proxy) {
		return fmt.Errorf("%w: сокет прокси %q", ErrPath, r.Proxy)
	}
	return checkURL(r.URL, r.Hosts)
}

// wantStatus — ожидаемый код ответа: по умолчанию 200.
func wantStatus(r Request) int {
	if r.Status == 0 {
		return http.StatusOK
	}
	return r.Status
}

// viaSocket — транспорт, который ведёт запросы через HTTP-прокси на сокете Unix: адрес прокси
// в URL условный, соединение всегда идёт на сокет; окружение (HTTPS_PROXY) не действует.
func viaSocket(base http.RoundTripper, socket string) (http.RoundTripper, error) {
	t, ok := base.(*http.Transport)
	if !ok {
		return nil, errors.New("загрузка через прокси: транспорт не http.Transport")
	}
	t = t.Clone()
	t.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: "xm-socket"})
	t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
	return t, nil
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
	transport := n.transport
	if r.Proxy != "" {
		t, err := viaSocket(transport, r.Proxy)
		if err != nil {
			return nil, err
		}
		defer t.(*http.Transport).CloseIdleConnections()
		transport = t
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects { // via — уже выполненные запросы: N-е перенаправление при len(via) == N
				return fmt.Errorf("больше %d перенаправлений", maxRedirects)
			}
			// Токен — только узлу первого запроса: net/http снимает заголовок лишь при смене узла.
			req.Header.Del("Authorization")
			return checkURL(req.URL.String(), r.Hosts)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("загрузка: %w", err)
	}
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
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
	if resp.StatusCode != wantStatus(r) {
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
	status   int // 0 — 200
}

// viaKey — ключ ответа подделки на запрос через прокси: он не пересекается с адресами https.
func viaKey(url string) string { return "via " + url }

type fakeNet struct{ f *Fake }

func (n fakeNet) Get(ctx context.Context, r Request) ([]byte, error) {
	if err := checkGet(ctx, r); err != nil {
		return nil, err
	}
	n.f.mu.Lock()
	n.f.calls = append(n.f.calls, Call{Op: "get", Path: r.URL, Auth: r.Token != "", Proxy: r.Proxy})
	n.f.mu.Unlock()
	cur := r.URL
	for hop := 0; ; hop++ {
		n.f.mu.Lock()
		route, ok := n.f.routes[cur]
		if via, found := n.f.routes[viaKey(cur)]; found && r.Proxy != "" {
			route, ok = via, true
		}
		n.f.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("загрузка %s: ответ 404", cur)
		}
		if route.location == "" {
			if got := cmp.Or(route.status, http.StatusOK); got != wantStatus(r) {
				return nil, fmt.Errorf("загрузка %s: ответ %d", cur, got)
			}
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

// procTCP — таблицы сокетов ядра; состояние 0A — LISTEN.
var procTCP = []string{"/proc/net/tcp", "/proc/net/tcp6"}

func checkPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("порт %d вне 1–65535", port)
	}
	return nil
}

func (realNet) Listening(ctx context.Context, port int) (bool, error) {
	if err := checkPort(port); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	for _, path := range procTCP {
		f, err := os.Open(path)
		// На хосте без IPv6 таблицы tcp6 нет: слушать на IPv6 там нечему.
		if errors.Is(err, fs.ErrNotExist) && path == procTCP[1] {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("таблица сокетов %s: %w", path, err)
		}
		on, err := scanListening(f, port)
		f.Close()
		if err != nil {
			return false, fmt.Errorf("таблица сокетов %s: %w", path, err)
		}
		if on {
			return true, nil
		}
	}
	return false, nil
}

// scanListening ищет в таблице /proc/net/tcp* сокет в состоянии LISTEN на порту port.
func scanListening(r io.Reader, port int) (bool, error) {
	sc := bufio.NewScanner(r)
	sc.Scan() // заголовок
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		_, hex, ok := strings.Cut(f[1], ":")
		if !ok {
			return false, errors.New("строка таблицы без порта")
		}
		p, err := strconv.ParseUint(hex, 16, 16)
		if err != nil {
			return false, errors.New("порт в таблице не число")
		}
		if int(p) == port {
			return true, nil
		}
	}
	return false, sc.Err()
}

func (n fakeNet) Listening(ctx context.Context, port int) (bool, error) {
	if err := checkPort(port); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	n.f.calls = append(n.f.calls, Call{Op: "listening", Path: strconv.Itoa(port)})
	return n.f.listening[port], nil
}
