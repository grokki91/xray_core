package platform

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"
)

// TLSRequest — одно TLS-соединение к Host:Port. Host — имя узла (буквы, цифры, «-», «.»).
// Allow — правило потребителя, к какому адресу имени можно подключаться (обязательно): отбор
// идёт до соединения, чтобы не стучаться на частные и петлевые адреса.
type TLSRequest struct {
	Host  string
	Port  int
	Allow func(netip.Addr) bool
}

// ErrNotAllowed — у имени нет адреса, допустимого по TLSRequest.Allow; соединения не было.
var ErrNotAllowed = errors.New("нет допустимого адреса")

// TLSInfo — что показало рукопожатие. CertErr — ошибка проверки цепочки на имя Host; nil —
// сертификат действителен. Addr — адрес фактического соединения. Handshake — от начала TCP-
// соединения до конца TLS-рукопожатия, без разрешения имени. Status и Location — ответ на
// HEAD / по тому же соединению (ADR-0040); HeadErr — ответа нет (Status 0), и почему.
type TLSInfo struct {
	Version   uint16
	ALPN      string
	Curve     tls.CurveID
	Addr      netip.Addr
	CertErr   error
	Handshake time.Duration
	Status    int
	Location  string
	HeadErr   error
}

const (
	// headTimeout — свой срок запроса HEAD / внутри общего срока проверки.
	headTimeout = 5 * time.Second
	// maxHeadHeaders — предел заголовков ответа; тело не читается.
	maxHeadHeaders = 16 << 10
)

// hostName — закрытое правило имени узла; IP-литерал тоже проходит (тесту нужен 127.0.0.1),
// отбор имён — у потребителя.
var hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

func checkTLS(ctx context.Context, r TLSRequest) error {
	if _, ok := ctx.Deadline(); !ok {
		return ErrDeadline
	}
	if len(r.Host) > 253 || !hostName.MatchString(r.Host) || r.Port < 1 || r.Port > 65535 || r.Allow == nil {
		return fmt.Errorf("%w: узел %q порт %d", ErrURL, r.Host, r.Port)
	}
	return ctx.Err()
}

func (n realNet) TLSProbe(ctx context.Context, r TLSRequest) (TLSInfo, error) {
	if err := checkTLS(ctx, r); err != nil {
		return TLSInfo{}, err
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", r.Host)
	if err != nil {
		return TLSInfo{}, fmt.Errorf("адрес %s: %w", r.Host, err)
	}
	if len(addrs) == 0 {
		return TLSInfo{}, fmt.Errorf("адрес %s: нет адресов", r.Host)
	}
	// Одно соединение на первый допустимый адрес: Dialer с именем перебирал бы адреса — проверка
	// чужого узла не должна выглядеть сканированием (правило network.md).
	addr, err := pickAddr(r, addrs)
	if err != nil {
		return TLSInfo{}, err
	}
	start := time.Now()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(r.Port)))
	if err != nil {
		return TLSInfo{}, fmt.Errorf("соединение %s: %w", r.Host, err)
	}
	defer raw.Close()
	dl, _ := ctx.Deadline()
	if err := raw.SetDeadline(dl); err != nil {
		return TLSInfo{}, fmt.Errorf("срок соединения %s: %w", r.Host, err)
	}
	// Цепочка проверяется после рукопожатия: при негодном сертификате остальные критерии всё
	// равно нужны в отчёте. После рукопожатия — только HEAD /.
	c := tls.Client(raw, &tls.Config{
		ServerName:         r.Host,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2"},
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		InsecureSkipVerify: true,
	})
	if err := c.HandshakeContext(ctx); err != nil {
		return TLSInfo{}, fmt.Errorf("рукопожатие %s: %w", r.Host, err)
	}
	took := time.Since(start)
	st := c.ConnectionState()
	info := TLSInfo{Version: st.Version, ALPN: st.NegotiatedProtocol, Curve: st.CurveID, Addr: addr, Handshake: took}
	info.Status, info.Location, info.HeadErr = head(ctx, c, r.Host)
	if len(st.PeerCertificates) == 0 {
		info.CertErr = fmt.Errorf("сервер не прислал сертификат")
		return info, nil
	}
	inter := x509.NewCertPool()
	for _, cert := range st.PeerCertificates[1:] {
		inter.AddCert(cert)
	}
	_, info.CertErr = st.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: r.Host, Roots: n.roots, Intermediates: inter})
	return info, nil
}

// head отправляет HEAD / с Host = host по уже установленному соединению c через HTTP/2
// стандартной библиотеки: транспорт получает c как единственное соединение, второе не
// открывается; перенаправления не выполняются, тело не читается.
func head(ctx context.Context, c *tls.Conn, host string) (int, string, error) {
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		return 0, "", errors.New("ALPN не h2: запрос не отправлен")
	}
	var used atomic.Bool
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	tr := &http.Transport{
		Protocols:              protos,
		MaxResponseHeaderBytes: maxHeadHeaders,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if used.Swap(true) {
				return nil, errors.New("второе соединение не открывается")
			}
			return c, nil
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	hctx, cancel := context.WithTimeout(ctx, headTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(hctx, http.MethodHead, "https://"+host+"/", nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, "", fmt.Errorf("HEAD /: %w", err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location"), nil
}

// pickAddr — первый адрес, допустимый по r.Allow; нет такого — ErrNotAllowed.
func pickAddr(r TLSRequest, addrs []netip.Addr) (netip.Addr, error) {
	for _, a := range addrs {
		if a = a.Unmap(); r.Allow(a) {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: %s → %v", ErrNotAllowed, r.Host, addrs)
}

// fakeTLS — ответ подделки на TLSProbe.
type fakeTLS struct {
	info TLSInfo
	err  error
}

// SetTLS задаёт итог TLSProbe к host: имя разрешается в info.Addr; адрес не по Allow — ErrNotAllowed
// без соединения (вызов «dial» не записан); не заданный узел — ошибка соединения.
func (f *Fake) SetTLS(host string, info TLSInfo, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tls[host] = fakeTLS{info, err}
}

func (n fakeNet) TLSProbe(ctx context.Context, r TLSRequest) (TLSInfo, error) {
	if err := checkTLS(ctx, r); err != nil {
		return TLSInfo{}, err
	}
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	n.f.calls = append(n.f.calls, Call{Op: "tls", Path: r.Host})
	got, ok := n.f.tls[r.Host]
	if !ok {
		return TLSInfo{}, fmt.Errorf("соединение %s: нет ответа", r.Host)
	}
	if got.info.Addr.IsValid() {
		if _, err := pickAddr(r, []netip.Addr{got.info.Addr}); err != nil {
			return TLSInfo{}, err
		}
	}
	n.f.calls = append(n.f.calls, Call{Op: "dial", Path: r.Host})
	return got.info, got.err
}
