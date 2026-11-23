package platform

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"time"
)

// TLSRequest — одно TLS-соединение к Host:Port. Host — имя узла (буквы, цифры, «-», «.»).
type TLSRequest struct {
	Host string
	Port int
}

// TLSInfo — что показало рукопожатие. CertErr — ошибка проверки цепочки на имя Host; nil —
// сертификат действителен. Addr — адрес фактического соединения. Handshake — TCP и TLS вместе.
type TLSInfo struct {
	Version   uint16
	ALPN      string
	Curve     tls.CurveID
	Addr      netip.Addr
	CertErr   error
	Handshake time.Duration
}

// hostName — закрытое правило имени узла; IP-литерал тоже проходит (тесту нужен 127.0.0.1),
// отбор имён — у потребителя.
var hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

func checkTLS(ctx context.Context, r TLSRequest) error {
	if _, ok := ctx.Deadline(); !ok {
		return ErrDeadline
	}
	if len(r.Host) > 253 || !hostName.MatchString(r.Host) || r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("%w: узел %q порт %d", ErrURL, r.Host, r.Port)
	}
	return ctx.Err()
}

func (n realNet) TLSProbe(ctx context.Context, r TLSRequest) (TLSInfo, error) {
	if err := checkTLS(ctx, r); err != nil {
		return TLSInfo{}, err
	}
	start := time.Now()
	// Одно соединение на первый адрес: Dialer с именем перебирал бы адреса — проверка чужого
	// узла не должна выглядеть сканированием (правило network.md).
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", r.Host)
	if err != nil || len(addrs) == 0 {
		return TLSInfo{}, fmt.Errorf("адрес %s: %w", r.Host, err)
	}
	addr := addrs[0].Unmap()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(r.Port)))
	if err != nil {
		return TLSInfo{}, fmt.Errorf("соединение %s: %w", r.Host, err)
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	// Цепочка проверяется после рукопожатия: при негодном сертификате остальные критерии всё
	// равно нужны в отчёте. Данные после рукопожатия не передаются.
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

// fakeTLS — ответ подделки на TLSProbe.
type fakeTLS struct {
	info TLSInfo
	err  error
}

// SetTLS задаёт итог TLSProbe к host; не заданный узел — ошибка соединения.
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
	return got.info, got.err
}
