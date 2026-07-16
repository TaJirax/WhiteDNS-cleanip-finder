package dnsscan

import (
	"context"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// dialUTLS establishes a TLS connection with a browser-like ClientHello. The
// scanner intentionally skips certificate verification because it probes raw
// resolver IPs, where the certificate name generally cannot match the target.
func dialUTLS(ctx context.Context, network, addr string, dialer *net.Dialer, alpn []string) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	uconn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // raw-IP resolver scan; see function comment
	}, utls.HelloChrome_Auto)

	// Chrome advertises h2 first. DoT must not negotiate an HTTP protocol, and
	// net/http's custom TLS hook below speaks HTTP/1.1, so tailor only ALPN while
	// retaining the rest of the browser ClientHello fingerprint.
	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, err
	}
	extensions := uconn.Extensions[:0]
	for _, extension := range uconn.Extensions {
		if ext, ok := extension.(*utls.ALPNExtension); ok {
			if len(alpn) == 0 {
				continue
			}
			ext.AlpnProtocols = append([]string(nil), alpn...)
		}
		extensions = append(extensions, extension)
	}
	uconn.Extensions = extensions

	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uconn, nil
}

func newDoHClient(timeout time.Duration, dialer *net.Dialer) *http.Client {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialUTLS(ctx, network, addr, dialer, []string{"http/1.1"})
		},
		ForceAttemptHTTP2: false,
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
