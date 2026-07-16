package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TunnelDialer establishes one live stream through a DNSTT tunnel that runs
// over the given resolver for opts.Domain, authenticated with opts.PubKey. The
// returned net.Conn is a bidirectional byte stream to whatever the operator's
// DNSTT server forwards tunneled connections to (the E2E endpoint, or a proxy
// in front of it).
//
// This is the seam that isolates the heavy tunnel runtime (Noise handshake +
// turbotunnel/KCP/smux over a DNS transport) from the rest of the engine. Every
// other part of this package — the concurrent Run orchestrator and the HTTP
// E2E check below — is pure-stdlib and fully testable with a fake dialer, so
// the only piece that depends on the dnstt libraries is a TunnelDialer impl
// wired in separately.
//
// Implementations MUST honor ctx (dial deadline/cancellation) and MUST return a
// non-nil error rather than a nil conn on failure.
type TunnelDialer interface {
	Dial(ctx context.Context, resolver string, opts Options) (net.Conn, error)
}

// dnsttValidator is the DNSTT/SlipNet-style backend: for each resolver it brings
// up a tunnel via the injected TunnelDialer, then confirms the tunnel carries
// real traffic by fetching opts.E2EURL over it and requiring an HTTP 2xx/3xx.
type dnsttValidator struct {
	dialer TunnelDialer
}

// NewDNSTTValidator returns a Validator that proves each resolver end-to-end
// through the given TunnelDialer. dialer must be non-nil.
func NewDNSTTValidator(dialer TunnelDialer) Validator {
	return &dnsttValidator{dialer: dialer}
}

func (v *dnsttValidator) Validate(ctx context.Context, resolver string, opts Options) Result {
	res := Result{Resolver: resolver}
	if v.dialer == nil {
		res.Reason = "no-tunnel-dialer"
		return res
	}

	start := time.Now()
	conn, err := v.dialer.Dial(ctx, resolver, opts)
	if err != nil {
		res.Reason = dialFailReason(ctx, err)
		return res
	}
	defer conn.Close()
	res.LatencyMs = time.Since(start).Milliseconds()

	// Without a public key the Noise handshake cannot run, so a completed dial is
	// the strongest signal available: the tunnel transport reached the far side.
	// The full HTTP round-trip below requires a key.
	if opts.PubKey == "" {
		res.OK = true
		res.Reason = "tunnel-reachable"
		return res
	}

	status, err := httpGetOverConn(ctx, conn, opts.E2EURL)
	if err != nil {
		res.Reason = "e2e-fetch: " + shortErr(err)
		return res
	}
	res.HTTPStatus = status
	// 2xx and 3xx both prove the request traversed the tunnel and got a real HTTP
	// reply from the far side; only 4xx/5xx (or no reply) count as a failure.
	if status >= 200 && status < 400 {
		res.OK = true
		res.Reason = fmt.Sprintf("http-%d", status)
	} else {
		res.Reason = fmt.Sprintf("http-%d", status)
	}
	return res
}

// httpGetOverConn issues a single HTTP GET for rawURL over an already-connected
// stream (the tunnel), wrapping it in TLS first for https URLs, and returns the
// response status code. It uses the stdlib HTTP writer/reader so chunked bodies
// and headers are parsed correctly, and drains a bounded prefix of the body so
// the connection can be cleanly closed.
func httpGetOverConn(ctx context.Context, conn net.Conn, rawURL string) (int, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return 0, fmt.Errorf("bad e2e url: %w", err)
	}
	if u.Host == "" {
		return 0, fmt.Errorf("bad e2e url: missing host")
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	var stream net.Conn = conn
	if u.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname()})
		if err := tc.HandshakeContext(ctx); err != nil {
			return 0, fmt.Errorf("tls: %w", err)
		}
		stream = tc
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "whitedns-e2e/1.0")
	req.Close = true

	if err := req.Write(stream); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

// dialFailReason distinguishes a per-resolver timeout from a genuine tunnel
// setup failure, so reports say why a resolver did not qualify.
func dialFailReason(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "tunnel-timeout"
	}
	return "tunnel-dial: " + shortErr(err)
}

// shortErr keeps failure strings compact for report columns.
func shortErr(err error) string {
	s := err.Error()
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
