package dnstt

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"whitedns-go/internal/dnstt/dns"
	"whitedns-go/internal/dnstt/noise"
	"whitedns-go/internal/dnstt/turbotunnel"
)

// idleTimeout closes smux streams after this long without data (upstream value).
const idleTimeout = 2 * time.Minute

// dialTimeout bounds establishing the underlying TCP transport (RFC 7766 mode).
const dialTimeout = 15 * time.Second

// defaultHandshakeTimeout bounds the Noise handshake when ctx carries no
// deadline, so a resolver that silently drops tunnel traffic can't wedge Dial.
const defaultHandshakeTimeout = 15 * time.Second

// dnsNameCapacity returns the bytes available for encoded data in a DNS name
// after including domain (RFC 1035 §2.3.4 length limits, base32 expansion).
func dnsNameCapacity(domain dns.Name) int {
	capacity := 255
	capacity -= 1 // null terminator
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64 // 63-byte labels need 64 bytes to encode
	capacity = capacity * 5 / 8   // base32 expands every 5 bytes to 8
	return capacity
}

// tunnelConn is one smux stream over a dnstt tunnel, presented as a net.Conn.
// Closing it tears down the whole per-resolver tunnel (stream, smux session,
// KCP conn, DNS packet conn, and the underlying socket) so a bulk scan leaks no
// goroutines or sockets between resolvers.
type tunnelConn struct {
	*smux.Stream
	sess      *smux.Session
	kcpConn   *kcp.UDPSession
	pconn     *DNSPacketConn
	transport io.Closer // the underlying UDP socket or TCP stream transport
}

func (t *tunnelConn) Close() error {
	err := t.Stream.Close()
	_ = t.sess.Close()
	_ = t.kcpConn.Close()
	_ = t.pconn.Close()
	_ = t.transport.Close()
	return err
}

// ensurePort returns resolver as host:port, defaulting to port 53 when only a
// bare IP is given (the resolver shortlist entries are bare IPs).
func ensurePort(resolver string) string {
	if _, _, err := net.SplitHostPort(resolver); err == nil {
		return resolver
	}
	return net.JoinHostPort(resolver, "53")
}

// Dial brings up one dnstt tunnel through resolver for domainStr, authenticated
// to the server identified by pubkey, and returns a single bidirectional stream
// to whatever the dnstt server forwards to. transport is "" / "udp" (DNS over
// UDP/53) or "tcp" (DNS over TCP/53, RFC 7766 framing) — the latter reaches
// servers where UDP/53 is poisoned. DoT/DoH are not vendored.
//
// The returned net.Conn's Close tears the whole tunnel down. The caller should
// set its own read/write deadlines on the returned conn for the data phase; the
// Noise handshake here is bounded by ctx's deadline (or defaultHandshakeTimeout).
func Dial(ctx context.Context, resolver, domainStr string, pubkey []byte, transport string) (net.Conn, error) {
	switch transport {
	case "", "udp", "tcp":
	default:
		return nil, fmt.Errorf("dnstt vendored transports are udp/tcp, got %q", transport)
	}
	if len(pubkey) != noise.KeyLen {
		return nil, fmt.Errorf("pubkey must be %d bytes, got %d", noise.KeyLen, len(pubkey))
	}

	domain, err := dns.ParseName(domainStr)
	if err != nil {
		return nil, fmt.Errorf("invalid domain %q: %w", domainStr, err)
	}

	// Build the underlying DNS transport (UDP socket or TCP stream) and the addr
	// that DNSPacketConn/KCP will route through. For TCP the addr is a dummy —
	// the stream transport has a single fixed conn — matching dnstt's DoT path.
	var (
		remoteAddr    net.Addr
		transportConn io.Closer
		underlying    net.PacketConn
	)
	if transport == "tcp" {
		conn, derr := net.DialTimeout("tcp", ensurePort(resolver), dialTimeout)
		if derr != nil {
			return nil, fmt.Errorf("dial tcp resolver %q: %w", resolver, derr)
		}
		sp := newStreamPacketConn(conn)
		remoteAddr = turbotunnel.DummyAddr{}
		transportConn = sp
		underlying = sp
	} else {
		udpAddr, rerr := net.ResolveUDPAddr("udp", ensurePort(resolver))
		if rerr != nil {
			return nil, fmt.Errorf("resolve resolver %q: %w", resolver, rerr)
		}
		udpConn, uerr := net.ListenUDP("udp", nil)
		if uerr != nil {
			return nil, fmt.Errorf("open udp socket: %w", uerr)
		}
		remoteAddr = udpAddr
		transportConn = udpConn
		underlying = udpConn
	}

	// From here on, any error must close what we've opened so far.
	pconn := NewDNSPacketConn(underlying, remoteAddr, domain)
	fail := func(err error) (net.Conn, error) {
		_ = pconn.Close()
		_ = transportConn.Close()
		return nil, err
	}

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + pad-len + pad + data-len
	if mtu < 80 {
		return fail(fmt.Errorf("domain %q leaves only %d bytes for payload", domainStr, mtu))
	}

	kcpConn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		return fail(fmt.Errorf("open KCP conn: %w", err))
	}
	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(0, 0, 0, 1) // nc=1: congestion window off
	kcpConn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if !kcpConn.SetMtu(mtu) {
		_ = kcpConn.Close()
		return fail(fmt.Errorf("set KCP mtu %d failed", mtu))
	}
	failKCP := func(err error) (net.Conn, error) {
		_ = kcpConn.Close()
		return fail(err)
	}

	// Bound the Noise handshake by ctx (or a default), since it blocks on the
	// server's reply and a dead resolver would otherwise hang here.
	deadline := time.Now().Add(defaultHandshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = kcpConn.SetDeadline(deadline)

	rw, err := noise.NewClient(kcpConn, pubkey)
	if err != nil {
		return failKCP(fmt.Errorf("noise handshake: %w", err))
	}
	// Handshake done: clear the deadline so the data phase is governed by the
	// caller's own deadlines / smux keepalive instead.
	_ = kcpConn.SetDeadline(time.Time{})

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return failKCP(fmt.Errorf("open smux session: %w", err))
	}
	stream, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		return failKCP(fmt.Errorf("open smux stream: %w", err))
	}

	return &tunnelConn{
		Stream:    stream,
		sess:      sess,
		kcpConn:   kcpConn,
		pconn:     pconn,
		transport: transportConn,
	}, nil
}
