package dnsscan

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DnsProbeResult is the outcome of a single DNS protocol probe against one resolver.
type DnsProbeResult struct {
	Protocol   string        // e.g. "UDP/53", "TCP/53", "DoT/853", "DoH/443"
	Responded  bool          // parseable DNS response received?
	IsPoisoned bool          // A-record answer mismatched the truth table?
	AnswerIPs  []string      // A-record IPs
	AnswerTXT  []string      // TXT strings
	TTFB       time.Duration // time-to-first-byte
	Error      string        // empty on success

	Header   DnsHeader // parsed response header (all flags + counts)
	HeaderOK bool      // header was parsed
	EDNS     bool      // resolver returned an EDNS0 OPT record
}

// ── A-record probes ──────────────────────────────────────────────────────────

// ProbeUDP sends a DNS A query over UDP (with EDNS0→bare fallback).
func ProbeUDP(ctx context.Context, resolverIP, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("UDP/%d", port)}
	hdr, ips, edns, ttfb, err := probeUDPWithFallback(ctx, resolverIP, domain, 1, timeout, dialer, port)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "UDP: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}
	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	if truth != nil {
		result.IsPoisoned = !truth.Verify(ips)
	}
	return result
}

// ProbeTCP sends a DNS A query over TCP.
func ProbeTCP(ctx context.Context, resolverIP, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("TCP/%d", port)}
	query, txid := buildDnsQuery(domain, 1, true)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = "TCP_DIAL: " + truncErr(err)
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if err := writeTCPQuery(conn, query); err != nil {
		result.Error = "TCP_WRITE: " + truncErr(err)
		return result
	}
	start := time.Now()
	respBuf, err := readTCPResponse(conn)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "TCP_READ: " + truncErr(err)
		return result
	}
	hdr, ips, edns, err := parseDnsMessage(respBuf, 1, txid, true)
	if err != nil {
		result.Error = "TCP_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}
	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	if truth != nil {
		result.IsPoisoned = !truth.Verify(ips)
	}
	return result
}

// ProbeDoT sends a DNS A query over DNS-over-TLS.
func ProbeDoT(ctx context.Context, resolverIP, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoT/%d", port)}
	query, txid := buildDnsQuery(domain, 1, true)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		result.Error = "DoT_TLS: " + truncErr(err)
		return result
	}
	defer tlsConn.Close()
	tlsConn.SetDeadline(time.Now().Add(timeout))

	if err := writeTCPQuery(tlsConn, query); err != nil {
		result.Error = "DoT_WRITE: " + truncErr(err)
		return result
	}
	start := time.Now()
	respBuf, err := readTCPResponse(tlsConn)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "DoT_READ: " + truncErr(err)
		return result
	}
	hdr, ips, edns, err := parseDnsMessage(respBuf, 1, txid, true)
	if err != nil {
		result.Error = "DoT_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}
	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	if truth != nil {
		result.IsPoisoned = !truth.Verify(ips)
	}
	return result
}

// ProbeDoH sends a DNS A query via DNS-over-HTTPS (JSON API).
func ProbeDoH(ctx context.Context, resolverIP, domain string, truth *TruthTable, timeout time.Duration, client *http.Client, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoH/%d", port)}
	dohResp, ttfb, err := doDoHQuery(ctx, resolverIP, domain, "A", timeout, client, port)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "DoH: " + err.Error()
		return result
	}
	var ips []string
	for _, ans := range dohResp.Answer {
		if ans.Type == 1 {
			ip := strings.TrimSpace(ans.Data)
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		result.Error = "DoH_NO_A"
		result.Header, result.HeaderOK = dohHeader(dohResp), true
		return result
	}
	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK = dohHeader(dohResp), true
	if truth != nil {
		result.IsPoisoned = !truth.Verify(ips)
	}
	return result
}

// ── TXT probes (tunnel passthrough) ──────────────────────────────────────────

// ProbeTXTUDP sends a TXT query over UDP (with EDNS0→bare fallback).
func ProbeTXTUDP(ctx context.Context, resolverIP, queryName string, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("UDP/%d", port)}
	hdr, txts, edns, ttfb, err := probeUDPWithFallback(ctx, resolverIP, queryName, 16, timeout, dialer, port)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "UDP: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}
	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	return result
}

// ProbeTXTDoH sends a TXT query via DNS-over-HTTPS.
func ProbeTXTDoH(ctx context.Context, resolverIP, queryName string, timeout time.Duration, client *http.Client, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoH/%d", port)}
	dohResp, ttfb, err := doDoHQuery(ctx, resolverIP, queryName, "TXT", timeout, client, port)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "DoH: " + err.Error()
		return result
	}
	var txts []string
	for _, ans := range dohResp.Answer {
		if ans.Type == 16 {
			txts = append(txts, strings.Trim(ans.Data, "\""))
		}
	}
	if len(txts) == 0 {
		result.Error = "DoH_NO_TXT"
		result.Header, result.HeaderOK = dohHeader(dohResp), true
		return result
	}
	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK = dohHeader(dohResp), true
	return result
}

// ── Shared low-level helpers ─────────────────────────────────────────────────

// probeUDPWithFallback dials the resolver and sends an EDNS0 query, then — if
// that gets no usable answer — retries once with a bare (non-EDNS) query on the
// same socket. This defeats middleboxes that silently drop or FORMERR EDNS
// traffic, so poisoned/broken resolvers are still observed rather than timing
// out. Returns header, answers, whether EDNS0 is usable, TTFB, and an error if
// both attempts fail.
func probeUDPWithFallback(ctx context.Context, resolverIP, name string, qtype uint16, timeout time.Duration, dialer *net.Dialer, port int) (DnsHeader, []string, bool, time.Duration, error) {
	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return DnsHeader{}, nil, false, 0, fmt.Errorf("DIAL: %s", truncErr(err))
	}
	defer conn.Close()

	var (
		hdr     DnsHeader
		ttfb    time.Duration
		lastErr error
	)
	for i, useEDNS := range []bool{true, false} {
		query, txid := buildDnsQuery(name, qtype, useEDNS)
		conn.SetDeadline(time.Now().Add(timeout))
		if _, werr := conn.Write(query); werr != nil {
			lastErr = fmt.Errorf("WRITE: %s", truncErr(werr))
			continue
		}
		start := time.Now()
		h, answers, edns, perr := readUDPResponse(conn, txid, qtype)
		attemptTTFB := time.Since(start)
		if i == 0 || ttfb == 0 {
			ttfb = attemptTTFB
		}
		if perr == nil {
			return h, answers, edns, attemptTTFB, nil
		}
		hdr, lastErr = h, fmt.Errorf("PARSE: %s", perr.Error())
	}
	return hdr, nil, false, ttfb, lastErr
}

// readUDPResponse reads datagrams until one is a genuine response to our query
// (matching TXID + QR set) or the deadline fires. Mismatched-TXID datagrams are
// off-path spoofs / stragglers and are skipped — the core anti-injection guard.
func readUDPResponse(conn net.Conn, txid, qtype uint16) (DnsHeader, []string, bool, error) {
	buf := make([]byte, ednsUDPPayloadSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return DnsHeader{}, nil, false, err
		}
		hdr, answers, edns, perr := parseDnsMessage(buf[:n], qtype, txid, true)
		if perr != nil && strings.Contains(perr.Error(), "txid mismatch") {
			continue
		}
		return hdr, answers, edns, perr
	}
}

// writeTCPQuery frames a DNS message with the 2-byte length prefix used by
// TCP/53 and DoT, and writes it.
func writeTCPQuery(conn net.Conn, query []byte) error {
	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg[:2], uint16(len(query)))
	copy(msg[2:], query)
	_, err := conn.Write(msg)
	return err
}

// readTCPResponse reads one length-prefixed DNS message from a stream.
func readTCPResponse(conn net.Conn) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen == 0 || respLen > ednsUDPPayloadSize {
		return nil, fmt.Errorf("bad length %d", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, err
	}
	return respBuf, nil
}

// doDoHQuery performs a DoH JSON query and returns the decoded response + TTFB.
func doDoHQuery(ctx context.Context, resolverIP, name, qtype string, timeout time.Duration, client *http.Client, port int) (dohJSONResponse, time.Duration, error) {
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	url := fmt.Sprintf("https://%s:%d/dns-query?name=%s&type=%s", resolverIP, port, name, qtype)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return dohJSONResponse{}, 0, fmt.Errorf("REQ: %s", truncErr(err))
	}
	req.Header.Set("Accept", "application/dns-json")

	start := time.Now()
	resp, err := client.Do(req)
	ttfb := time.Since(start)
	if err != nil {
		return dohJSONResponse{}, ttfb, fmt.Errorf("HTTP: %s", truncErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return dohJSONResponse{}, ttfb, fmt.Errorf("STATUS: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return dohJSONResponse{}, ttfb, fmt.Errorf("READ: %s", truncErr(err))
	}
	var dohResp dohJSONResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return dohJSONResponse{}, ttfb, fmt.Errorf("JSON: %s", truncErr(err))
	}
	if dohResp.Status != 0 {
		return dohResp, ttfb, fmt.Errorf("RCODE: %d", dohResp.Status)
	}
	return dohResp, ttfb, nil
}
