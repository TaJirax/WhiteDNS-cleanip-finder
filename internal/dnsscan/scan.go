package dnsscan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Options configures a resolver scan.
type Options struct {
	TargetDomain  string        // A-record integrity domain (default "google.com")
	TxtDomain     string        // TXT passthrough domain (default = TargetDomain)
	Timeout       time.Duration // per-probe timeout (default 3s)
	Ports         []int         // custom ports; empty => 53(UDP/TCP) + 853(DoT) + 443(DoH)
	Protocol      string        // "udp" | "tcp" | "both" | "all" (default "all" = incl DoT/DoH)
	Concurrency   int           // resolver worker pool size (default 64)
	TruthProvider string        // reference resolver for the truth table: "google" (default) | "cloudflare"

	// ScoreThreshold: resolvers with a compatibility Score >= this are considered
	// "qualified" (range-scout parity). 0 keeps everything.
	ScoreThreshold int
	// TestNearby expands the /24 of every tunnel-ready resolver and rescans it
	// (range-scout "Test Nearby IPs").
	TestNearby bool
}

func (o Options) withDefaults() Options {
	if strings.TrimSpace(o.TargetDomain) == "" {
		o.TargetDomain = "google.com"
	}
	if strings.TrimSpace(o.TxtDomain) == "" {
		o.TxtDomain = o.TargetDomain
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 64
	}
	switch strings.ToLower(strings.TrimSpace(o.Protocol)) {
	case "udp", "tcp", "both", "all":
		o.Protocol = strings.ToLower(strings.TrimSpace(o.Protocol))
	default:
		o.Protocol = "all"
	}
	switch strings.ToLower(strings.TrimSpace(o.TruthProvider)) {
	case ReferenceGoogle, ReferenceCloudflare, ReferenceQuad9:
		o.TruthProvider = strings.ToLower(strings.TrimSpace(o.TruthProvider))
	default:
		o.TruthProvider = ReferenceGoogle
	}
	return o
}

// ResolverResult is the aggregated verdict for one resolver IP.
type ResolverResult struct {
	IP           string
	Probes       []DnsProbeResult // per-protocol A-record probes
	TxtProbe     DnsProbeResult   // TXT passthrough probe
	Responded    bool
	UDPOK        bool          // responded over UDP
	TCPOK        bool          // responded over TCP
	RA           bool          // open recursion advertised
	EDNS         bool          // EDNS0 large-payload usable
	Poisoned     bool          // any A answer mismatched the truth table
	TxtPass      bool          // TXT rdata returned intact
	Transparent  bool          // transparent DNS proxy / lying resolver detected
	Score        int           // SlipNet-style compatibility score 0-6
	TunnelReady  bool          // RA + EDNS + TXT passthrough
	TunnelReason string        // why ready / what's missing
	BestLatency  time.Duration // fastest responding probe
	Nearby       bool          // discovered via /24 nearby-expansion pass
	Status       string        // overall verdict: valid | poison | hijack | invalid
	NSCount      int           // authority (NS) records seen across probes
	ARCount      int           // additional records seen across probes
	PoisonIP     string        // the mismatched A answer(s) that tripped poisoning
	HijackIP     string        // the forged A answer returned for a nonexistent name
}

// Resolver status values (one per resolver, most-severe wins).
const (
	StatusValid   = "valid"   // responded with an honest answer
	StatusPoison  = "poison"  // answer failed truth-table integrity
	StatusHijack  = "hijack"  // transparent proxy / forged NXDOMAIN answer
	StatusInvalid = "invalid" // no usable response at all
)

// classifyStatus collapses the per-resolver flags into a single state. Order of
// precedence: no response (invalid) → forged answers (poison) → transparent
// interception (hijack) → honest (valid).
func classifyStatus(r ResolverResult) string {
	switch {
	case !r.Responded:
		return StatusInvalid
	case r.Poisoned:
		return StatusPoison
	case r.Transparent:
		return StatusHijack
	default:
		return StatusValid
	}
}

// StatusColor maps a resolver status to the report colour requested by the
// operator: poison=purple, hijack=yellow, valid=green, invalid=red.
func StatusColor(status string) string {
	switch status {
	case StatusPoison:
		return "purple"
	case StatusHijack:
		return "yellow"
	case StatusValid:
		return "green"
	default:
		return "red"
	}
}

// HeaderDump returns one "PROTO | header" line per probe (full header per probe).
func (r ResolverResult) HeaderDump() []string {
	lines := make([]string, 0, len(r.Probes)+1)
	for _, p := range r.Probes {
		hdr := "(no header)"
		if p.HeaderOK {
			hdr = p.Header.String()
		}
		ans := strings.Join(p.AnswerIPs, ",")
		lines = append(lines, fmt.Sprintf("%-8s %s | ans=%s err=%s", p.Protocol, hdr, ans, p.Error))
	}
	if r.TxtProbe.Protocol != "" {
		hdr := "(no header)"
		if r.TxtProbe.HeaderOK {
			hdr = r.TxtProbe.Header.String()
		}
		lines = append(lines, fmt.Sprintf("%-8s %s | txt=%s err=%s",
			"TXT/"+r.TxtProbe.Protocol, hdr, strings.Join(r.TxtProbe.AnswerTXT, ""), r.TxtProbe.Error))
	}
	return lines
}

// ScanResolvers probes every resolver IP and reports aggregated results. The
// truth table is fetched once up front. progress (optional) is called after each
// resolver completes, from a single goroutine, so it is safe for UI updates.
func ScanResolvers(ctx context.Context, ips []string, opts Options, progress func(done, total int, r ResolverResult)) []ResolverResult {
	opts = opts.withDefaults()

	truth := NewTruthTable(opts.TargetDomain)
	truth.Prefer = opts.TruthProvider
	_ = truth.FetchTruth() // best-effort; Verify() treats an empty table as clean

	dialer := &net.Dialer{Timeout: opts.Timeout}
	dohClient := newDoHClient(opts.Timeout, dialer)

	total := len(ips)
	results := make([]ResolverResult, total)

	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	worker := func() {
		defer wg.Done()
		for i := range jobs {
			if ctx.Err() != nil {
				return
			}
			r := ScanResolver(ctx, strings.TrimSpace(ips[i]), opts, truth, dialer, dohClient)
			results[i] = r
			mu.Lock()
			done++
			d := done
			mu.Unlock()
			if progress != nil {
				progress(d, total, r)
			}
		}
	}

	n := opts.Concurrency
	if n > total {
		n = total
	}
	for w := 0; w < n; w++ {
		wg.Add(1)
		go worker()
	}
	for i := range ips {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

// ScanResolver probes one resolver across all configured protocols, runs a TXT
// passthrough test, and classifies tunnel suitability. dialer/dohClient may be
// nil (they are created per-call then).
func ScanResolver(ctx context.Context, ip string, opts Options, truth *TruthTable, dialer *net.Dialer, dohClient *http.Client) ResolverResult {
	opts = opts.withDefaults()
	res := ResolverResult{IP: ip}
	if !isIP(ip) {
		res.TunnelReason = "invalid-ip"
		return res
	}

	res.Probes = probeAllProtocols(ctx, ip, opts, truth, dialer, dohClient)

	// TXT passthrough: query a domain that actually has TXT records (plain, not a
	// random label — a nonexistent subdomain would NXDOMAIN and falsely fail
	// every resolver) so we can tell whether the resolver forwards TXT rdata,
	// the classic tunnel channel. Operators can point TxtDomain at a zone they
	// control for true end-to-end echo verification.
	txtPort := 53
	if len(opts.Ports) > 0 {
		txtPort = opts.Ports[0]
		for _, p := range opts.Ports {
			if p == 53 { // TXT passthrough is a Do53 concept — prefer 53 when scanned
				txtPort = 53
				break
			}
		}
	}
	res.TxtProbe = ProbeTXTUDP(ctx, ip, opts.TxtDomain, opts.Timeout, dialer, txtPort)
	res.TxtPass = res.TxtProbe.Responded && len(res.TxtProbe.AnswerTXT) > 0

	best := time.Duration(0)
	for _, p := range res.Probes {
		// Responsiveness = a well-formed DNS reply came back (HeaderOK means QR=1
		// with a matching transaction ID). A resolver that answers REFUSED /
		// SERVFAIL / NXDOMAIN, or returns no A record for the probe domain, is
		// still a live, reachable server — only a total lack of reply (timeout /
		// unreachable) is "invalid". Many tunnel-capable resolvers REFUSE a direct
		// google.com query from a non-subscriber IP yet still forward the tunnel
		// zone, so gating on a clean A answer wrongly discarded them.
		if p.HeaderOK {
			res.Responded = true
			if strings.HasPrefix(p.Protocol, "UDP") {
				res.UDPOK = true
			}
			if strings.HasPrefix(p.Protocol, "TCP") {
				res.TCPOK = true
			}
			if p.Header.RA {
				res.RA = true
			}
			if p.TTFB > 0 && (best == 0 || p.TTFB < best) {
				best = p.TTFB
			}
			if int(p.Header.NSCount) > res.NSCount {
				res.NSCount = int(p.Header.NSCount)
			}
			if int(p.Header.ARCount) > res.ARCount {
				res.ARCount = int(p.Header.ARCount)
			}
		}
		if p.EDNS {
			res.EDNS = true
		}
		if p.IsPoisoned {
			res.Poisoned = true
			if res.PoisonIP == "" && len(p.AnswerIPs) > 0 {
				res.PoisonIP = strings.Join(p.AnswerIPs, ",")
			}
		}
	}
	res.BestLatency = best

	// Transparent-proxy / lying-resolver detection: a random, guaranteed-
	// nonexistent name must return NXDOMAIN. If the resolver hands back an A
	// record for it, it is intercepting/forging answers (a transparent DNS
	// proxy / NXDOMAIN-redirect), which makes it unreliable for tunneling. Two
	// independent bogus names are tried because a single UDP probe can be lost
	// or rate-limited, which would silently miss a hijacker (false negative).
	if res.Responded {
		res.Transparent, res.HijackIP = detectHijack(ctx, ip, opts.Timeout, dialer, txtPort)
	}

	res.Score = computeScore(res)
	res.TunnelReady, res.TunnelReason = classifyTunnel(res)
	res.Status = classifyStatus(res)
	return res
}

// computeScore assigns a SlipNet-style 0-6 compatibility score.
func computeScore(r ResolverResult) int {
	score := 0
	if r.UDPOK {
		score++
	}
	if r.TCPOK {
		score++
	}
	if r.RA {
		score++
	}
	if r.EDNS {
		score++
	}
	if r.TxtPass {
		score++
	}
	if r.Responded && !r.Poisoned && !r.Transparent {
		score++ // answer-integrity point
	}
	return score
}

// probeAllProtocols runs the A-record probes across the configured ports and the
// selected transports (opts.Protocol: udp/tcp/both/all).
func probeAllProtocols(ctx context.Context, ip string, opts Options, truth *TruthTable, dialer *net.Dialer, dohClient *http.Client) []DnsProbeResult {
	domain := opts.TargetDomain
	out := make([]DnsProbeResult, 0, 8)

	wantUDP := opts.Protocol != "tcp"
	wantTCP := opts.Protocol != "udp"
	wantEnc := opts.Protocol == "all" // DoT/DoH only in "all" mode

	ports := opts.Ports
	if len(ports) == 0 {
		ports = []int{53}
		if wantEnc {
			ports = []int{53, 853, 443}
		}
	}

	for _, p := range ports {
		if wantUDP && p != 853 && p != 443 {
			out = append(out, ProbeUDP(ctx, ip, domain, truth, opts.Timeout, dialer, p))
		}
		if wantTCP && p != 853 && p != 443 {
			out = append(out, ProbeTCP(ctx, ip, domain, truth, opts.Timeout, dialer, p))
		}
		if wantEnc && p == 853 {
			out = append(out, ProbeDoT(ctx, ip, domain, truth, opts.Timeout, dialer, p))
		}
		if wantEnc && p == 443 {
			out = append(out, ProbeDoH(ctx, ip, domain, truth, opts.Timeout, dohClient, p))
		}
	}
	return out
}

// classifyTunnel decides tunnel suitability: open recursion (RA) + EDNS0 + TXT
// passthrough. Poisoning is reported separately and never disqualifies.
func classifyTunnel(r ResolverResult) (bool, string) {
	if !r.Responded {
		return false, "no-response"
	}
	var missing []string
	if !r.RA {
		missing = append(missing, "no-recursion(RA=0)")
	}
	if !r.EDNS {
		missing = append(missing, "no-edns0")
	}
	if !r.TxtPass {
		missing = append(missing, "no-txt-passthrough")
	}
	if len(missing) == 0 {
		return true, "open-recursor+edns0+txt-passthrough"
	}
	return false, strings.Join(missing, ",")
}

// detectHijack probes the resolver with independent, guaranteed-nonexistent
// names. A correct resolver answers NXDOMAIN (no A record); a transparent proxy,
// captive portal, or NXDOMAIN-redirect box forges an A record instead. It tries
// two names so a single dropped/rate-limited UDP datagram does not mask a
// hijacker, and returns the first forged IP for the report.
func detectHijack(ctx context.Context, ip string, timeout time.Duration, dialer *net.Dialer, port int) (bool, string) {
	for i := 0; i < 2; i++ {
		bogus := "nx" + randomLabel() + "." + randomLabel() + ".com"
		tp := ProbeUDP(ctx, ip, bogus, nil, timeout, dialer, port)
		if tp.Responded && len(tp.AnswerIPs) > 0 {
			return true, strings.Join(tp.AnswerIPs, ",")
		}
	}
	return false, ""
}

// randomLabel returns a short random hex label for cache-busting / bogus names.
func randomLabel() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// NearbyIPs returns the 256 addresses of the /24 containing ip (range-scout
// "Test Nearby IPs"). Returns nil for non-IPv4 input.
func NearbyIPs(ip string) []string {
	p := net.ParseIP(strings.TrimSpace(ip)).To4()
	if p == nil {
		return nil
	}
	out := make([]string, 0, 256)
	for i := 0; i < 256; i++ {
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", p[0], p[1], p[2], i))
	}
	return out
}
