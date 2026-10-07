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
	TruthProvider string        // reference resolver: "google" (default) | "cloudflare" | "quad9"
	ScanDepth     string        // "fast" skips hijack probes; "full" (default) runs every check

	// ScoreThreshold: resolvers with a compatibility Score >= this are considered
	// "qualified" (range-scout parity). 0 keeps everything.
	ScoreThreshold int
	// TestNearby expands the /24 of every tunnel-ready resolver and rescans it
	// (range-scout "Test Nearby IPs").
	TestNearby bool

	// Optional query rate limit (see rate_limit.go); all zero = unlimited.
	RateLimitPerSecond            float64 // whole scan
	RateLimitPerResolverPerSecond float64 // any one resolver
	RateLimitBurst                int     // back-to-back queries allowed (1 = evenly spaced)
	TimingJitter                  float64 // 0..1: randomly lengthen gaps
}

const (
	ScanDepthFast = "fast"
	ScanDepthFull = "full"
	// ScanDepthThorough is accepted as a user-facing alias for the canonical
	// "full" value. Keeping Full as the stored value preserves mobile/API
	// compatibility while the UI can call the mode Thorough.
	ScanDepthThorough = "thorough"

	// Fast scans are intended for broad ASN sweeps. One slow/dead resolver must
	// not occupy a worker for the normal three-second probe timeout.
	fastProbeTimeout = 1200 * time.Millisecond
)

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
	switch strings.ToLower(strings.TrimSpace(o.ScanDepth)) {
	case ScanDepthFast:
		o.ScanDepth = ScanDepthFast
	case ScanDepthFull, ScanDepthThorough:
		o.ScanDepth = ScanDepthFull
	default:
		o.ScanDepth = ScanDepthFull
	}
	if o.ScanDepth == ScanDepthFast && o.Timeout > fastProbeTimeout {
		o.Timeout = fastProbeTimeout
	}
	return o
}

// ResolverResult is the aggregated verdict for one resolver IP.
type ResolverResult struct {
	IP                    string
	Probes                []DnsProbeResult // per-protocol A-record probes
	TxtProbe              DnsProbeResult   // best TXT passthrough probe (compatibility/reporting)
	TxtProbes             []DnsProbeResult // TXT probes for every selected transport
	Responded             bool
	UDPOK                 bool          // responded over UDP
	TCPOK                 bool          // responded over TCP
	UDPPoisoned           bool          // UDP answer failed integrity checks
	TCPPoisoned           bool          // TCP answer failed integrity checks
	InjectionObserved     bool          // forged UDP NXDOMAIN raced a usable answer
	TransportDisagreement bool          // UDP and TCP produced different integrity verdicts
	PreferredTransport    string        // fastest usable Do53 path: udp or tcp
	FallbackTransport     string        // warm alternate Do53 path, when available
	RA                    bool          // open recursion advertised
	AA                    bool          // authoritative answer seen on any probe
	TC                    bool          // truncated answer seen on any probe
	RD                    bool          // recursion-desired flag echoed by any probe
	RCodes                string        // compact per-path response codes (for example UDP/53=0,TCP/53=2)
	QDCount               int           // maximum question count seen across probes
	ANCount               int           // maximum answer count seen across probes
	EDNS                  bool          // EDNS0 large-payload usable
	Poisoned              bool          // any A answer mismatched the truth table
	TxtPass               bool          // TXT rdata returned intact
	Transparent           bool          // transparent DNS proxy / lying resolver detected
	Score                 int           // SlipNet-style compatibility score 0-6
	TunnelReady           bool          // at least one clean transport can recurse and pass TXT
	TunnelTransport       string        // transport selected for tunneling: udp | tcp | dot | doh
	TunnelReason          string        // why ready / what's missing
	BestLatency           time.Duration // fastest responding probe
	Nearby                bool          // discovered via /24 nearby-expansion pass
	Status                string        // overall verdict: valid | poison | hijack | invalid
	NSCount               int           // authority (NS) records seen across probes
	ARCount               int           // additional records seen across probes
	PoisonIP              string        // the mismatched A answer(s) that tripped poisoning
	HijackIP              string        // the forged A answer returned for a nonexistent name
	HijackConfidence      string        // none | inconclusive | low | medium | high
	HijackReason          string        // compact evidence summary
	HijackUDP             bool          // anomalous reserved-name reply over UDP
	HijackTCP             bool          // anomalous reserved-name reply over TCP
	HijackChecks          int           // valid reserved-name responses examined
	HijackAnomalies       int           // responses that violated NXDOMAIN expectations
	HijackRCodes          string        // compact transport RCODE evidence
}

// Resolver status values (one per resolver, most-severe wins).
const (
	StatusValid   = "valid"   // responded with an honest answer
	StatusPoison  = "poison"  // answer failed truth-table integrity
	StatusHijack  = "hijack"  // transparent proxy / forged NXDOMAIN answer
	StatusInvalid = "invalid" // no usable response at all
)

// classifyStatus collapses the per-resolver flags into a single state. A dirty
// UDP path does not condemn a clean TCP/DoT/DoH path: this matters on networks
// that inject only UDP/53. Poison therefore means every responding A-record
// path failed integrity, while the per-transport poison fields retain evidence
// about mixed results.
func classifyStatus(r ResolverResult) string {
	switch {
	case !r.Responded:
		return StatusInvalid
	case r.Transparent:
		return StatusHijack
	case hasCleanAPath(r.Probes):
		return StatusValid
	case hasPoisonedAPath(r.Probes):
		return StatusPoison
	default:
		// A parseable REFUSED/SERVFAIL/NODATA response proves the server is
		// reachable, but it is neither a valid recursive resolver nor evidence
		// of poisoning. Keep it out of both valid and poison result lists.
		return StatusInvalid
	}
}

func hasCleanAPath(probes []DnsProbeResult) bool {
	for _, probe := range probes {
		if probe.Responded && probe.HeaderOK && !probe.IsPoisoned {
			return true
		}
	}
	return false
}

func hasPoisonedAPath(probes []DnsProbeResult) bool {
	for _, probe := range probes {
		if probe.IsPoisoned {
			return true
		}
	}
	return false
}

// Passed is the canonical resolver acceptance rule shared by desktop, Android,
// nearby expansion, and report files. TunnelReady already selects a clean
// transport; StatusValid additionally rejects resolver-wide NXDOMAIN hijacking.
func (r ResolverResult) Passed() bool {
	return r.TunnelReady && r.Status == StatusValid
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

// HeaderDump returns concise per-probe detection details. Responded (QR), RA,
// NS, and AR already have aggregate result fields, so they are intentionally
// omitted here instead of repeating the full raw DNS header.
func (r ResolverResult) HeaderDump() []string {
	lines := make([]string, 0, len(r.Probes)+len(r.TxtProbes)+1)
	for _, p := range r.Probes {
		if !p.HeaderOK {
			line := fmt.Sprintf("%-8s no-header", p.Protocol)
			if p.Error != "" {
				line += " | error=" + p.Error
			}
			lines = append(lines, line)
			continue
		}
		line := fmt.Sprintf("%-8s aa=%s tc=%s rd=%s rcode=%d qd=%d an=%d",
			p.Protocol, ynb(p.Header.AA), ynb(p.Header.TC), ynb(p.Header.RD),
			p.Header.Rcode, p.Header.QDCount, p.Header.ANCount)
		var findings []string
		if len(p.AnswerIPs) > 0 {
			findings = append(findings, "answer="+strings.Join(p.AnswerIPs, ","))
		}
		if p.IsPoisoned {
			findings = append(findings, "POISON")
		}
		if p.InjectionObserved {
			findings = append(findings, "INJECTION")
		}
		if p.Error != "" {
			findings = append(findings, "error="+p.Error)
		}
		if len(findings) > 0 {
			line += " | " + strings.Join(findings, " ")
		}
		lines = append(lines, line)
	}
	txtProbes := r.TxtProbes
	if len(txtProbes) == 0 && r.TxtProbe.Protocol != "" {
		txtProbes = []DnsProbeResult{r.TxtProbe}
	}
	for _, p := range txtProbes {
		protocol := "TXT/" + p.Protocol
		if !p.HeaderOK {
			line := fmt.Sprintf("%-8s no-header", protocol)
			if p.Error != "" {
				line += " | error=" + p.Error
			}
			lines = append(lines, line)
		} else {
			line := fmt.Sprintf("%-8s aa=%s tc=%s rd=%s rcode=%d qd=%d an=%d | txt-records=%d",
				protocol, ynb(p.Header.AA), ynb(p.Header.TC), ynb(p.Header.RD),
				p.Header.Rcode, p.Header.QDCount, p.Header.ANCount, len(p.AnswerTXT))
			if p.Error != "" {
				line += " error=" + p.Error
			}
			lines = append(lines, line)
		}
	}
	return lines
}

func mergeHeaderSummary(result *ResolverResult, probe DnsProbeResult) {
	if !probe.HeaderOK {
		return
	}
	result.AA = result.AA || probe.Header.AA
	result.TC = result.TC || probe.Header.TC
	result.RD = result.RD || probe.Header.RD
	if int(probe.Header.QDCount) > result.QDCount {
		result.QDCount = int(probe.Header.QDCount)
	}
	if int(probe.Header.ANCount) > result.ANCount {
		result.ANCount = int(probe.Header.ANCount)
	}
	rcode := fmt.Sprintf("%s=%d", probe.Protocol, probe.Header.Rcode)
	for _, existing := range strings.Split(result.RCodes, ",") {
		if existing == rcode {
			return
		}
	}
	if result.RCodes != "" {
		result.RCodes += ","
	}
	result.RCodes += rcode
}

// ScanResolvers probes every resolver IP and reports aggregated results. The
// truth table is fetched once up front. progress (optional) is called after each
// resolver completes. Calls are serialized and receive monotonically increasing
// done values, so UI callbacks do not need their own ordering guard.
func ScanResolvers(ctx context.Context, ips []string, opts Options, progress func(done, total int, r ResolverResult)) []ResolverResult {
	opts = opts.withDefaults()
	if rateLimiterFrom(ctx) == nil { // callers scanning in chunks attach one limiter for the whole scan
		ctx = WithRateLimiter(ctx, NewRateLimiter(opts.RateLimitPerSecond, opts.RateLimitPerResolverPerSecond, opts.RateLimitBurst, opts.TimingJitter))
	}

	truth := cachedTruthTable(opts.TargetDomain, opts.TruthProvider)

	dialer := &net.Dialer{Timeout: opts.Timeout}
	dohClient := newDoHClient(opts.Timeout, dialer)

	total := len(ips)
	if total == 0 {
		return nil
	}
	results := make([]ResolverResult, total)
	completed := make([]bool, total)

	jobs := make(chan int)
	var wg sync.WaitGroup
	var progressMu sync.Mutex
	done := 0

	worker := func() {
		defer wg.Done()
		for i := range jobs {
			if ctx.Err() != nil {
				return
			}
			r := ScanResolver(ctx, strings.TrimSpace(ips[i]), opts, truth, dialer, dohClient)
			results[i] = r
			completed[i] = true
			progressMu.Lock()
			done++
			d := done
			if progress != nil {
				progress(d, total, r)
			}
			progressMu.Unlock()
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
			return completedResults(results, completed)
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func completedResults(results []ResolverResult, completed []bool) []ResolverResult {
	out := make([]ResolverResult, 0, len(results))
	for i, result := range results {
		if completed[i] {
			out = append(out, result)
		}
	}
	return out
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
	// The A/transport probes and TXT passthrough probes are independent. Running
	// them together prevents their timeouts from stacking for dead resolvers.
	txtResult := make(chan []DnsProbeResult, 1)
	go func() {
		txtResult <- probeTXTProtocols(ctx, ip, opts, dialer, dohClient)
	}()
	res.Probes = probeAllProtocols(ctx, ip, opts, truth, dialer, dohClient)
	res.TxtProbes = <-txtResult
	res.TxtProbe = bestTXTProbe(res.TxtProbes)
	res.TxtPass = txtProbePassed(res.TxtProbe)

	best := time.Duration(0)
	var udpLatency, tcpLatency time.Duration
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
			mergeHeaderSummary(&res, p)
			if strings.HasPrefix(p.Protocol, "UDP") {
				res.UDPOK = true
				if p.TTFB > 0 && (udpLatency == 0 || p.TTFB < udpLatency) {
					udpLatency = p.TTFB
				}
			}
			if strings.HasPrefix(p.Protocol, "TCP") {
				res.TCPOK = true
				if p.TTFB > 0 && (tcpLatency == 0 || p.TTFB < tcpLatency) {
					tcpLatency = p.TTFB
				}
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
			if strings.HasPrefix(p.Protocol, "UDP") {
				res.UDPPoisoned = true
			}
			if strings.HasPrefix(p.Protocol, "TCP") {
				res.TCPPoisoned = true
			}
			if res.PoisonIP == "" && len(p.AnswerIPs) > 0 {
				res.PoisonIP = strings.Join(p.AnswerIPs, ",")
			}
		}
		if p.InjectionObserved {
			res.InjectionObserved = true
		}
	}
	res.BestLatency = best
	res.TransportDisagreement = res.UDPOK && res.TCPOK && res.UDPPoisoned != res.TCPPoisoned
	switch {
	case res.UDPOK && (!res.TCPOK || tcpLatency == 0 || (udpLatency > 0 && udpLatency <= tcpLatency)):
		res.PreferredTransport = "udp"
		if res.TCPOK {
			res.FallbackTransport = "tcp"
		}
	case res.TCPOK:
		res.PreferredTransport = "tcp"
		if res.UDPOK {
			res.FallbackTransport = "udp"
		}
	}

	// Reserved-name checks run concurrently over every working Do53 transport.
	// This catches A redirects, CNAME/answer rewriting, repeated NOERROR/NODATA,
	// and UDP-only injection while adding at most one timeout to the scan.
	if res.Responded && opts.ScanDepth == ScanDepthFull {
		hijack := detectHijack(ctx, ip, opts.Timeout, dialer, txtPort, res.UDPOK, res.TCPOK)
		res.Transparent = hijack.Hijacked
		res.HijackIP = strings.Join(hijack.IPs, ",")
		res.HijackConfidence = hijack.Confidence
		res.HijackReason = strings.Join(hijack.Reasons, ";")
		res.HijackUDP = hijack.UDP
		res.HijackTCP = hijack.TCP
		res.HijackChecks = hijack.Checks
		res.HijackAnomalies = hijack.Anomalies
		res.HijackRCodes = strings.Join(hijack.RCodes, ",")
	} else if opts.ScanDepth == ScanDepthFast {
		res.HijackConfidence = "skipped"
		res.HijackReason = "fast-scan"
	}

	res.Score = computeScore(res)
	res.TunnelReady, res.TunnelTransport, res.TunnelReason = classifyTunnel(res)
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
	probes := make([]func() DnsProbeResult, 0, 8)

	wantUDP, wantTCP, wantEnc := protocolProbePlan(opts.Protocol)

	ports := opts.Ports
	if len(ports) == 0 {
		ports = []int{53}
		if wantEnc {
			ports = []int{53, 853, 443}
		}
	}

	for _, p := range ports {
		port := p
		if wantUDP && p != 853 && p != 443 {
			probes = append(probes, func() DnsProbeResult {
				return probeUDP(ctx, ip, domain, truth, opts.Timeout, dialer, port, opts.ScanDepth != ScanDepthFast)
			})
		}
		if wantTCP && p != 853 && p != 443 {
			probes = append(probes, func() DnsProbeResult {
				return ProbeTCP(ctx, ip, domain, truth, opts.Timeout, dialer, port)
			})
		}
		if wantEnc && p == 853 {
			probes = append(probes, func() DnsProbeResult {
				return ProbeDoT(ctx, ip, domain, truth, opts.Timeout, dialer, port)
			})
		}
		if wantEnc && p == 443 {
			probes = append(probes, func() DnsProbeResult {
				return ProbeDoH(ctx, ip, domain, truth, opts.Timeout, dohClient, port)
			})
		}
	}
	return runProbesConcurrently(probes)
}

// probeTXTProtocols tests TXT forwarding on every selected transport. The old
// single-UDP probe produced false negatives when UDP was injected, stripped, or
// legitimately truncated while TCP/53 remained fully usable for tunneling.
func probeTXTProtocols(ctx context.Context, ip string, opts Options, dialer *net.Dialer, dohClient *http.Client) []DnsProbeResult {
	wantUDP, wantTCP, wantEnc := protocolProbePlan(opts.Protocol)
	ports := opts.Ports
	if len(ports) == 0 {
		ports = []int{53}
		if wantEnc {
			ports = []int{53, 853, 443}
		}
	}
	probes := make([]func() DnsProbeResult, 0, 8)
	for _, p := range ports {
		port := p
		if wantUDP && port != 853 && port != 443 {
			probes = append(probes, func() DnsProbeResult {
				return probeTXTUDP(ctx, ip, opts.TxtDomain, opts.Timeout, dialer, port, opts.ScanDepth != ScanDepthFast)
			})
		}
		if wantTCP && port != 853 && port != 443 {
			probes = append(probes, func() DnsProbeResult {
				return ProbeTXTTCP(ctx, ip, opts.TxtDomain, opts.Timeout, dialer, port)
			})
		}
		if wantEnc && port == 853 {
			probes = append(probes, func() DnsProbeResult {
				return ProbeTXTDoT(ctx, ip, opts.TxtDomain, opts.Timeout, dialer, port)
			})
		}
		if wantEnc && port == 443 {
			probes = append(probes, func() DnsProbeResult {
				return ProbeTXTDoH(ctx, ip, opts.TxtDomain, opts.Timeout, dohClient, port)
			})
		}
	}
	return runProbesConcurrently(probes)
}

func txtProbePassed(probe DnsProbeResult) bool {
	return probe.Responded && len(probe.AnswerTXT) > 0
}

func bestTXTProbe(probes []DnsProbeResult) DnsProbeResult {
	var best DnsProbeResult
	for _, probe := range probes {
		if txtProbePassed(probe) && (!txtProbePassed(best) || best.TTFB <= 0 || (probe.TTFB > 0 && probe.TTFB < best.TTFB)) {
			best = probe
		}
	}
	if txtProbePassed(best) {
		return best
	}
	for _, probe := range probes {
		if best.Protocol == "" || (probe.HeaderOK && !best.HeaderOK) {
			best = probe
		}
	}
	return best
}

// runProbesConcurrently preserves the configured probe order while preventing
// slow or blocked transports from serially adding their timeout to every IP.
func runProbesConcurrently(probes []func() DnsProbeResult) []DnsProbeResult {
	results := make([]DnsProbeResult, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		wg.Add(1)
		go func(index int, run func() DnsProbeResult) {
			defer wg.Done()
			results[index] = run()
		}(i, probe)
	}
	wg.Wait()
	return results
}

func protocolProbePlan(protocol string) (udp, tcp, encrypted bool) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "udp":
		return true, false, false
	case "tcp":
		return false, true, false
	case "both":
		return true, true, false
	default:
		return true, true, true
	}
}

func txtProbeKind(opts Options, port int) string {
	switch strings.ToLower(strings.TrimSpace(opts.Protocol)) {
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	}
	if port == 853 {
		return "dot"
	}
	if port == 443 {
		return "doh"
	}
	return "udp"
}

// classifyTunnel selects one transport that has a clean A response, recursion,
// and TXT passthrough. UDP additionally requires EDNS0 for usable payload size;
// stream transports do not. This allows a clean TCP path to pass when UDP/53 is
// poisoned or a large UDP TXT response is truncated.
func classifyTunnel(r ResolverResult) (bool, string, string) {
	if !r.Responded {
		return false, "", "no-response"
	}
	cleanResponse, cleanRecursor, txtOnCleanRecursor, udpNeedsEDNS := false, false, false, false
	for _, probe := range r.Probes {
		if !probe.HeaderOK || probe.IsPoisoned {
			continue
		}
		cleanResponse = true
		if !probe.Header.RA {
			continue
		}
		cleanRecursor = true
		for _, txt := range r.TxtProbes {
			if txt.Protocol != probe.Protocol || !txtProbePassed(txt) {
				continue
			}
			txtOnCleanRecursor = true
			transport := transportName(probe.Protocol)
			if transport == "udp" && !probe.EDNS && !txt.EDNS {
				udpNeedsEDNS = true
				continue
			}
			reason := "clean-" + transport + "+recursion+txt-passthrough"
			if transport == "udp" {
				reason += "+edns0"
			}
			return true, transport, reason
		}
	}
	switch {
	case !cleanResponse:
		return false, "", "no-clean-answer-path"
	case !cleanRecursor:
		return false, "", "no-recursion(RA=0)"
	case !r.TxtPass:
		return false, "", "no-txt-passthrough"
	case udpNeedsEDNS:
		return false, "", "no-edns0-on-udp-path"
	case !txtOnCleanRecursor:
		return false, "", "no-txt-on-clean-recursive-transport"
	default:
		return false, "", "no-tunnel-capable-transport"
	}
}

func transportName(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	switch {
	case strings.HasPrefix(protocol, "udp"):
		return "udp"
	case strings.HasPrefix(protocol, "tcp"):
		return "tcp"
	case strings.HasPrefix(protocol, "dot"):
		return "dot"
	case strings.HasPrefix(protocol, "doh"):
		return "doh"
	default:
		return protocol
	}
}

// detectHijack probes the resolver with independent, guaranteed-nonexistent
// names. A correct resolver answers NXDOMAIN (no A record); a transparent proxy,
// captive portal, or NXDOMAIN-redirect box forges an A record instead. It tries
// two names so a single dropped/rate-limited UDP datagram does not mask a
// hijacker, and returns the first forged IP for the report.
// randomLabel returns a short random hex label for cache-busting / bogus names.
func randomLabel() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// NearbyIPs returns the 256 addresses sharing ip's last-octet block: the /24
// for IPv4, the /120 for IPv6 (range-scout "Test Nearby IPs"). Returns nil for
// unparseable input.
func NearbyIPs(ip string) []string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return nil
	}
	p := parsed.To4()
	if p == nil {
		p = parsed.To16()
	}
	if p == nil {
		return nil
	}
	out := make([]string, 0, 256)
	for i := 0; i < 256; i++ {
		next := make(net.IP, len(p))
		copy(next, p)
		next[len(next)-1] = byte(i)
		out = append(out, next.String())
	}
	return out
}
