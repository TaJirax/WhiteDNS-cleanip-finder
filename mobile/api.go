package mobile

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"whitedns-go/internal/asn"
	"whitedns-go/internal/asnexport"
	"whitedns-go/internal/scanner"
	"whitedns-go/internal/tlsprobe"
)

// ── throttle ─────────────────────────────────────────────────────────────────
// Allows at most one event per periodMs. Lock-free (atomic CAS on timestamp).

type throttle struct {
	lastMs   int64
	periodMs int64
}

func newThrottle(period time.Duration) *throttle {
	return &throttle{periodMs: period.Milliseconds()}
}

func (t *throttle) allow() bool {
	now := time.Now().UnixMilli()
	last := atomic.LoadInt64(&t.lastMs)
	if now-last < t.periodMs {
		return false
	}
	return atomic.CompareAndSwapInt64(&t.lastMs, last, now)
}

// ── resultFile ───────────────────────────────────────────────────────────────
// Opened once at scan start, appended to for every accepted result, closed at
// scan end. This keeps memory flat regardless of how many results arrive.

type resultFile struct {
	f   *os.File
	w   *bufio.Writer
	path string
}

func openResultFile(dataDir, kind string) (*resultFile, error) {
	stamp := time.Now().Format("20060102-150405")
	p := filepath.Join(dataDir, "results", fmt.Sprintf("scan-%s-%s.txt", kind, stamp))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(p)
	if err != nil {
		return nil, err
	}
	return &resultFile{f: f, w: bufio.NewWriterSize(f, 32*1024), path: p}, nil
}

func (rf *resultFile) write(line string) {
	if rf == nil {
		return
	}
	_, _ = fmt.Fprintln(rf.w, line)
}

func (rf *resultFile) close() string {
	if rf == nil {
		return ""
	}
	_ = rf.w.Flush()
	_ = rf.f.Close()
	return rf.path
}

// ── helpers ──────────────────────────────────────────────────────────────────

func splitTargets(blob string) []string {
	fields := strings.FieldsFunc(blob, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ','
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func parsePortsCSV(portStr string) []int {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return []int{443, 2053, 2083, 2087, 2096, 8443}
	}
	seen := make(map[int]bool)
	var ports []int
	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rng := strings.SplitN(part, "-", 2)
			s, _ := strconv.Atoi(strings.TrimSpace(rng[0]))
			e, _ := strconv.Atoi(strings.TrimSpace(rng[1]))
			for p := s; p <= e; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			if p, err := strconv.Atoi(part); err == nil && !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}
	if len(ports) == 0 {
		return []int{80, 443, 8080}
	}
	sort.Ints(ports)
	return ports
}

func parsePortsOrEmpty(portStr string) []int {
	if strings.TrimSpace(portStr) == "" {
		return nil
	}
	return parsePortsCSV(portStr)
}

func timeoutOrDefault(ms int, def time.Duration, lowBandwidth bool) time.Duration {
	t := def
	if ms > 0 {
		t = time.Duration(ms) * time.Millisecond
	}
	if lowBandwidth && t < 15*time.Second {
		t = 15 * time.Second
	}
	return t
}

// concurrencyOrDefault keeps worker counts phone-safe. High fanout on a phone
// saturates the radio/fd table and disconnects the device, so we hard-cap well
// below desktop values.
func concurrencyOrDefault(c, def int) int {
	if c <= 0 {
		c = def
	}
	// Mobile hard cap: 100 workers. Even this is high for a weak device; the
	// recommended modes are 10/25/50.
	if c > 100 {
		c = 100
	}
	if c < 1 {
		c = 1
	}
	return c
}

// Mobile memory guards — bound RAM so CDN-sized ranges (e.g. Cloudflare) can't
// OOM-crash a phone. The scan runs on the capped subset (slow but stable).
const (
	mobileMaxIPs       = 200000 // cap unique IPs expanded from CIDRs
	mobileMaxEndpoints = 400000 // cap total ip:port endpoints (memory + goroutines)
)

// gentleProbeDomains returns a reduced probe-domain list for low-concurrency
// "gentle" modes (≤25 workers). Fewer probes per endpoint = far less bandwidth,
// which keeps the user's connection alive on weak links.
func gentleProbeDomains(conc int) []string {
	switch {
	case conc <= 10:
		return []string{"workers.dev"}
	case conc <= 25:
		return []string{"workers.dev", "pages.dev", "chatgpt.com"}
	default:
		return nil // nil -> engine uses its full default list
	}
}

func calcETA(start time.Time, processed, total int) int {
	if processed <= 0 || processed >= total {
		return 0
	}
	rate := float64(processed) / time.Since(start).Seconds()
	if rate <= 0 {
		return 0
	}
	return int(float64(total-processed) / rate)
}

// ── IP / CIDR scan ───────────────────────────────────────────────────────────

// StartIPScan scans IP ranges. Results are written to
// {dataDir}/results/scan-ip-*.txt incrementally; only the last few are
// forwarded to the listener (for live display). On millions of IPs this keeps
// Android memory flat.
func StartIPScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	sc := scanner.NewScanner(nil)
	h := newScanHandle(sc)

	targets := splitTargets(cfg.Targets)
	ports := parsePortsCSV(cfg.Ports)
	conc := concurrencyOrDefault(cfg.Concurrency, 50) // phone default: 50 workers
	timeout := timeoutOrDefault(cfg.TimeoutMs, scanner.ScanTimeout, cfg.LowBandwidth)

	sc.SetTargetPorts(ports)

	logThrottle := newThrottle(250 * time.Millisecond)
	sc.SetLogCallback(func(msg string) {
		if !h.isStopped() && logThrottle.allow() {
			l.OnLog(strings.TrimRight(msg, "\n"))
		}
	})

	opts := scanner.IPScanOptions{
		Ports:         ports,
		Concurrency:   conc,
		Timeout:       timeout,
		EndpointCount: len(targets) * len(ports),
		// Android safety: never let the engine auto-raise to 2000 workers, and
		// bound memory so CDN-sized ranges can't OOM the device.
		DisableAutoConcurrency: true,
		MaxIPs:                 mobileMaxIPs,
		MaxEndpoints:           mobileMaxEndpoints,
	}
	// Gentle modes (≤25 workers): probe fewer domains per endpoint to keep the
	// user's connection alive on weak links. Also pin per-endpoint parallelism low.
	if gentle := gentleProbeDomains(conc); gentle != nil {
		opts.ProbeDomainsHTTP = gentle
		opts.ProbeDomainsHTTPS = gentle
		opts.AdaptiveDomainConcurrency = 1
	}
	if cfg.LowBandwidth {
		opts.AdaptiveDomainConcurrency = 1
	}

	start := time.Now()
	progressCb := func(processed, totalProbes, accepted int, currentIP string, totalIPs int) {
		if !h.isStopped() {
			l.OnProgress(processed, totalProbes, accepted, totalIPs, currentIP,
				calcETA(start, processed, totalProbes))
		}
	}

	go func() {
		defer sc.SetLogCallback(nil)

		rf, _ := openResultFile(dataDir, "ip")
		resultThrottle := newThrottle(250 * time.Millisecond)

		// Wrap progressCb to also capture accepted endpoints as they stream.
		// The engine reports the currentIP on every progress tick; we hook into
		// the accepted count to detect new hits. However the engine doesn't give
		// us accepted endpoints mid-scan — we receive the full list at the end.
		// So: write all to file at end, send throttled sample to listener.
		results, err := sc.ScanIPsWithProgress(targets, opts, progressCb)
		sc.SetLogCallback(nil)

		if err != nil || h.isStopped() {
			savedPath := rf.close()
			msg := ""
			if err != nil {
				msg = err.Error()
			} else {
				msg = "stopped"
			}
			if savedPath != "" && err == nil {
				// partial results already written? no — engine returns nothing on stop.
			}
			l.OnDone("", msg)
			return
		}

		// Write all results to disk, forward throttled sample to Kotlin for display.
		for _, r := range results {
			rf.write(r)
			if resultThrottle.allow() {
				l.OnResult(r)
			}
		}
		savedPath := rf.close()
		l.OnDone(savedPath, "")
	}()
	return h
}

// ── HTTP / SOCKS5 proxy scans ────────────────────────────────────────────────

func startProxyScan(dataDir, kind string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	sc := scanner.NewScanner(nil)
	h := newScanHandle(sc)

	targets := splitTargets(cfg.Targets)
	conc := concurrencyOrDefault(cfg.Concurrency, 50)
	timeout := timeoutOrDefault(cfg.TimeoutMs, 8*time.Second, cfg.LowBandwidth)

	opts := scanner.ProxyScanOptions{
		Ports:         parsePortsOrEmpty(cfg.Ports),
		Discovery:     "direct",
		Concurrency:   conc,
		Timeout:       timeout,
		TransferModel: strings.TrimSpace(cfg.TransferModel),
	}

	logThrottle := newThrottle(250 * time.Millisecond)
	sc.SetLogCallback(func(msg string) {
		if !h.isStopped() && logThrottle.allow() {
			l.OnLog(strings.TrimRight(msg, "\n"))
		}
	})

	start := time.Now()
	sc.SetProxyProgressCallback(func(processed, total, hits int, currentIP string, totalIPs int) {
		if !h.isStopped() {
			l.OnProgress(processed, total, hits, totalIPs, currentIP,
				calcETA(start, processed, total))
		}
	})

	go func() {
		defer func() {
			sc.SetLogCallback(nil)
			sc.SetProxyProgressCallback(nil)
		}()

		var results []string
		var err error
		if kind == "socks5" {
			results, err = sc.ScanSOCKS5Proxies(targets, opts)
		} else {
			results, err = sc.ScanHTTPProxies(targets, opts)
		}

		if err != nil || h.isStopped() {
			msg := ""
			if err != nil {
				msg = err.Error()
			} else {
				msg = "stopped"
			}
			l.OnDone("", msg)
			return
		}

		rf, _ := openResultFile(dataDir, kind)
		resultThrottle := newThrottle(250 * time.Millisecond)
		for _, r := range results {
			rf.write(r)
			if resultThrottle.allow() {
				l.OnResult(r)
			}
		}
		l.OnDone(rf.close(), "")
	}()
	return h
}

// StartHTTPProxyScan begins a direct HTTP-proxy scan.
func StartHTTPProxyScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	return startProxyScan(dataDir, "http", cfg, l)
}

// StartSOCKS5Scan begins a direct SOCKS5-proxy scan.
func StartSOCKS5Scan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	return startProxyScan(dataDir, "socks5", cfg, l)
}

// ── SNI scan ─────────────────────────────────────────────────────────────────

// StartSNIScan probes TLS/SNI. Each successful result is written to disk
// immediately; only a throttled sample goes to the listener.
func StartSNIScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	h := newScanHandle(nil)
	targets := splitTargets(cfg.Targets)
	domains := splitTargets(cfg.SNIDomains)
	if len(domains) == 0 {
		domains = tlsprobe.GetDomains(dataDir)
	}
	ports := parsePortsCSV(cfg.Ports)
	conc := concurrencyOrDefault(cfg.Concurrency, 50)
	timeout := timeoutOrDefault(cfg.TimeoutMs, scanner.ScanTimeout, cfg.LowBandwidth)

	go func() {
		if len(targets) == 0 || len(domains) == 0 {
			reason := "no IP targets selected"
			if len(domains) == 0 {
				reason = "no SNI domains selected"
			}
			l.OnDone("", reason)
			return
		}

		rf, _ := openResultFile(dataDir, "sni")
		logThrottle := newThrottle(250 * time.Millisecond)
		resultThrottle := newThrottle(250 * time.Millisecond)

		resCh := make(chan tlsprobe.ProbeResult, 512)
		go func() {
			tlsprobe.RunScan(tlsprobe.ScanConfig{
				Targets:     targets,
				Hostnames:   domains,
				Port:        ports[0],
				TimeoutSec:  timeout.Seconds(),
				Concurrency: conc,
				StrictSNI:   cfg.SNIStrict,
			}, resCh, nil)
		}()

		expanded := len(tlsprobe.ExpandTargets(targets))
		if expanded == 0 {
			expanded = len(targets)
		}
		total := expanded * len(domains)
		start := time.Now()
		processed, hits := 0, 0

		for pr := range resCh {
			processed++
			if h.isStopped() {
				continue // drain so producer goroutine can finish
			}

			label := "FAIL"
			if pr.Success {
				label = "OK"
				hits++
			}
			suffix := ""
			if pr.CertMatchesSNI {
				suffix = " [cert-match]"
			} else if pr.SNIAccepted {
				suffix = " [sni-ok]"
			}
			text := fmt.Sprintf("%s %s:%d %s %dms %s %d%s",
				pr.Hostname, pr.IP, pr.Port, label,
				int(pr.LatencyMs), pr.TLSVersion, pr.HTTPStatus, suffix)

			if pr.Success {
				rf.write(text)
				if resultThrottle.allow() {
					l.OnResult(text)
				}
			}
			if logThrottle.allow() {
				l.OnLog(text)
			}
			l.OnProgress(processed, total, hits, expanded, pr.IP,
				calcETA(start, processed, total))
		}

		if h.isStopped() {
			l.OnDone("", "stopped")
			_ = rf.close()
			return
		}
		l.OnDone(rf.close(), "")
	}()
	return h
}

// ── ASN export & search ──────────────────────────────────────────────────────

// ExportASN expands all ASNs matching query into a flat IP list on disk under
// {dataDir}/asn_exports/. Returns the output file path.
func ExportASN(dataDir, query string) (string, error) {
	eng := asn.NewASNEngine(dataDir)
	if err := eng.Load(); err != nil {
		return "", err
	}
	groups, err := eng.SearchGroups(query)
	if err != nil {
		return "", err
	}
	if len(groups) == 0 {
		return "", fmt.Errorf("no ASNs matched %q", query)
	}
	cidrs := make([]string, 0)
	for _, g := range groups {
		cidrs = append(cidrs, g.CIDRs...)
	}
	path, _, err := asnexport.ExportTargetsToTXT(dataDir, cidrs, "")
	return path, err
}

// normASN normalizes an ASN identifier for exact comparison ("AS44244" == "44244").
func normASN(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "AS")
	return s
}

// ExpandASNs takes newline/space/comma-separated ASN identifiers (e.g. the ones
// the ASN picker returns) and expands each to its IPv4 CIDRs, returning them as
// a newline-separated string suitable for use as scan Targets. IPv6 ranges are
// skipped because the IP/SNI/proxy scanners operate on IPv4.
func ExpandASNs(dataDir, asnIDs string) (string, error) {
	eng := asn.NewASNEngine(dataDir)
	if err := eng.Load(); err != nil {
		return "", err
	}
	ids := splitTargets(asnIDs)
	if len(ids) == 0 {
		return "", fmt.Errorf("no ASNs given")
	}
	seen := make(map[string]bool)
	var cidrs []string
	for _, id := range ids {
		groups, err := eng.SearchGroups(id)
		if err != nil {
			continue
		}
		want := normASN(id)
		for _, g := range groups {
			if normASN(g.ASN) != want {
				continue // substring match for a different ASN — skip
			}
			for _, c := range g.CIDRs {
				if strings.Contains(c, ":") {
					continue // IPv6 — not scannable here
				}
				if !seen[c] {
					seen[c] = true
					cidrs = append(cidrs, c)
				}
			}
		}
	}
	if len(cidrs) == 0 {
		return "", fmt.Errorf("no IPv4 CIDRs found for the selected ASN(s)")
	}
	return strings.Join(cidrs, "\n"), nil
}

// ExportCIDRs expands the given newline/space/comma-separated CIDRs into a flat
// IP list written under {dataDir}/asn_exports/ and returns the file path.
func ExportCIDRs(dataDir, cidrs string) (string, error) {
	list := splitTargets(cidrs)
	if len(list) == 0 {
		return "", fmt.Errorf("no CIDRs to export")
	}
	path, _, err := asnexport.ExportTargetsToTXT(dataDir, list, "")
	return path, err
}

// ASNSearch returns matching ASNs as newline-separated "ASN\tName\tsubnetCount" rows.
func ASNSearch(dataDir, query string) (string, error) {
	eng := asn.NewASNEngine(dataDir)
	if err := eng.Load(); err != nil {
		return "", err
	}
	groups, err := eng.SearchGroups(query)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, g := range groups {
		fmt.Fprintf(&b, "%s\t%s\t%d\n", g.ASN, g.Name, g.SubnetCount)
	}
	return b.String(), nil
}
