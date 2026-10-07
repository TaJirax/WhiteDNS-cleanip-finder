package mobile

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whitedns-go/internal/asnexport"
	"whitedns-go/internal/dnsscan"
	"whitedns-go/internal/dnstt"
	"whitedns-go/internal/e2e"
	"whitedns-go/internal/scanner"
	"whitedns-go/internal/tlsprobe"
)

// ── throttle ─────────────────────────────────────────────────────────────────
// Allows at most one event per periodMs. Lock-free (atomic CAS on timestamp).

type throttle struct {
	lastMs   atomic.Int64
	periodMs int64
}

func newThrottle(period time.Duration) *throttle {
	return &throttle{periodMs: period.Milliseconds()}
}

func (t *throttle) allow() bool {
	now := time.Now().UnixMilli()
	last := t.lastMs.Load()
	if now-last < t.periodMs {
		return false
	}
	return t.lastMs.CompareAndSwap(last, now)
}

// ── resultFile ───────────────────────────────────────────────────────────────
// Opened once at scan start, appended to for every accepted result, closed at
// scan end. This keeps memory flat regardless of how many results arrive.

type resultFile struct {
	f    *os.File
	w    *bufio.Writer
	path string
	// Companion file containing ONLY the ip:port of each passed result (no probe
	// domains or extra columns) — a clean list ready to paste elsewhere.
	ipF    *os.File
	ipW    *bufio.Writer
	ipPath string
}

// ipPortRegex matches the first IPv4 (with optional :port) in a result line, so
// the clean ip:port list works for every scan's line format (plain "ip:port",
// SNI "host ip:port OK …", Speed-Rank "N. ip DOWN …", proxy "http ip:port …").
var ipPortRegex = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b`)

func openResultFile(dataDir, kind string) (*resultFile, error) {
	stamp := time.Now().Format("20060102-150405")
	dir := filepath.Join(dataDir, "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, fmt.Sprintf("scan-%s-%s.txt", kind, stamp))
	f, err := os.Create(p)
	if err != nil {
		return nil, err
	}
	rf := &resultFile{f: f, w: bufio.NewWriterSize(f, 32*1024), path: p}
	// Best-effort companion ip:port-only file; if it can't be created the main
	// results file still works.
	ipP := filepath.Join(dir, fmt.Sprintf("scan-%s-%s-ipport.txt", kind, stamp))
	if ipF, ierr := os.Create(ipP); ierr == nil {
		rf.ipF = ipF
		rf.ipW = bufio.NewWriterSize(ipF, 16*1024)
		rf.ipPath = ipP
	}
	return rf, nil
}

func (rf *resultFile) write(line string) {
	if rf == nil {
		return
	}
	_, _ = fmt.Fprintln(rf.w, line)
	if rf.ipW != nil {
		if ipPort := ipPortRegex.FindString(line); ipPort != "" {
			_, _ = fmt.Fprintln(rf.ipW, ipPort)
		}
	}
}

// flush persists buffered results to disk without closing the file. Called after
// each chunk so passed IPs survive even if the app is killed mid-scan.
func (rf *resultFile) flush() {
	if rf == nil {
		return
	}
	_ = rf.w.Flush()
	_ = rf.f.Sync()
	if rf.ipW != nil {
		_ = rf.ipW.Flush()
		_ = rf.ipF.Sync()
	}
}

func (rf *resultFile) close() string {
	if rf == nil {
		return ""
	}
	_ = rf.w.Flush()
	_ = rf.f.Close()
	if rf.ipW != nil {
		_ = rf.ipW.Flush()
		_ = rf.ipF.Close()
	}
	return rf.path
}

// ── logFile ──────────────────────────────────────────────────────────────────
// Persists the scan's activity log to {dataDir}/logs/. Called from many probe
// goroutines, so writes are mutex-guarded. Very verbose engine lines (per-IP
// DEBUG/TRACE/SKIP/PROGRESS) are filtered out to keep the file manageable.

type logFile struct {
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	path string
}

func openLogFile(dataDir, kind string) *logFile {
	stamp := time.Now().Format("20060102-150405")
	p := filepath.Join(dataDir, "logs", fmt.Sprintf("scan-%s-%s.log", kind, stamp))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil
	}
	f, err := os.Create(p)
	if err != nil {
		return nil
	}
	return &logFile{f: f, w: bufio.NewWriterSize(f, 16*1024), path: p}
}

var verboseLogTags = []string{"[DEBUG]", "[TRACE]", "[SKIP]", "[PROGRESS]"}

func (lf *logFile) write(line string) {
	if lf == nil {
		return
	}
	for _, tag := range verboseLogTags {
		if strings.Contains(line, tag) {
			return // skip very chatty lines
		}
	}
	lf.mu.Lock()
	_, _ = fmt.Fprintln(lf.w, line)
	lf.mu.Unlock()
}

func (lf *logFile) close() {
	if lf == nil {
		return
	}
	lf.mu.Lock()
	_ = lf.w.Flush()
	_ = lf.f.Close()
	lf.mu.Unlock()
}

// ── helpers ──────────────────────────────────────────────────────────────────

func splitTargets(blob string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(blob, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		appendTargetLine(&out, line, 0)
	}
	return out
}

func appendTargetLine(out *[]string, line string, depth int) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if strings.HasPrefix(line, "@") {
		appendTargetsFromFile(out, strings.TrimSpace(strings.TrimPrefix(line, "@")), depth+1)
		return
	}
	for _, f := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ','
	}) {
		if f = strings.TrimSpace(f); f != "" {
			*out = append(*out, f)
		}
	}
}

func appendTargetsFromFile(out *[]string, path string, depth int) {
	if depth > 3 {
		return
	}
	path = strings.Trim(path, `"'`)
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	fileScanner := bufio.NewScanner(f)
	fileScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for fileScanner.Scan() {
		appendTargetLine(out, fileScanner.Text(), depth)
	}
	// Best-effort target-file reader with no caller-visible error channel (see
	// splitTargets/ExpandASNs callers); a read error here just means the target
	// list is truncated to whatever was read before it, which is already this
	// function's documented behavior for malformed lines.
	_ = fileScanner.Err()
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

func forceLiteRuntime() bool {
	return runtime.GOOS == "android" && (runtime.GOARCH == "arm" || runtime.GOARCH == "386")
}

func effectiveLiteMode(cfg *ScanConfig) bool {
	return (cfg != nil && cfg.LiteMode) || forceLiteRuntime()
}

func effectiveLowBandwidth(cfg *ScanConfig, liteMode bool) bool {
	return (cfg != nil && cfg.LowBandwidth) || liteMode
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

// Chunked-scan parameters. Instead of expanding every CIDR into RAM (which
// OOM-crashes on CDN-sized ranges), the IP scan streams all IPs to a file on
// disk, then scans them back a chunk at a time. This keeps RAM flat while
// preserving FULL coverage — no CIDRs or IPs are dropped.
const (
	chunkIPCount  = 4000  // IPs scanned per chunk (bounds per-chunk RAM)
	perCIDRMaxIPs = 65536 // matches the desktop engine's per-CIDR expansion cap

	// Lite mode (old / low-RAM devices): much smaller chunks and a hard low
	// concurrency cap to keep peak memory, fd usage and CPU minimal.
	liteChunkIPCount       = 512
	liteChunkEndpointCount = 1024
	liteMaxConcurrency     = 8

	// Staging de-duplication set caps (the only RAM cost while expanding targets
	// to disk). Normal mode dedups up to ~400k unique IPs (~25 MB); Lite mode
	// disables the staging set so big ASNs stage with almost no RAM on weak devices.
	stageDedupCap = 400_000
	liteDedupCap  = 0

	// Android 32-bit devices should still show an ASN list, but only need a
	// bounded first page in the picker to avoid a large Java/Kotlin string.
	liteASNSearchLimit = 80
)

// interChunkPause returns a short delay inserted between chunks so the scan does
// not hold the radio saturated continuously — gentler on the user's connection.
func interChunkPause(conc int) time.Duration {
	switch {
	case conc <= 10:
		return 500 * time.Millisecond
	case conc <= 25:
		return 250 * time.Millisecond
	case conc <= 50:
		return 100 * time.Millisecond
	default:
		return 0
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

// etaTracker estimates remaining time from the RECENT scan rate rather than the
// cumulative average since start. The cumulative average is badly skewed by the
// slow warm-up (health check, TLS handshakes, the first timeouts), which makes
// the ETA read absurdly high (e.g. "3000m") for the first minute. A sliding
// window over the last ~30s reflects the true steady-state pace.
type etaTracker struct {
	mu      sync.Mutex
	times   []time.Time
	counts  []int
	windowS float64
}

func newETATracker() *etaTracker { return &etaTracker{windowS: 30} }

func (e *etaTracker) eta(done, total int) int {
	if done <= 0 || done >= total {
		return 0
	}
	now := time.Now()
	e.mu.Lock()
	e.times = append(e.times, now)
	e.counts = append(e.counts, done)
	// Drop samples older than the window, always keeping at least one anchor.
	cutoff := now.Add(-time.Duration(e.windowS) * time.Second)
	drop := 0
	for drop < len(e.times)-1 && e.times[drop].Before(cutoff) {
		drop++
	}
	e.times = e.times[drop:]
	e.counts = e.counts[drop:]
	t0, c0 := e.times[0], e.counts[0]
	e.mu.Unlock()

	dt := now.Sub(t0).Seconds()
	dc := done - c0
	if dt <= 0 || dc <= 0 {
		return 0
	}
	rate := float64(dc) / dt // endpoints per second over the recent window
	return int(float64(total-done) / rate)
}

// ── IP / CIDR scan ───────────────────────────────────────────────────────────

// StartIPScan scans IP ranges with FULL coverage but flat memory. It streams
// every expanded IP to a temp file on disk, then scans the file back in small
// chunks — so a Cloudflare-sized range can be scanned without OOM-crashing the
// device. Results are written to {dataDir}/results/scan-ip-*.txt incrementally
// (so a stopped scan still keeps what it found).
func StartIPScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	sc := scanner.NewScanner(nil)
	if err := sc.ConfigureAntiDPI(cfg.AntiDPI, fragmentSize(cfg), cfg.DPIFragmentDelayMs); err != nil {
		h := newScanHandle(sc)
		go l.OnDone("", err.Error())
		return h
	}
	h := newScanHandle(sc)

	liteMode := effectiveLiteMode(cfg)
	lowBandwidth := effectiveLowBandwidth(cfg, liteMode)
	targets := splitTargets(cfg.Targets)
	ports := parsePortsCSV(cfg.Ports)
	conc := concurrencyOrDefault(cfg.Concurrency, 50) // phone default: 50 workers
	timeout := timeoutOrDefault(cfg.TimeoutMs, scanner.ScanTimeout, lowBandwidth)

	// Lite mode for old / low-RAM devices: smaller chunks, far lower concurrency,
	// sequential per-IP domain probing, and inter-chunk pauses. This keeps peak
	// memory, open file descriptors, and CPU low enough that the scan doesn't
	// OOM/ANR-crash on weak hardware. Coverage is unchanged — only resource use.
	chunkSize := chunkIPCount
	if liteMode {
		chunkSize = liteChunkIPCount
		if len(ports) > 0 {
			chunkSize = liteChunkEndpointCount / len(ports)
			if chunkSize < 1 {
				chunkSize = 1
			}
			if chunkSize > liteChunkIPCount {
				chunkSize = liteChunkIPCount
			}
		}
		if conc > liteMaxConcurrency {
			conc = liteMaxConcurrency
		}
	}

	sc.SetTargetPorts(ports)
	sc.SetVerboseProbeLogging(cfg.VerboseLog)

	lf := openLogFile(dataDir, "ip")
	logThrottle := newThrottle(250 * time.Millisecond)
	sc.SetLogCallback(func(msg string) {
		line := strings.TrimRight(msg, "\n")
		lf.write(line) // persist activity log to disk (filtered)
		if !h.isStopped() && logThrottle.allow() {
			l.OnLog(line)
		}
	})

	// Per-chunk options. DisableAutoConcurrency keeps worker count phone-safe.
	// No MaxIPs/MaxEndpoints caps — coverage is full; chunking bounds memory.
	//
	// Bandwidth is reduced WITHOUT changing results: lower worker concurrency,
	// inter-chunk pauses, and (for gentle/low-bandwidth modes) probing the
	// endpoint's domains one-at-a-time (AdaptiveDomainConcurrency=1). The full
	// probe-domain list is always used, so the same endpoints are found.
	edgeDomains := edgeProbeDomains(cfg)
	makeOpts := func() scanner.IPScanOptions {
		o := scanner.IPScanOptions{
			Ports:                  ports,
			Concurrency:            conc,
			Timeout:                timeout,
			LowBandwidth:           lowBandwidth,
			DisableAutoConcurrency: true,
			ProbeDomainsHTTP:       edgeDomains,
			ProbeDomainsHTTPS:      edgeDomains,
			RequiredProbeDomains:   edgeRequiredDomains(cfg),
			FastMode:               cfg.FastMode && !lowBandwidth && !liteMode,
		}
		if conc <= 25 || lowBandwidth || liteMode {
			o.AdaptiveDomainConcurrency = 1
		}
		return o
	}

	go func() {
		defer sc.SetLogCallback(nil)
		defer lf.close()
		if cfg.TargetType == "domain" {
			resolved, err := resolveDomainTargets(h.ctx, targets)
			if err != nil {
				l.OnDone("", err.Error())
				return
			}
			targets = resolved
		}

		// A bounded producer starts probes as soon as a chunk is ready. Counting
		// never blocks scanning; the exact total is published only when known.
		dedupCap := stageDedupCap
		if liteMode {
			dedupCap = liteDedupCap
		}
		var knownTotal, emittedTotal atomic.Int64
		source := make(chan string, chunkSize)
		producerCtx, cancelProducer := context.WithCancel(h.ctx)
		defer cancelProducer()
		expansionErr := make(chan error, 1)
		go func() {
			defer close(source)
			total, err := walkTargets(producerCtx, targets, dedupCap, func(line string) error {
				select {
				case source <- line:
					emittedTotal.Add(1)
					return nil
				case <-producerCtx.Done():
					return producerCtx.Err()
				}
			})
			if err == nil {
				knownTotal.Store(int64(total))
			}
			expansionErr <- err
		}()
		if cfg.CountTotal {
			go func() {
				total, err := walkTargets(producerCtx, targets, dedupCap, func(string) error { return nil })
				if err == nil {
					knownTotal.Store(int64(total))
				}
			}()
		}
		totalIPs, totalEndpoints := 0, 0
		lf.write(fmt.Sprintf("[IP-SCAN-START] streaming targets=%d ports=%d concurrency=%d lite=%v low_bandwidth=%v", len(targets), len(ports), conc, liteMode, lowBandwidth))
		rf, _ := openResultFile(dataDir, "ip")
		resultThrottle := newThrottle(250 * time.Millisecond)

		start := time.Now()
		etaEst := newETATracker()
		processedBase := 0 // endpoints fully scanned in prior chunks
		foundTotal := 0
		pause := interChunkPause(conc)

		// 2. Scan one chunk of IPs, writing accepted results to disk as we go.
		runChunk := func(chunk []string) {
			if len(chunk) == 0 {
				return
			}
			progressCb := func(processed, _ /*totalProbes*/, accepted int, currentIP string, _ int) {
				if !h.isStopped() {
					done := processedBase + processed
					l.OnProgress(done, int(knownTotal.Load())*len(ports), foundTotal+accepted, int(emittedTotal.Load()),
						currentIP, etaEst.eta(done, int(knownTotal.Load())*len(ports)))
				}
			}
			results, scanErr := sc.ScanIPsWithProgress(chunk, makeOpts(), progressCb)
			if scanErr == nil {
				for _, r := range results {
					rf.write(r)
					if resultThrottle.allow() {
						l.OnResult(r)
					}
				}
				foundTotal += len(results)
			}
			rf.flush() // persist this chunk's passed IPs immediately (survives a kill)
			processedBase += len(chunk) * len(ports)
		}

		chunk := make([]string, 0, chunkSize)
		for line := range source {
			if h.isStopped() {
				cancelProducer()
				break
			}
			for h.isPaused() && !h.isStopped() {
				time.Sleep(200 * time.Millisecond)
			}
			if h.isStopped() {
				cancelProducer()
				break
			}
			chunk = append(chunk, line)
			if len(chunk) >= chunkSize {
				runChunk(chunk)
				if pause > 0 {
					time.Sleep(pause)
				}
				chunk = chunk[:0]
			}
		}
		if !h.isStopped() {
			runChunk(chunk)
		}
		cancelProducer()
		if err := <-expansionErr; err != nil && !h.isStopped() {
			l.OnLog("[IP-SCAN] target expansion error: " + err.Error())
		}
		totalIPs = int(knownTotal.Load())
		if totalIPs == 0 {
			totalIPs = int(emittedTotal.Load())
		}
		totalEndpoints = totalIPs * len(ports)
		if totalIPs == 0 && !h.isStopped() {
			rf.close()
			l.OnDone("", "no IPs expanded from targets")
			return
		}
		l.OnProgress(processedBase, totalEndpoints, foundTotal, totalIPs, "", 0)

		// Whether the scan finished or was stopped, partial results are already on
		// disk — report success with the saved path so the Results screen shows
		// them (a user-initiated stop is not an error).
		reason := "completed"
		if h.isStopped() {
			reason = "stopped"
		}
		endMsg := fmt.Sprintf("[IP-SCAN-END] reason=%s staged_ips=%d processed_endpoints=%d/%d found=%d elapsed=%s",
			reason, totalIPs, processedBase, totalEndpoints, foundTotal, time.Since(start).Round(time.Second))
		lf.write(endMsg)
		l.OnLog(endMsg)

		savedPath := rf.close()
		l.OnDone(savedPath, "")
	}()
	return h
}

// expandTargetsToFile streams every IP from the given CIDRs/IPs to path, one per
// line, without holding the full set in RAM. ip:port targets and bare IPs pass
// through unchanged. Each CIDR is capped at perCIDRMaxIPs (matching the desktop
// engine) so a single huge prefix can't fill the disk. Returns the line count.
// expandTargetsToFile streams every IP to path. dedupCap bounds the size of the
// de-duplication set (its only RAM cost): once reached, the rest is emitted
// unfiltered so memory can never blow up. A single ASN's CIDRs don't overlap,
// so its dedup set finds nothing — Lite mode therefore passes a tiny cap (or 0
// to disable) to stage huge ASNs with almost no RAM, WITHOUT dropping any IPs.
func expandTargetsToFile(targets []string, path string, dedupCap int) (int, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return 0, err
	}
	file, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	writer := bufio.NewWriterSize(file, 64*1024)
	count, err := walkTargets(context.Background(), targets, dedupCap, func(line string) error { _, err := fmt.Fprintln(writer, line); return err })
	if err != nil {
		return count, err
	}
	if err = writer.Flush(); err != nil {
		return count, err
	}
	return count, file.Close()
}

func walkTargets(ctx context.Context, targets []string, dedupCap int, consume func(string) error) (int, error) {
	count := 0
	// IPv4 IPs and CIDRs become integer spans that are merged before streaming,
	// so overlapping CIDRs/ASNs (a /16 and a /24 inside it) are scanned once —
	// exactly, with no RAM-bounded seen-set — and each address is formatted
	// into one reusable buffer. Endpoints and IPv6 samples keep the seen-set,
	// which dedupCap <= 0 disables entirely (lowest RAM).
	var seen map[string]struct{}
	if dedupCap > 0 {
		seen = make(map[string]struct{}, 1024)
	}
	emit := func(line string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if seen != nil && len(seen) < dedupCap {
			if _, dup := seen[line]; dup {
				return nil
			}
			seen[line] = struct{}{}
		}
		if err := consume(line); err != nil {
			return err
		}
		count++
		return nil
	}
	var spans []asnexport.IPv4Span
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		// ip:port passthrough
		if host, _, err := net.SplitHostPort(t); err == nil && net.ParseIP(host) != nil {
			if err := emit(t); err != nil {
				return count, err
			}
			continue
		}
		// bare IP
		if ip := net.ParseIP(t); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				v := uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3])
				spans = append(spans, asnexport.IPv4Span{First: v, Last: v})
				continue
			}
			if err := emit(t); err != nil {
				return count, err
			}
			continue
		}
		_, ipnet, perr := net.ParseCIDR(t)
		if perr != nil {
			continue
		}
		span, ok := asnexport.IPv4SpanOf(ipnet)
		if !ok {
			for _, sample := range tlsprobe.ExpandTargets([]string{t}) {
				if err := emit(sample); err != nil {
					return count, err
				}
			}
			continue
		}
		if span.Last-span.First+1 > perCIDRMaxIPs { // same per-CIDR cap as before
			span.Last = span.First + perCIDRMaxIPs - 1
		}
		spans = append(spans, span)
	}
	buf := make([]byte, 0, 15)
	done := ctx.Done() // a non-blocking receive per address: Stop takes effect at once
	for _, span := range asnexport.MergeIPv4Spans(spans) {
		for v := span.First; v <= span.Last; v++ {
			select {
			case <-done:
				return count, ctx.Err()
			default:
			}
			if err := consume(string(asnexport.AppendIPv4(buf[:0], uint32(v)))); err != nil {
				return count, err
			}
			count++
		}
	}
	return count, nil
}

func expandTargetsLimited(targets []string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)
	emit := func(ip string) bool {
		if ip == "" {
			return len(out) >= limit
		}
		if _, ok := seen[ip]; ok {
			return len(out) >= limit
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
		return len(out) >= limit
	}

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(t); err == nil && net.ParseIP(host) != nil {
			if emit(host) {
				break
			}
			continue
		}
		if net.ParseIP(t) != nil {
			if emit(t) {
				break
			}
			continue
		}
		_, ipnet, err := net.ParseCIDR(t)
		if err != nil {
			continue
		}
		if ipnet.IP.To4() == nil {
			for _, sample := range tlsprobe.ExpandTargets([]string{t}) {
				if emit(sample) {
					return out
				}
			}
			continue
		}
		cur := make(net.IP, len(ipnet.IP))
		copy(cur, ipnet.IP.Mask(ipnet.Mask))
		emitted := 0
		for ipnet.Contains(cur) && emitted < perCIDRMaxIPs {
			if emit(cur.String()) {
				return out
			}
			emitted++
			incIP(cur)
		}
	}
	return out
}

// incIP increments an IP address (big-endian) by one, in place.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ── HTTP / SOCKS5 proxy scans ────────────────────────────────────────────────

func startProxyScan(dataDir, kind string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	sc := scanner.NewScanner(nil)
	if err := sc.ConfigureAntiDPI(cfg.AntiDPI, fragmentSize(cfg), cfg.DPIFragmentDelayMs); err != nil {
		h := newScanHandle(sc)
		go l.OnDone("", err.Error())
		return h
	}
	h := newScanHandle(sc)

	liteMode := effectiveLiteMode(cfg)
	lowBandwidth := effectiveLowBandwidth(cfg, liteMode)
	targets := splitTargets(cfg.Targets)
	conc := concurrencyOrDefault(cfg.Concurrency, 50)
	if liteMode && conc > liteMaxConcurrency {
		conc = liteMaxConcurrency
	}
	timeout := timeoutOrDefault(cfg.TimeoutMs, 8*time.Second, lowBandwidth)

	opts := scanner.ProxyScanOptions{
		Ports:         parsePortsOrEmpty(cfg.Ports),
		Discovery:     "direct",
		Concurrency:   conc,
		Timeout:       timeout,
		TransferModel: strings.TrimSpace(cfg.TransferModel),
		ProxyTestURL:  cfg.ProxyTestURL,
		LiteMode:      liteMode,
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

		// Only a real engine error is fatal. A user-initiated stop is NOT an error:
		// the scan returns whatever it found so far, and we persist it so the user
		// never loses partial results by stopping (there is no manual save on phone).
		if err != nil {
			l.OnDone("", err.Error())
			return
		}

		rf, _ := openResultFile(dataDir, kind)
		resultThrottle := newThrottle(250 * time.Millisecond)
		stopped := h.isStopped()
		for _, r := range results {
			rf.write(r)
			if !stopped && resultThrottle.allow() {
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
	liteMode := effectiveLiteMode(cfg)
	lowBandwidth := effectiveLowBandwidth(cfg, liteMode)
	targets := splitTargets(cfg.Targets)
	domains := splitTargets(cfg.SNIDomains)
	if len(domains) == 0 {
		domains = edgeProbeDomains(cfg)
	}
	if len(domains) == 0 {
		domains = tlsprobe.GetDomains(dataDir)
	}
	ports := parsePortsCSV(cfg.Ports)
	conc := concurrencyOrDefault(cfg.Concurrency, 50)
	if liteMode && conc > liteMaxConcurrency {
		conc = liteMaxConcurrency
	}
	timeout := timeoutOrDefault(cfg.TimeoutMs, scanner.ScanTimeout, lowBandwidth)

	go func() {
		if len(targets) == 0 || len(domains) == 0 {
			reason := "no IP targets selected"
			if len(domains) == 0 {
				reason = "no SNI domains selected"
			}
			l.OnDone("", reason)
			return
		}
		if liteMode {
			runLiteSNIScan(dataDir, cfg, l, h, targets, domains, ports, conc, timeout)
			return
		}

		rf, _ := openResultFile(dataDir, "sni")
		logThrottle := newThrottle(250 * time.Millisecond)
		resultThrottle := newThrottle(250 * time.Millisecond)

		resCh := make(chan tlsprobe.ProbeResult, 512)
		go func() {
			tlsprobe.RunScanContext(h.ctx, tlsprobe.ScanConfig{
				Targets:     targets,
				Hostnames:   domains,
				Ports:       ports,
				TimeoutSec:  timeout.Seconds(),
				Concurrency: conc,
				StrictSNI:   cfg.SNIStrict,
				PauseFunc:   h.isPaused,
			}, resCh, nil)
		}()

		expanded := len(tlsprobe.ExpandTargets(targets))
		if expanded == 0 {
			expanded = len(targets)
		}
		total := expanded * len(domains) * len(ports)
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

		// A stop is not an error: SNI passes are written to disk as they are found,
		// so return the saved path (not an error) and keep the partial results.
		l.OnDone(rf.close(), "")
	}()
	return h
}

// ── Speed & Loss rank ────────────────────────────────────────────────────────

func runLiteSNIScan(dataDir string, cfg *ScanConfig, l ScanListener, h *ScanHandle, targets, domains []string, ports []int, conc int, timeout time.Duration) {
	// A chunk costs IPs x domains x ports probes, so the port count has to be in
	// the divisor: sizing on domains alone makes a multi-port chunk that many
	// times heavier than the budget Lite mode exists to hold.
	chunkSize := liteChunkIPCount
	if probesPerIP := len(domains) * len(ports); probesPerIP > 0 {
		chunkSize = liteChunkEndpointCount / probesPerIP
		if chunkSize < 1 {
			chunkSize = 1
		}
		if chunkSize > liteChunkIPCount {
			chunkSize = liteChunkIPCount
		}
	}

	tmpPath := filepath.Join(dataDir, "tmp", fmt.Sprintf("sni-targets-%d.txt", time.Now().UnixNano()))
	totalIPs, err := expandTargetsToFile(targets, tmpPath, liteDedupCap)
	if err != nil {
		l.OnDone("", "could not stage SNI targets: "+err.Error())
		return
	}
	defer os.Remove(tmpPath)
	if totalIPs == 0 {
		l.OnDone("", "no IP targets selected")
		return
	}

	file, err := os.Open(tmpPath)
	if err != nil {
		l.OnDone("", err.Error())
		return
	}
	defer file.Close()

	rf, _ := openResultFile(dataDir, "sni")
	logThrottle := newThrottle(250 * time.Millisecond)
	resultThrottle := newThrottle(250 * time.Millisecond)
	total := totalIPs * len(domains) * len(ports)
	start := time.Now()
	processed, hits := 0, 0

	l.OnLog(fmt.Sprintf("[SNI-LITE-START] targets=%d staged_ips=%d domains=%d ports=%d total_probes=%d concurrency=%d",
		len(targets), totalIPs, len(domains), len(ports), total, conc))

	runChunk := func(chunk []string) {
		if len(chunk) == 0 || h.isStopped() {
			return
		}
		resCh := make(chan tlsprobe.ProbeResult, 128)
		go func() {
			tlsprobe.RunScanContext(h.ctx, tlsprobe.ScanConfig{
				Targets:     chunk,
				Hostnames:   domains,
				Ports:       ports,
				TimeoutSec:  timeout.Seconds(),
				Concurrency: conc,
				StrictSNI:   cfg.SNIStrict,
				PauseFunc:   h.isPaused,
			}, resCh, nil)
		}()

		for pr := range resCh {
			processed++
			if h.isStopped() {
				continue
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
			l.OnProgress(processed, total, hits, totalIPs, pr.IP,
				calcETA(start, processed, total))
		}
		rf.flush()
	}

	fileScanner := bufio.NewScanner(file)
	fileScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	chunk := make([]string, 0, chunkSize)
	for fileScanner.Scan() {
		if h.isStopped() {
			break
		}
		for h.isPaused() && !h.isStopped() {
			time.Sleep(200 * time.Millisecond)
		}
		line := strings.TrimSpace(fileScanner.Text())
		if line == "" {
			continue
		}
		chunk = append(chunk, line)
		if len(chunk) >= chunkSize {
			runChunk(chunk)
			chunk = chunk[:0]
			runtime.GC()
			time.Sleep(300 * time.Millisecond)
		}
	}
	if !h.isStopped() {
		runChunk(chunk)
	}
	if err := fileScanner.Err(); err != nil {
		l.OnLog("[SNI-LITE] staged-IP read error, coverage may be truncated: " + err.Error())
	}

	reason := "completed"
	if h.isStopped() {
		reason = "stopped"
	}
	l.OnLog(fmt.Sprintf("[SNI-LITE-END] reason=%s staged_ips=%d processed=%d/%d hits=%d elapsed=%s",
		reason, totalIPs, processed, total, hits, time.Since(start).Round(time.Second)))
	l.OnDone(rf.close(), "")
}

// maxSpeedRankIPs caps how many IPs are benchmarked on a phone. The speed test
// downloads/uploads several MB per IP, so this stays bounded rather than
// unlimited — but raised well past a typical found-IP shortlist so the "Speed
// Test" auto-chain toggle (which feeds a whole scan's accepted IPs in) isn't
// artificially truncated.
const maxSpeedRankIPs = 2000

// StartSpeedRankScan benchmarks each target IP with transfers pinned to that IP
// and ranks them by a
// composite of download/upload throughput, packet loss, and latency. Results
// are written best-first to {dataDir}/results/scan-speedrank-*.txt and a CSV is
// saved alongside. Mirrors the desktop TUI "Speed & Loss Rank" scan.
func StartSpeedRankScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	h := newScanHandle(nil)

	liteMode := effectiveLiteMode(cfg)
	lowBandwidth := effectiveLowBandwidth(cfg, liteMode)
	targets := splitTargets(cfg.Targets)
	ports := parsePortsOrEmpty(cfg.Ports)
	port := 443
	if len(ports) > 0 && ports[0] > 0 {
		port = ports[0]
	}
	conc := concurrencyOrDefault(cfg.Concurrency, 16)
	if liteMode && conc > 4 {
		conc = 4
	}
	timeout := timeoutOrDefault(cfg.TimeoutMs, 12*time.Second, lowBandwidth)

	go func() {
		var ips []string
		if liteMode {
			ips = expandTargetsLimited(targets, maxSpeedRankIPs)
		} else {
			ips = tlsprobe.ExpandTargets(targets)
		}
		if len(ips) == 0 {
			ips = targets
		}
		if len(ips) == 0 {
			l.OnDone("", "no IP targets selected")
			return
		}
		if len(ips) > maxSpeedRankIPs {
			l.OnLog(fmt.Sprintf("[SPEEDRANK] %d IPs given; benchmarking the first %d (speed test is heavy)", len(ips), maxSpeedRankIPs))
			ips = ips[:maxSpeedRankIPs]
		}

		rf, _ := openResultFile(dataDir, "speedrank")
		resultThrottle := newThrottle(250 * time.Millisecond)
		start := time.Now()
		total := len(ips)
		l.OnLog(fmt.Sprintf("[SPEEDRANK] Benchmarking %d IP(s) against each candidate IP (port %d, concurrency %d)", total, port, conc))

		opts := scanner.SpeedRankOptions{
			Port:        port,
			Concurrency: conc,
			Timeout:     timeout,
			SNI:         edgeSpeedSNI(cfg),
			PauseFunc:   h.isPaused,
		}
		progressCb := func(processed, totalIPs, reachable int, currentIP string) {
			if !h.isStopped() {
				l.OnProgress(processed, totalIPs, reachable, totalIPs, currentIP,
					calcETA(start, processed, totalIPs))
			}
		}

		results := scanner.SpeedRankIPs(h.ctx, ips, opts, progressCb)

		// Persist every ranked line to disk, but stream to the live UI only while
		// not stopped — otherwise a stop would keep emitting results/logs.
		stopped := h.isStopped()
		reachable := 0
		for i, r := range results {
			if r.Reachable {
				reachable++
			}
			line := scanner.FormatSpeedRankLine(i+1, r)
			rf.write(line)
			if !stopped && resultThrottle.allow() {
				l.OnResult(line)
			}
		}
		rf.flush()
		if csvPath, err := scanner.WriteSpeedRankCSV(dataDir, results); err == nil && !stopped {
			l.OnLog("[SPEEDRANK] Ranked CSV saved to " + csvPath)
		}
		if !stopped {
			l.OnLog(fmt.Sprintf("[SPEEDRANK] Done: %d reachable / %d total", reachable, total))
		}

		// A stop is not an error: every ranked line was already written to disk
		// above, so return the saved path so the user keeps their partial results.
		l.OnDone(rf.close(), "")
	}()
	return h
}

// ── DNS resolver / tunnel scan ───────────────────────────────────────────────

// StartDNSScan probes each resolver IP for open recursion, EDNS0 support, TXT
// passthrough, and answer-integrity (poisoning/hijack detection), then reports
// tunnel-readiness — mirrors the desktop TUI's "DNS Resolver / Tunnel Scan".
//
// Targets are streamed to disk and scanned back in bounded chunks exactly like
// StartIPScan, so a large CIDR/ASN of resolvers can't OOM the device. Lite mode
// additionally forces "Test Nearby IPs" off: every tunnel-ready hit would
// otherwise expand into a 256-address /24 rescan, which is unsafe to trigger
// unattended on weak hardware.
func StartDNSScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	h := newScanHandle(nil)

	liteMode := effectiveLiteMode(cfg)
	targets := splitTargets(cfg.Targets)
	ports := parsePortsOrEmpty(cfg.Ports)
	conc := concurrencyOrDefault(cfg.Concurrency, 64)
	if liteMode && conc > liteMaxConcurrency {
		conc = liteMaxConcurrency
	}
	timeout := timeoutOrDefault(cfg.TimeoutMs, 3*time.Second, cfg.LowBandwidth)

	protocol := strings.ToLower(strings.TrimSpace(cfg.DNSProtocol))
	switch protocol {
	case "udp", "tcp", "both", "all":
	default:
		protocol = "both"
	}
	reference := strings.ToLower(strings.TrimSpace(cfg.DNSReference))
	switch reference {
	case dnsscan.ReferenceGoogle, dnsscan.ReferenceCloudflare, dnsscan.ReferenceQuad9:
	default:
		reference = dnsscan.ReferenceGoogle
	}
	scanDepth := strings.ToLower(strings.TrimSpace(cfg.DNSScanDepth))
	if scanDepth != dnsscan.ScanDepthFast && scanDepth != dnsscan.ScanDepthThorough {
		scanDepth = dnsscan.ScanDepthFull
	}
	testNearby := cfg.DNSTestNearby && !liteMode

	opts := dnsscan.Options{
		TargetDomain:  "google.com",
		Timeout:       timeout,
		Concurrency:   conc,
		Protocol:      protocol,
		Ports:         ports,
		TruthProvider: reference,
		ScanDepth:     scanDepth,
	}
	if cfg.DNSRateLimit < 0 || cfg.DNSRateLimitPerResolver < 0 || cfg.DNSTimingJitter < 0 || cfg.DNSTimingJitter > 1 {
		go l.OnDone("", "DNS rate limit: use nonnegative rates and jitter 0–1")
		return h
	}
	// One limiter for every chunk, so chunk boundaries keep the spacing.
	scanCtx := dnsscan.WithRateLimiter(h.ctx, dnsscan.NewRateLimiter(cfg.DNSRateLimit, cfg.DNSRateLimitPerResolver, int(cfg.DNSRateBurst), cfg.DNSTimingJitter))

	chunkSize := chunkIPCount
	if liteMode {
		chunkSize = liteChunkIPCount
	}

	go func() {
		if len(targets) == 0 {
			l.OnDone("", "no resolver IPs/CIDRs selected")
			return
		}

		dedupCap := stageDedupCap
		if liteMode {
			dedupCap = liteDedupCap
		}
		tmpPath := filepath.Join(dataDir, "tmp", fmt.Sprintf("dns-targets-%d.txt", time.Now().UnixNano()))
		totalIPs, err := expandTargetsToFile(targets, tmpPath, dedupCap)
		if err != nil {
			l.OnDone("", "could not stage resolver targets: "+err.Error())
			return
		}
		defer os.Remove(tmpPath)
		if totalIPs == 0 {
			l.OnDone("", "no resolver IPs expanded from targets")
			return
		}

		file, err := os.Open(tmpPath)
		if err != nil {
			l.OnDone("", err.Error())
			return
		}
		defer file.Close()

		lf := openLogFile(dataDir, "dns")
		logThrottle := newThrottle(250 * time.Millisecond)
		resultThrottle := newThrottle(250 * time.Millisecond)
		start := time.Now()
		etaEst := newETATracker()
		processedBase := 0
		passedTotal := 0
		var all []dnsscan.ResolverResult

		// Allocate the stable Android DNS report set (txt + csv + html + xlsx +
		// json) for this scan in its own "dns scan" folder. Each chunk overwrites
		// these same paths so stopped/killed scans retain their progress without
		// producing a new timestamped batch of files.
		outDir := filepath.Join(dataDir, "dns scan")
		reportPaths, reportPathErr := dnsscan.NewMobileReportPaths(outDir)
		if reportPathErr != nil {
			lf.write("[DNS] report setup failed: " + reportPathErr.Error())
			lf.close()
			l.OnDone("", "report setup failed: "+reportPathErr.Error())
			return
		}
		var lastSavedPath string
		flushReports := func() {
			if err := dnsscan.WriteMobileReports(reportPaths, all); err == nil {
				lastSavedPath = reportPaths.Detailed
			} else {
				lf.write("[DNS] report flush failed: " + err.Error())
			}
		}

		stagedMsg := fmt.Sprintf("[DNS-SCAN-START] targets=%d staged_ips=%d protocol=%s depth=%s reference=%s concurrency=%d lite=%v nearby=%v",
			len(targets), totalIPs, protocol, scanDepth, reference, conc, liteMode, testNearby)
		lf.write(stagedMsg)
		l.OnLog(stagedMsg)
		flushReports() // create the folder + empty reports immediately, before any resolver completes

		// progress is invoked from a single goroutine per ScanResolvers call (see
		// dnsscan.ScanResolvers doc), so passedTotal/processedBase need no locking.
		makeProgress := func(totalForETA int) func(done, tot int, r dnsscan.ResolverResult) {
			return func(done, _ int, r dnsscan.ResolverResult) {
				passed := r.Passed()
				if passed {
					passedTotal++
				}
				if h.isStopped() {
					return
				}
				status := "no-response"
				if r.Responded {
					status = fmt.Sprintf("resp %dms", r.BestLatency.Milliseconds())
				}
				line := fmt.Sprintf("%-39s %-13s verdict=%s score=%d/6 tunnel=%v via=%s (%s)",
					r.IP, status, r.Status, r.Score, r.TunnelReady, r.TunnelTransport, r.TunnelReason)
				line += fmt.Sprintf(" path=%s fallback=%s udp_poison=%v tcp_poison=%v",
					r.PreferredTransport, r.FallbackTransport, r.UDPPoisoned, r.TCPPoisoned)
				if r.PoisonIP != "" {
					line += " poison_ip=" + r.PoisonIP
				}
				if r.HijackIP != "" {
					line += " hijack_ip=" + r.HijackIP
				}
				if r.HijackReason != "" {
					line += fmt.Sprintf(" hijack=%s:%s", r.HijackConfidence, r.HijackReason)
				}
				lf.write(line)
				if logThrottle.allow() {
					l.OnLog(line)
				}
				if passed && resultThrottle.allow() {
					l.OnResult(line)
				}
				doneTotal := processedBase + done
				l.OnProgress(doneTotal, totalForETA, passedTotal, totalForETA, r.IP, etaEst.eta(doneTotal, totalForETA))
			}
		}

		runChunk := func(chunk []string) {
			if len(chunk) == 0 {
				return
			}
			results := dnsscan.ScanResolvers(scanCtx, chunk, opts, makeProgress(totalIPs))
			all = append(all, results...)
			processedBase += len(chunk)
			flushReports() // persist this chunk's results immediately (survives a kill)
		}

		fileScanner := bufio.NewScanner(file)
		fileScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		chunk := make([]string, 0, chunkSize)
		for fileScanner.Scan() {
			if h.isStopped() {
				break
			}
			for h.isPaused() && !h.isStopped() {
				time.Sleep(200 * time.Millisecond)
			}
			line := strings.TrimSpace(fileScanner.Text())
			if line == "" {
				continue
			}
			chunk = append(chunk, line)
			if len(chunk) >= chunkSize {
				runChunk(chunk)
				chunk = chunk[:0]
				if liteMode {
					// Reclaim the chunk's memory promptly, same as StartIPScan.
					runtime.GC()
					time.Sleep(300 * time.Millisecond)
				}
			}
		}
		if !h.isStopped() {
			runChunk(chunk)
		}
		if err := fileScanner.Err(); err != nil {
			warnMsg := "[DNS-SCAN] staged resolver-IP read error, coverage may be truncated: " + err.Error()
			lf.write(warnMsg)
			l.OnLog(warnMsg)
		}

		// Test Nearby IPs: expand the /24 around each tunnel-ready resolver and
		// rescan the addresses not already tried (desktop TUI parity). Forced off
		// in Lite mode (see doc comment above).
		if testNearby && !h.isStopped() {
			scanned := make(map[string]struct{}, totalIPs)
			if file2, err := os.Open(tmpPath); err == nil {
				sc2 := bufio.NewScanner(file2)
				sc2.Buffer(make([]byte, 0, 64*1024), 1024*1024)
				for sc2.Scan() {
					if t := strings.TrimSpace(sc2.Text()); t != "" {
						scanned[t] = struct{}{}
					}
				}
				if err := sc2.Err(); err != nil {
					// Only affects dedup: a partial "already scanned" set means a few
					// addresses might be redundantly rescanned below, never dropped.
					l.OnLog("[DNS-NEARBY] dedup read error (may rescan a few addresses): " + err.Error())
				}
				file2.Close()
			}
			var nearby []string
			for _, r := range all {
				if !r.Passed() {
					continue
				}
				for _, nip := range dnsscan.NearbyIPs(r.IP) {
					if _, ok := scanned[nip]; ok {
						continue
					}
					scanned[nip] = struct{}{}
					nearby = append(nearby, nip)
				}
			}
			if len(nearby) > 0 {
				nearbyMsg := fmt.Sprintf("[DNS-NEARBY] expanding %d address(es) around tunnel-ready hits", len(nearby))
				lf.write(nearbyMsg)
				l.OnLog(nearbyMsg)
				base := processedBase
				totalWithNearby := base + len(nearby)
				for i := 0; i < len(nearby) && !h.isStopped(); i += chunkSize {
					end := i + chunkSize
					if end > len(nearby) {
						end = len(nearby)
					}
					sub := nearby[i:end]
					results := dnsscan.ScanResolvers(scanCtx, sub, opts, makeProgress(totalWithNearby))
					for j := range results {
						results[j].Nearby = true
					}
					all = append(all, results...)
					processedBase += len(sub)
					flushReports()
				}
			}
		}

		reason := "completed"
		if h.isStopped() {
			reason = "stopped"
		}
		endMsg := fmt.Sprintf("[DNS-SCAN-END] reason=%s scanned=%d passed_clean=%d elapsed=%s",
			reason, len(all), passedTotal, time.Since(start).Round(time.Second))
		lf.write(endMsg)
		l.OnLog(endMsg)
		lf.close()

		// Whether the scan finished or was stopped, everything gathered so far is
		// already flushed to outDir via flushReports() — a user-initiated stop is
		// not an error (matches every other scan kind's behavior). One final flush
		// picks up anything scanned since the last chunk boundary.
		flushReports()
		if lastSavedPath == "" {
			l.OnDone("", "report write failed")
			return
		}
		l.OnDone(lastSavedPath, "")
	}()
	return h
}

// ── DNSTT end-to-end tunnel test ─────────────────────────────────────────────

// e2eTransportSupported reports whether the requested E2E transport is wired up.
// UDP/53 and TCP/53 are implemented; dot/doh are accepted by the UI (gated) but
// rejected here so the backend can never attempt an unimplemented transport.
func e2eTransportSupported(transport string) bool {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "", "udp", "tcp":
		return true
	default:
		return false
	}
}

// e2eTransportOption maps a transport string to the engine transport.
func e2eTransportOption(transport string) e2e.Transport {
	if strings.ToLower(strings.TrimSpace(transport)) == "tcp" {
		return e2e.TransportTCP
	}
	return e2e.TransportUDP
}

// StartE2EScan validates a resolver shortlist end-to-end by bringing up a real
// DNSTT tunnel through each resolver against the operator's DNSTT server
// (cfg.E2EDomain + cfg.E2EPubKey) and fetching cfg.E2EURL over it. cfg.Targets
// holds the resolver list (one per line — typically the tunnel-ready shortlist
// from a prior DNS scan). Only resolvers that carry an HTTP 2xx/3xx round-trip
// are reported as passed. Results/logs stream via the listener exactly like the
// other scans, and the passed resolver IPs are written to disk.
func StartE2EScan(dataDir string, cfg *ScanConfig, l ScanListener) *ScanHandle {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	h := newScanHandle(nil)

	domain := strings.TrimSpace(cfg.E2EDomain)
	transport := strings.ToLower(strings.TrimSpace(cfg.E2ETransport))
	if transport == "" {
		transport = "udp"
	}
	resolvers := splitTargets(cfg.Targets)

	liteMode := effectiveLiteMode(cfg)
	conc := concurrencyOrDefault(cfg.Concurrency, 4)
	// Tunnel setup is heavy; keep concurrency modest and lower still on weak devices.
	if conc > 8 {
		conc = 8
	}
	if liteMode && conc > 2 {
		conc = 2
	}
	timeout := timeoutOrDefault(cfg.TimeoutMs, 20*time.Second, cfg.LowBandwidth)

	go func() {
		if domain == "" {
			l.OnDone("", "no DNSTT domain provided")
			return
		}
		if !e2eTransportSupported(transport) {
			l.OnDone("", fmt.Sprintf("transport %q not yet supported (UDP only for now)", transport))
			return
		}
		if len(resolvers) == 0 {
			l.OnDone("", "no resolvers to test")
			return
		}

		opts := e2e.Options{
			Domain:      domain,
			PubKey:      strings.TrimSpace(cfg.E2EPubKey),
			Transport:   e2eTransportOption(transport),
			Timeout:     timeout,
			Concurrency: conc,
			E2EURL:      strings.TrimSpace(cfg.E2EURL),
		}

		lf := openLogFile(dataDir, "e2e")
		logThrottle := newThrottle(250 * time.Millisecond)
		resultThrottle := newThrottle(250 * time.Millisecond)
		start := time.Now()
		total := len(resolvers)

		startMsg := fmt.Sprintf("[E2E-START] resolvers=%d domain=%s transport=%s key=%v concurrency=%d",
			total, domain, transport, opts.PubKey != "", conc)
		lf.write(startMsg)
		l.OnLog(startMsg)

		var passed int
		progress := func(done, tot int, r e2e.Result) {
			if h.isStopped() {
				return
			}
			line := fmt.Sprintf("%-21s %-4s %s", r.Resolver, boolYN(r.OK), r.Reason)
			lf.write(line)
			if r.OK {
				passed++
				if resultThrottle.allow() {
					l.OnResult(r.Resolver)
				}
			}
			if logThrottle.allow() {
				l.OnLog(line)
			}
			l.OnProgress(done, tot, passed, total, r.Resolver, calcETA(start, done, tot))
		}

		results := e2e.Run(h.ctx, resolvers, opts, dnstt.NewValidator(), progress)

		// Persist the passed (end-to-end validated) resolvers as a clean list.
		rf, _ := openResultFile(dataDir, "e2e")
		for _, r := range e2e.PassedResolvers(results) {
			rf.write(r)
		}
		rf.flush()

		reason := "completed"
		if h.isStopped() {
			reason = "stopped"
		}
		endMsg := fmt.Sprintf("[E2E-END] reason=%s tested=%d passed=%d elapsed=%s",
			reason, total, passed, time.Since(start).Round(time.Second))
		lf.write(endMsg)
		l.OnLog(endMsg)
		lf.close()

		l.OnDone(rf.close(), "")
	}()
	return h
}

func boolYN(v bool) string {
	if v {
		return "PASS"
	}
	return "fail"
}

// TunnelReadyIPsPath derives the clean passed-IP list written alongside an
// Android DNS scan report. New reports use dns-results-<ts>.txt plus the raw
// dns-passed-raw-<ts>.txt companion. The legacy desktop names remain supported
// so existing callers and old reports keep working.
func TunnelReadyIPsPath(dnsReportPath string) string {
	dnsReportPath = strings.TrimSpace(dnsReportPath)
	if dnsReportPath == "" {
		return ""
	}
	dir := filepath.Dir(dnsReportPath)
	base := filepath.Base(dnsReportPath)
	var candidate string
	switch {
	case strings.HasPrefix(base, "dns-results-"):
		candidate = filepath.Join(dir, "dns-passed-raw-"+strings.TrimPrefix(base, "dns-results-"))
	case strings.HasPrefix(base, "dns_scan_"):
		candidate = filepath.Join(dir, "tunnel_ready_ips_"+strings.TrimPrefix(base, "dns_scan_"))
	default:
		return ""
	}
	info, err := os.Stat(candidate)
	if err != nil || info.Size() == 0 {
		return ""
	}
	return candidate
}

// ── ASN export & search ──────────────────────────────────────────────────────

// ExportASN expands all ASNs matching query into a flat IP list on disk under
// {dataDir}/asn_exports/. Returns the output file path.
func ExportASN(dataDir, query string) (string, error) {
	eng := cachedASNEngine(dataDir)
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

// ExpandASNs expands picker ASN identifiers to scan targets. Plain input keeps
// the legacy IPv4 behavior; the GUI may prepend an ASN-family control prefix.
func ExpandASNs(dataDir, asnIDs string) (string, error) {
	family, asnIDs := parseASNFamilyQuery(asnIDs)
	eng := cachedASNEngine(dataDir)
	var loadErr error
	if family == "ipv4" {
		loadErr = eng.LoadIPv4()
	} else {
		loadErr = eng.Load()
	}
	if loadErr != nil {
		return "", loadErr
	}
	ids := splitTargets(asnIDs)
	if len(ids) == 0 {
		return "", fmt.Errorf("no ASNs given")
	}
	cidrs, err := eng.CIDRsForASNs(ids, family)
	if err != nil {
		return "", err
	}
	if len(cidrs) == 0 {
		return "", fmt.Errorf("no %s CIDRs found for the selected ASN(s)", family)
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

const (
	asnPageQueryPrefix   = "__WHITEDNS_ASN_PAGE__\t"
	asnFamilyQueryPrefix = "__WHITEDNS_ASN_FAMILY__\t"
)

func parseASNFamilyQuery(value string) (family, rest string) {
	if !strings.HasPrefix(value, asnFamilyQueryPrefix) {
		return "ipv4", value
	}
	familyText, rest, ok := strings.Cut(strings.TrimPrefix(value, asnFamilyQueryPrefix), "\t")
	if !ok {
		return "ipv4", value
	}
	switch strings.ToLower(strings.TrimSpace(familyText)) {
	case "ipv6", "v6":
		return "ipv6", rest
	case "both", "all", "dual":
		return "both", rest
	default:
		return "ipv4", rest
	}
}

func parseASNSearchQuery(query string, defaultLimit int) (string, int, int) {
	if !strings.HasPrefix(query, asnPageQueryPrefix) {
		return query, 0, defaultLimit
	}

	rest := strings.TrimPrefix(query, asnPageQueryPrefix)
	offsetText, rest, ok := strings.Cut(rest, "\t")
	if !ok {
		return query, 0, defaultLimit
	}
	limitText, actualQuery, ok := strings.Cut(rest, "\t")
	if !ok {
		return query, 0, defaultLimit
	}

	offset, err := strconv.Atoi(offsetText)
	if err != nil || offset < 0 {
		offset = 0
	}
	limit, err := strconv.Atoi(limitText)
	if err != nil || limit <= 0 {
		limit = defaultLimit
	}
	if limit <= 0 {
		limit = liteASNSearchLimit
	}
	if limit > 500 {
		limit = 500
	}
	return actualQuery, offset, limit
}

// ASNSearch returns matching ASNs as newline-separated
// "ASN\tName\tsubnetCount" rows. An optional family control prefix selects
// IPv4, IPv6, or both; unprefixed calls retain the legacy IPv4 behavior.
func ASNSearch(dataDir, query string) (string, error) {
	limit := 0
	if forceLiteRuntime() {
		limit = liteASNSearchLimit
	}
	family, query := parseASNFamilyQuery(query)
	query, offset, limit := parseASNSearchQuery(query, limit)
	return asnSearchRowsFamily(dataDir, query, limit, offset, family)
}

func asnSearchRows(dataDir, query string, limit int, offset int) (string, error) {
	return asnSearchRowsFamily(dataDir, query, limit, offset, "ipv4")
}

func asnSearchRowsFamily(dataDir, query string, limit int, offset int, family string) (string, error) {
	eng := cachedASNEngine(dataDir)
	var loadErr error
	if family == "ipv4" {
		loadErr = eng.LoadIPv4()
	} else {
		loadErr = eng.Load()
	}
	if loadErr != nil {
		return "", loadErr
	}
	searchLimit := limit
	if offset > 0 && limit > 0 {
		searchLimit = offset + limit
	}
	groups, err := eng.SearchSummariesFamily(query, searchLimit, family)
	if err != nil {
		return "", err
	}
	if offset > 0 {
		if offset >= len(groups) {
			groups = nil
		} else {
			groups = groups[offset:]
		}
	}
	if limit > 0 && len(groups) > limit {
		groups = groups[:limit]
	}
	var b strings.Builder
	for _, g := range groups {
		fmt.Fprintf(&b, "%s\t%s\t%d\n", g.ASN, g.Name, g.SubnetCount)
	}
	return b.String(), nil
}

func fragmentSize(cfg *ScanConfig) int {
	if cfg.DPIFragmentSize < 1 {
		return 64
	}
	return cfg.DPIFragmentSize
}
