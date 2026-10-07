package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"whitedns-go/internal/antidpi"
)

const (
	defaultHTTPScanTimeout   = 8 * time.Second
	defaultSOCKS5ScanTimeout = 5 * time.Second
	// maxProxyIPsPerRange bounds how many addresses one target range contributes
	// to direct discovery. Candidates are held in memory as ip:port strings, so
	// an uncapped /8 across eight ports is ~130M strings and an OOM.
	// ponytail: a flat cap, not a sampler — raise it if wide ranges matter more
	// than the memory ceiling.
	maxProxyIPsPerRange = 65536
)

// Default and extended port lists must match Python scanner.py exactly
var defaultHTTPProxyPorts = []int{80, 8080, 3128, 8000, 8888, 8118, 8081, 8123}
var extendedHTTPProxyPorts = []int{80, 443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083, 8123, 8443, 8888, 8889, 3128, 3129, 8118, 8119, 9000, 9001, 9090, 9091, 9999, 1080, 1081, 1082, 1083, 1085, 9050, 9051, 10808}
var defaultSOCKS5ProxyPorts = []int{1080, 1081, 1082, 1083, 1085, 3128, 8080, 8118, 9050, 9051, 10808}

const (
	httpWave1Timeout     = 2 * time.Second
	httpWave2Timeout     = 4 * time.Second
	httpWave3Timeout     = 8 * time.Second
	httpWave3Limit       = 8192
	httpWave1Concurrency = 4000
	httpWave2Concurrency = 1000
	httpWave3Concurrency = 200
)

// waveTimeouts derives per-wave verification deadlines from a base timeout so
// that low-bandwidth / high-latency users (who configure a larger timeout) are
// not rejected by the short hard-coded windows. With the default 8s base this
// reproduces the historical 2s/4s/8s waves exactly.
func waveTimeouts(base time.Duration) (w1, w2, w3 time.Duration) {
	if base <= 0 {
		base = defaultHTTPScanTimeout
	}
	w3 = base
	w2 = base / 2
	w1 = base / 4
	if w1 < httpWave1Timeout {
		w1 = httpWave1Timeout
	}
	if w2 < w1 {
		w2 = w1
	}
	if w3 < w2 {
		w3 = w2
	}
	return
}

var (
	exampleDomainSig = []byte("Example Domain")
)

// ProxyScanOptions controls discovery and verification of HTTP/SOCKS5 proxies.
type ProxyScanOptions struct {
	ProxyTestURL string
	Ports        []int
	Discovery    string
	Concurrency  int
	Timeout      time.Duration
	// TransferModel selects which transfer benchmark implementation to use.
	// Valid values: "old" (default) or "brrr" (new fast model).
	TransferModel string
	// LiteMode uses the bounded worker verifier for HTTP proxy scans instead of
	// the high-fanout desktop wave pipeline.
	LiteMode bool
}

type ProxyScanResult struct {
	Protocol     string
	Endpoint     string
	Latency      time.Duration
	DownloadKBps float64
	UploadKBps   float64
	Tags         []string
}

type proxyVerifier interface {
	verify(endpoint string, timeout time.Duration) bool
	defaultPorts() []int
	defaultTimeout() time.Duration
}

type httpVerifier struct {
	dpi     antidpi.Options
	testURL string
}

func (httpVerifier) defaultPorts() []int           { return defaultHTTPProxyPorts }
func (httpVerifier) defaultTimeout() time.Duration { return defaultHTTPScanTimeout }

type socks5Verifier struct {
	dpi     antidpi.Options
	testURL string
}

func (socks5Verifier) defaultPorts() []int           { return defaultSOCKS5ProxyPorts }
func (socks5Verifier) defaultTimeout() time.Duration { return defaultSOCKS5ScanTimeout }

// ScanHTTPProxies discovers and verifies HTTP proxies without touching routing state.
func (s *Scanner) ScanHTTPProxies(rawTargets []string, opts ProxyScanOptions) ([]string, error) {
	results, err := s.scanProxies(rawTargets, opts, httpVerifier{dpi: s.antiDPIOptions(), testURL: opts.ProxyTestURL})
	return formatProxyScanResults(results), err
}

// ScanSOCKS5Proxies discovers and verifies SOCKS5 proxies without touching routing state.
func (s *Scanner) ScanSOCKS5Proxies(rawTargets []string, opts ProxyScanOptions) ([]string, error) {
	results, err := s.scanProxies(rawTargets, opts, socks5Verifier{dpi: s.antiDPIOptions(), testURL: opts.ProxyTestURL})
	return formatProxyScanResults(results), err
}

func (s *Scanner) scanProxies(rawTargets []string, opts ProxyScanOptions, verifier proxyVerifier) ([]ProxyScanResult, error) {
	if len(rawTargets) == 0 {
		return []ProxyScanResult{}, nil
	}

	ports := append([]int(nil), opts.Ports...)
	if len(ports) == 0 {
		ports = verifier.defaultPorts()
	}

	discovery := strings.ToLower(strings.TrimSpace(opts.Discovery))
	if discovery == "" {
		discovery = "masscan"
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 500
	}
	if concurrency > 10000 {
		concurrency = 10000
	}
	// Clamp to the OS file-descriptor limit so Termux/Android (default
	// RLIMIT_NOFILE ~1024) does not exhaust its fd table and fail every dial.
	if fdCap := maxSafeConcurrency(); fdCap > 0 && concurrency > fdCap {
		s.logf("[DEBUG] scanProxies: capping concurrency %d -> %d (fd limit)\n", concurrency, fdCap)
		concurrency = fdCap
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = verifier.defaultTimeout()
	}
	healthSummary := s.ensureTransportHealthy(context.Background(), "proxy-scan", nil, timeout, 1)
	// Skip the pause-monitor when health sites were unreachable at startup so a
	// device that simply cannot reach them (e.g. Termux abroad) is not stalled
	// by false "outage" pauses mid-scan.
	stopHealthMonitor := func() {}
	if healthSummary.Reachable >= 1 {
		stopHealthMonitor = s.startTransportHealthMonitor(context.Background(), "proxy-scan", nil, timeout, 1)
	} else {
		s.logf("[HEALTH] proxy-scan health sites unreachable at startup; running without the pause-monitor\n")
	}
	defer stopHealthMonitor()

	// Log AFTER all variables are defined
	s.logf("[TRACE] scanProxies: targets=%d discovery=%s ports=%v concurrency=%d timeout=%s\n", len(rawTargets), discovery, ports, concurrency, timeout.String())

	s.logf("[TRACE] scanProxies: about to call collectProxyCandidates\n")
	candidates, err := s.collectProxyCandidates(rawTargets, ports, discovery)
	s.logf("[TRACE] scanProxies: collectProxyCandidates returned candidates=%d err=%v\n", len(candidates), err)
	if err != nil {
		s.logf("[ERROR] collectProxyCandidates failed: %v\n", err)
		return nil, err
	}
	if len(candidates) == 0 {
		s.logf("[TRACE] scanProxies: no candidates, returning empty\n")
		return []ProxyScanResult{}, nil
	}
	if _, isHTTP := verifier.(httpVerifier); isHTTP {
		s.logf("[TRACE] scanProxies: shuffling HTTP candidates\n")
		rand.Shuffle(len(candidates), func(i, j int) {
			candidates[i], candidates[j] = candidates[j], candidates[i]
		})
	}

	s.logf("[TRACE] scanProxies: about to call scanProxyCandidates with %d candidates\n", len(candidates))
	verified := s.scanProxyCandidates(candidates, concurrency, timeout, verifier, opts.TransferModel, opts.LiteMode)
	s.logf("[TRACE] scanProxies: scanProxyCandidates returned %d verified\n", len(verified))
	return deduplicateProxyResults(verified), nil
}

func (s *Scanner) collectProxyCandidates(rawTargets []string, ports []int, discovery string) ([]string, error) {
	s.logf("[DEBUG] collectProxyCandidates: discovery=%s targets=%d ports=%d\n", discovery, len(rawTargets), len(ports))
	switch discovery {
	case "direct":
		s.logf("[DEBUG] using direct method (no external tool)\n")
		var candidates []string
		rangeTargets := make([]string, 0, len(rawTargets))
		for _, target := range rawTargets {
			target = strings.TrimSpace(target)
			if host, portText, err := net.SplitHostPort(target); err == nil {
				port, err := strconv.Atoi(portText)
				if net.ParseIP(host) != nil && err == nil && port > 0 && port <= 65535 {
					candidates = append(candidates, hostPort(host, port))
				}
				continue
			}
			rangeTargets = append(rangeTargets, target)
		}
		ranges := ParseIPRanges(rangeTargets)
		s.logf("[DEBUG] parsed %d IP ranges\n", len(ranges))
		if len(ranges) == 0 {
			return deduplicateEndpoints(candidates), nil
		}
		skipped := 0
		for _, r := range ranges {
			start, end, ok := rangeBounds(r)
			if !ok {
				// IPv6 and malformed ranges cannot be walked as IPv4; scanning
				// whatever ipToInt made of them would probe unrelated hosts.
				skipped++
				continue
			}
			if span := end - start + 1; span > maxProxyIPsPerRange {
				s.logf("[DEBUG] direct discovery: capping range %v-%v at %d IPs\n", r.Start, r.End, maxProxyIPsPerRange)
				end = start + maxProxyIPsPerRange - 1
			}
			for current := start; current <= end; current++ {
				ip := ipv4String(current)
				shuffledPorts := append([]int(nil), ports...)
				if len(shuffledPorts) > 1 {
					rand.Shuffle(len(shuffledPorts), func(i, j int) {
						shuffledPorts[i], shuffledPorts[j] = shuffledPorts[j], shuffledPorts[i]
					})
				}
				for _, port := range shuffledPorts {
					candidates = append(candidates, hostPort(ip, port))
				}
			}
		}
		if skipped > 0 {
			s.logf("[!] direct discovery skipped %d non-IPv4 target range(s)\n", skipped)
		}
		s.logf("[DEBUG] direct method generated %d candidates\n", len(candidates))
		return deduplicateEndpoints(candidates), nil
	case "nmap":
		s.logf("[DEBUG] using nmap discovery\n")
		return s.withTargetPorts(ports, func() ([]string, error) {
			endpoints, err := s.NmapPreflight(rawTargets, false)
			s.logf("[DEBUG] nmap returned %d endpoints, err=%v\n", len(endpoints), err)
			return endpoints, err
		})
	default:
		s.logf("[DEBUG] using masscan discovery\n")
		return s.withTargetPorts(ports, func() ([]string, error) {
			endpoints, err := s.MasscanPreflight(rawTargets, false)
			s.logf("[DEBUG] masscan returned %d endpoints, err=%v\n", len(endpoints), err)
			return endpoints, err
		})
	}
}

func (s *Scanner) withTargetPorts(ports []int, fn func() ([]string, error)) ([]string, error) {
	if len(ports) == 0 || s == nil || s.config == nil {
		return fn()
	}

	oldPorts := append([]int(nil), s.config.TargetPorts...)
	s.config.TargetPorts = append([]int(nil), ports...)
	defer func() {
		s.config.TargetPorts = oldPorts
	}()

	return fn()
}

func (s *Scanner) scanProxyCandidates(candidates []string, concurrency int, timeout time.Duration, verifier proxyVerifier, transferModel string, liteMode bool) []ProxyScanResult {
	if v, ok := verifier.(httpVerifier); ok && v.dpi.Enabled {
		liteMode = true
	}
	total := len(candidates)
	if total == 0 {
		return []ProxyScanResult{}
	}

	// For HTTP proxies, use optimized 3-wave pipeline
	if _, isHTTP := verifier.(httpVerifier); isHTTP && !liteMode {
		s.logf("[TRACE] scanProxyCandidates: Using 3-wave HTTP proxy pipeline for %d candidates\n", total)
		return s.scanProxyCandidatesWave3(candidates, concurrency, timeout, transferModel)
	}

	// Lite HTTP and SOCKS5 use bounded worker verification.
	protocol := proxyProtocolLabel(verifier)
	s.logf("[DEBUG] scanProxyCandidates start (%s): total=%d concurrency=%d timeout=%s lite=%v\n", protocol, total, concurrency, timeout.String(), liteMode)
	s.reportProxyProgress(0, total, 0, "", total)
	if concurrency > total {
		concurrency = total
	}

	var mu sync.Mutex
	var verified []ProxyScanResult
	var completed atomic.Int64
	var hits atomic.Int64

	jobs := make(chan string, concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for endpoint := range jobs {
				if !s.waitWhilePaused() {
					completed.Add(1)
					continue
				}
				start := time.Now()
				if verifier.verify(endpoint, timeout) {
					result := ProxyScanResult{
						Protocol: proxyProtocolLabel(verifier),
						Endpoint: endpoint,
						Latency:  time.Since(start),
						Tags:     s.profileProxyTags(endpoint, verifier, timeout),
					}
					if transferModel == "brrr" {
						result.DownloadKBps, result.UploadKBps = proxyTransferBenchmarkBrrr(endpoint, verifier, timeout)
					} else {
						result.DownloadKBps, result.UploadKBps = proxyTransferBenchmark(endpoint, verifier, timeout)
					}
					// Log benchmark results for diagnostics
					if result.DownloadKBps > 0 || result.UploadKBps > 0 {
						s.logf("[DEBUG] transfer benchmark %s down=%.1fKB/s up=%.1fKB/s\n", endpoint, result.DownloadKBps, result.UploadKBps)
					} else {
						s.logf("[DEBUG] transfer benchmark %s returned no throughput\n", endpoint)
					}
					mu.Lock()
					verified = append(verified, result)
					mu.Unlock()
					hits.Add(1)
					s.logf("[+] %s\n", formatProxyResult(result))
				}
				processed := completed.Add(1)
				if processed%50 == 0 || processed == int64(total) {
					s.logf("[*] Verified %d/%d | Found %d\n", processed, total, hits.Load())
					s.reportProxyProgress(int(processed), total, int(hits.Load()), "", total)
				}
			}
		}()
	}

	for _, endpoint := range candidates {
		jobs <- endpoint
	}
	close(jobs)
	wg.Wait()
	s.logf("[DEBUG] scanProxyCandidates complete (%s) processed=%d hits=%d\n", protocol, completed.Load(), hits.Load())
	return verified
}

// scanProxyCandidatesWave3 implements a per-candidate 3-wave pipeline.
// Each candidate flows W1->W2->W3 independently (like Python), so slow W3
// candidates do not block W1/W2 throughput for the rest of the set.
func (s *Scanner) scanProxyCandidatesWave3(candidates []string, concurrency int, maxTimeout time.Duration, transferModel string) []ProxyScanResult {
	total := len(candidates)
	s.logf("[TRACE] Pipelined Wave3 starting: total=%d candidates (w1=%d w2=%d w3=%d)\n", total, httpWave1Concurrency, httpWave2Concurrency, httpWave3Concurrency)
	w1Timeout, w2Timeout, w3Timeout := waveTimeouts(maxTimeout)

	if total == 0 {
		return []ProxyScanResult{}
	}
	s.reportProxyProgress(0, total, 0, "", total)

	minInt := func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}

	concurrency = max(1, min(concurrency, total))
	sem1 := make(chan struct{}, minInt(httpWave1Concurrency, concurrency))
	sem2 := make(chan struct{}, minInt(httpWave2Concurrency, concurrency))
	sem3 := make(chan struct{}, minInt(httpWave3Concurrency, concurrency))

	// Match Python's bounded task-object strategy to avoid goroutine explosion.
	taskCap := concurrency
	taskSlots := make(chan struct{}, taskCap)

	var (
		verified []ProxyScanResult
		mu       sync.Mutex
		wg       sync.WaitGroup

		completed atomic.Int64
		reportMu  sync.Mutex
		w1Done    atomic.Int64
		w1Pass    atomic.Int64
		w2Done    atomic.Int64
		w2Pass    atomic.Int64
		w3Done    atomic.Int64
		w3Pass    atomic.Int64
	)

	tickEvery := total / 400
	if tickEvery < 1 {
		tickEvery = 1
	}

	report := func() {
		reportMu.Lock()
		defer reportMu.Unlock()
		done := completed.Add(1)
		if done%int64(tickEvery) != 0 && done != int64(total) {
			return
		}
		s.logf("[*] pipeline: w1 %d/%d w2 %d/%d w3 %d/%d found=%d\n",
			w1Pass.Load(), w1Done.Load(),
			w2Pass.Load(), w2Done.Load(),
			w3Pass.Load(), w3Done.Load(),
			int(w3Pass.Load()),
		)
		s.reportProxyProgress(int(done), total, int(w3Pass.Load()), "", total)
	}

	for _, endpoint := range candidates {
		taskSlots <- struct{}{}
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			defer func() { <-taskSlots }()
			defer report()
			if !s.waitWhilePaused() {
				w1Done.Add(1)
				return
			}
			start := time.Now()

			// Wave 1
			sem1 <- struct{}{}
			if !s.waitWhilePaused() {
				<-sem1
				w1Done.Add(1)
				return
			}
			ok := httpWave1(ep, w1Timeout)
			<-sem1
			w1Done.Add(1)
			if ok {
				w1Pass.Add(1)
			} else {
				return
			}

			// Wave 2
			sem2 <- struct{}{}
			if !s.waitWhilePaused() {
				<-sem2
				return
			}
			ok = httpWave2(ep, w2Timeout)
			<-sem2
			w2Done.Add(1)
			if ok {
				w2Pass.Add(1)
			} else {
				return
			}

			// Wave 3 (strict acceptance)
			sem3 <- struct{}{}
			if !s.waitWhilePaused() {
				<-sem3
				return
			}
			ok = httpWave3(ep, w3Timeout)
			<-sem3
			w3Done.Add(1)
			if ok {
				w3Pass.Add(1)
				result := ProxyScanResult{
					Protocol: "http",
					Endpoint: ep,
					Latency:  time.Since(start),
					Tags:     s.profileProxyTags(ep, httpVerifier{}, maxTimeout),
				}
				if transferModel == "brrr" {
					result.DownloadKBps, result.UploadKBps = proxyTransferBenchmarkBrrr(ep, httpVerifier{}, maxTimeout)
				} else {
					result.DownloadKBps, result.UploadKBps = proxyTransferBenchmark(ep, httpVerifier{}, maxTimeout)
				}
				if result.DownloadKBps > 0 || result.UploadKBps > 0 {
					s.logf("[DEBUG] transfer benchmark %s down=%.1fKB/s up=%.1fKB/s\n", ep, result.DownloadKBps, result.UploadKBps)
				} else {
					s.logf("[DEBUG] transfer benchmark %s returned no throughput\n", ep)
				}
				mu.Lock()
				verified = append(verified, result)
				mu.Unlock()
			}

		}(endpoint)
	}

	wg.Wait()

	s.reportProxyProgress(total, total, int(w3Pass.Load()), "", total)
	s.logf("[DEBUG] Pipelined Wave3 complete: final verified=%d\n", len(verified))
	return verified
}

// runProxyWaveOptimized runs an optimized verification wave with proper task distribution
// Uses actual HTTP wave verification functions and higher concurrency for speed
func (s *Scanner) runProxyWaveOptimized(candidates []string, concurrency int, timeout time.Duration, waveName string, isFastPing bool) []ProxyScanResult {
	total := len(candidates)
	if total == 0 {
		return []ProxyScanResult{}
	}
	w1Timeout, w2Timeout, w3Timeout := waveTimeouts(timeout)

	if concurrency > total {
		concurrency = total
	}

	var verified []ProxyScanResult
	var mu sync.Mutex
	var processedCount atomic.Int64
	var lastReport atomic.Int64

	// Buffered channel for batch efficiency
	jobs := make(chan string, concurrency)
	var wg sync.WaitGroup

	// Spawn worker goroutines - Go goroutines are very lightweight
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for endpoint := range jobs {
				if !s.waitWhilePaused() {
					processedCount.Add(1)
					continue
				}
				var passed bool
				start := time.Now()

				// Route to appropriate verification function
				if isFastPing {
					passed = httpWave1(endpoint, w1Timeout)
				} else if waveName == "wave2" {
					passed = httpWave2(endpoint, w2Timeout)
				} else {
					passed = httpWave3(endpoint, w3Timeout)
				}

				if passed {
					result := ProxyScanResult{
						Protocol: "http",
						Endpoint: endpoint,
						Latency:  time.Since(start),
						Tags:     s.profileProxyTags(endpoint, httpVerifier{}, timeout),
					}
					result.DownloadKBps, result.UploadKBps = proxyTransferBenchmark(endpoint, httpVerifier{}, timeout)
					mu.Lock()
					verified = append(verified, result)
					mu.Unlock()
				}

				// Progress reporting every 200 or at end
				processed := processedCount.Add(1)
				last := lastReport.Load()
				if processed-last >= 2000 || processed == int64(total) {
					lastReport.Store(processed)
					s.logf("[*] %s: %d/%d processed\n", waveName, processed, total)
				}
			}
		}()
	}

	// Feed jobs to workers
	for _, endpoint := range candidates {
		jobs <- endpoint
	}
	close(jobs)

	// Wait for completion
	wg.Wait()

	s.logf("[DEBUG] %s complete: %d/%d verified\n", waveName, len(verified), total)
	return verified
}

func formatProxyScanResults(results []ProxyScanResult) []string {
	if len(results) == 0 {
		return []string{}
	}
	formatted := make([]string, 0, len(results))
	for _, result := range results {
		formatted = append(formatted, formatProxyResult(result))
	}
	return deduplicateEndpoints(formatted)
}

func formatProxyResult(result ProxyScanResult) string {
	protocol := strings.ToLower(strings.TrimSpace(result.Protocol))
	if protocol == "" {
		protocol = "proxy"
	}
	parts := []string{protocol, result.Endpoint}
	if result.Latency > 0 {
		parts = append(parts, fmt.Sprintf("lat=%dms", result.Latency.Milliseconds()))
	}
	if result.DownloadKBps > 0 {
		parts = append(parts, fmt.Sprintf("↓%.1fKB/s", result.DownloadKBps))
	}
	if result.UploadKBps > 0 {
		parts = append(parts, fmt.Sprintf("↑%.1fKB/s", result.UploadKBps))
	}
	for _, tag := range result.Tags {
		tag = strings.TrimSpace(strings.ToLower(tag))
		if tag == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("[%s]", tag))
	}
	return strings.Join(parts, " ")
}

func deduplicateProxyResults(results []ProxyScanResult) []ProxyScanResult {
	if len(results) == 0 {
		return []ProxyScanResult{}
	}
	seen := make(map[string]struct{}, len(results))
	filtered := make([]ProxyScanResult, 0, len(results))
	for _, result := range results {
		line := formatProxyResult(result)
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		filtered = append(filtered, result)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return formatProxyResult(filtered[i]) < formatProxyResult(filtered[j])
	})
	return filtered
}

func proxyProtocolLabel(verifier proxyVerifier) string {
	switch verifier.(type) {
	case httpVerifier:
		return "http"
	case socks5Verifier:
		return "socks5"
	default:
		return "proxy"
	}
}

func (s *Scanner) profileProxyTags(endpoint string, verifier proxyVerifier, timeout time.Duration) []string {
	_ = s
	tagTimeout := timeout / 2
	if tagTimeout <= 0 {
		tagTimeout = 2 * time.Second
	}
	if tagTimeout > 3*time.Second {
		tagTimeout = 3 * time.Second
	}

	var tags []string
	if probeProxyHost(endpoint, verifier, "web.telegram.org", tagTimeout) {
		tags = append(tags, "telegram")
	}
	if probeProxyHost(endpoint, verifier, "chatgpt.com", tagTimeout) {
		tags = append(tags, "chatgpt")
	}
	if probeProxyHost(endpoint, verifier, "psiphon.ca", tagTimeout) {
		tags = append(tags, "psiphon")
	}
	return tags
}

func probeProxyHost(endpoint string, verifier proxyVerifier, host string, timeout time.Duration) bool {
	switch verifier.(type) {
	case httpVerifier:
		return probeHTTPProxyHost(endpoint, host, timeout)
	case socks5Verifier:
		return probeSOCKS5ProxyHost(endpoint, host, timeout)
	default:
		return false
	}
}

func probeHTTPProxyHost(endpoint, host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host, host)
	if _, err := io.WriteString(conn, req); err != nil {
		return false
	}

	return readProxyHTTPResponse(conn, false, true)
}

func probeSOCKS5ProxyHost(endpoint, host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return false
	}

	hostBytes := []byte(host)
	if len(hostBytes) == 0 || len(hostBytes) > 255 {
		return false
	}
	req := make([]byte, 0, 7+len(hostBytes))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(hostBytes)))
	req = append(req, hostBytes...)
	req = append(req, 0x00, 0x50)
	if _, err := conn.Write(req); err != nil {
		return false
	}

	if !readSOCKS5Reply(conn) {
		return false
	}

	reqLine := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host, host)
	if _, err := io.WriteString(conn, reqLine); err != nil {
		return false
	}
	return readProxyHTTPResponse(conn, false, true)
}

func (v httpVerifier) verify(endpoint string, timeout time.Duration) bool {
	if v.dpi.Enabled && !VerifyProxyTLS(endpoint, "http", v.testURL, timeout, v.dpi) {
		return false
	}
	w1, w2, w3 := waveTimeouts(timeout)
	if !httpWave1(endpoint, w1) {
		return false
	}
	if !httpWave2(endpoint, w2) {
		return false
	}
	return httpWave3(endpoint, w3)
}

func httpWave1(endpoint string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_ = conn.Close()
	return true
}

func httpWave2(endpoint string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	const proxyRequest = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, proxyRequest); err != nil {
		return false
	}

	return readProxyHTTPResponse(conn, false, false)
}

func httpWave3(endpoint string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	const fingerprintRequest = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, fingerprintRequest); err != nil {
		return false
	}

	return readProxyHTTPResponse(conn, true, false)
}

// Bound untrusted headers and body, and let net/http handle TCP fragmentation
// and chunked transfer encoding. A fingerprint in a header is not a body match.
func readProxyHTTPResponse(reader io.Reader, fingerprint, allowRedirect bool) bool {
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(reader, httpWave3Limit)), nil)
	if err != nil {
		return false
	}
	// The caller owns and closes the raw connection. Closing this parsed body
	// would drain it and delay a header-only probe until EOF or timeout.
	if response.StatusCode != http.StatusOK && !(allowRedirect && response.StatusCode >= 200 && response.StatusCode < 400) {
		return false
	}
	if !fingerprint {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, httpWave3Limit))
	return err == nil && bytes.Contains(body, exampleDomainSig)
}

func readSOCKS5Reply(reader io.Reader) bool {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil || header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return false
	}
	var size int64
	switch header[3] {
	case 1:
		size = 6
	case 4:
		size = 18
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil || length[0] == 0 {
			return false
		}
		size = int64(length[0]) + 2
	default:
		return false
	}
	_, err := io.CopyN(io.Discard, reader, size)
	return err == nil
}

func (v socks5Verifier) verify(endpoint string, timeout time.Duration) bool {
	if v.dpi.Enabled && !VerifyProxyTLS(endpoint, "socks5", v.testURL, timeout, v.dpi) {
		return false
	}
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return false
	}

	request := []byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x50}
	if _, err := conn.Write(request); err != nil {
		return false
	}

	if !readSOCKS5Reply(conn) {
		return false
	}

	if _, err := io.WriteString(conn, "HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"); err != nil {
		return false
	}

	return readProxyHTTPResponse(conn, false, true)
}
