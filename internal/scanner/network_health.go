package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// healthGateDisabled reports whether the Iranian-domain transport health gate
// has been switched off via WHITE_DISABLE_HEALTH_GATE. This is useful when
// testing from a VM or a network abroad that cannot reach the hardcoded health
// sites, where the gate would otherwise pause the scan.
func healthGateDisabled() bool {
	v := strings.TrimSpace(os.Getenv("WHITE_DISABLE_HEALTH_GATE"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// quickConnectivityCheck reports whether the device currently has working
// network, using a couple of fast TCP dials to well-known anycast hosts. Unlike
// the Iranian-site health probe, a single TCP SYN succeeds even while a heavy
// scan is in flight and regardless of whether the user can reach Iranian sites —
// so it tells genuine "device offline" apart from "can't reach Iran health
// sites" (self-congestion, or a user with no Iran ping). Used to avoid stalling
// a scan when the device actually has internet.
func quickConnectivityCheck(timeout time.Duration) bool {
	if timeout <= 0 || timeout > 4*time.Second {
		timeout = 3 * time.Second
	}
	for _, host := range []string{"1.1.1.1:443", "8.8.8.8:53", "9.9.9.9:443"} {
		c, err := net.DialTimeout("tcp", host, timeout)
		if err == nil {
			_ = c.Close()
			return true
		}
	}
	return false
}

var defaultTransportHealthSites = []string{
	"snapp.ir",
	"digikala.com",
	"divar.ir",
	"torob.com",
	"cafebazaar.ir",
}


var transportHealthProbe = probeTransportSite

var proxyTransferBenchmark = defaultProxyTransferBenchmark

// proxyTransferBenchmarkBrrr is an alternative, more aggressive transfer
// benchmark. It runs a small number of parallel download/upload attempts
// and returns the best observed throughput. It's designed to be faster and
// to reduce per-endpoint latency when the user selects the "brrr" model.
func proxyTransferBenchmarkBrrr(endpoint string, verifier proxyVerifier, timeout time.Duration) (float64, float64) {
	// Use slightly shorter bounding but more attempts/parallelism.
	benchTimeout := timeout
	if benchTimeout < 6*time.Second {
		benchTimeout = 6 * time.Second
	}
	if benchTimeout > 20*time.Second {
		benchTimeout = 20 * time.Second
	}

	attempts := 3
	var bestDown, bestUp float64
	for i := 0; i < attempts; i++ {
		client, err := benchmarkHTTPClientForProxy(endpoint, verifier, benchTimeout)
		if err != nil {
			time.Sleep(80 * time.Millisecond)
			continue
		}
		// run download and upload concurrently with context
		ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
		downCh := make(chan float64, 1)
		upCh := make(chan float64, 1)
		go func() { downCh <- benchmarkProxyDownload(ctx, client) }()
		go func() { upCh <- benchmarkProxyUpload(ctx, client) }()
		down := <-downCh
		up := <-upCh
		cancel()

		if down > bestDown {
			bestDown = down
		}
		if up > bestUp {
			bestUp = up
		}
		if bestDown > 0 && bestUp > 0 {
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	return bestDown, bestUp
}

const (
	defaultTransportHealthInterval = 8 * time.Second
	defaultTransportPauseSleep     = 3 * time.Second
	defaultTransportHealthAttempts = 2
	defaultTransportHealthRetryGap = 200 * time.Millisecond
	// transportHealthFailuresToPause is how many consecutive failed monitor
	// checks (each defaultTransportHealthInterval apart) must occur before the
	// scan is auto-paused. This debounces transient blips caused by the scan
	// itself crowding out the health probes on small/VM networks.
	transportHealthFailuresToPause = 3
	// transportHealthMaxWait bounds how long the pre-scan gate may block waiting
	// for an Iranian health site to become reachable. On devices/networks that
	// simply cannot reach those hardcoded sites (e.g. Termux on a non-Iran
	// network), the gate would otherwise loop forever and no IPs would ever be
	// scanned. After this it proceeds anyway; the debounced monitor still watches.
	transportHealthMaxWait = 12 * time.Second
)

type TransportHealthSummary struct {
	Label     string
	Total     int
	Reachable int
	Duration  time.Duration
	Up        []string
	Down      []string
}

func (s *Scanner) logTransportHealth(ctx context.Context, label string, sites []string, timeout time.Duration) TransportHealthSummary {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(sites) == 0 {
		sites = defaultTransportHealthSites
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if timeout > 4*time.Second {
		timeout = 4 * time.Second
	}

	started := time.Now()
	summary := TransportHealthSummary{
		Label: label,
		Total: len(sites),
		Up:    make([]string, 0, len(sites)),
		Down:  make([]string, 0, len(sites)),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for _, site := range sites {
		site := site
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok := probeTransportSiteWithRetry(ctx, site, timeout, defaultTransportHealthAttempts, defaultTransportHealthRetryGap, transportHealthProbe)
			mu.Lock()
			if ok {
				summary.Reachable++
				summary.Up = append(summary.Up, site)
			} else {
				summary.Down = append(summary.Down, site)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	summary.Duration = time.Since(started)
	sort.Strings(summary.Up)
	sort.Strings(summary.Down)

	if s != nil {
		s.logf("[HEALTH] %s transport check: %d/%d reachable in %s | up=%v | down=%v\n",
			strings.TrimSpace(label), summary.Reachable, summary.Total, summary.Duration.Round(time.Millisecond), summary.Up, summary.Down)
	}

	return summary
}

func probeTransportSiteWithRetry(ctx context.Context, site string, timeout time.Duration, attempts int, retryGap time.Duration, probe func(context.Context, string, time.Duration) bool) bool {
	if probe == nil {
		probe = probeTransportSite
	}
	if attempts <= 0 {
		attempts = 1
	}
	if retryGap < 0 {
		retryGap = 0
	}

	for attempt := 0; attempt < attempts; attempt++ {
		if probe(ctx, site, timeout) {
			return true
		}
		if attempt == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(retryGap):
		}
	}
	return false
}

// isDeviceOfflineError reports whether a probe failure indicates the scanning
// DEVICE has lost connectivity (no route at all), as opposed to a target simply
// being dead (connection refused / per-host timeout). These device-level errors
// fail instantly, so a sudden burst of them means the phone/PC dropped its
// network — not that thousands of IPs are individually dead.
func isDeviceOfflineError(result *IPScanResult) bool {
	if result == nil {
		return false
	}
	reason := strings.ToLower(result.Error)
	if reason == "" {
		return false
	}
	return strings.Contains(reason, "network is unreachable") ||
		strings.Contains(reason, "network is down") ||
		strings.Contains(reason, "no route to host") ||
		strings.Contains(reason, "host is unreachable") ||
		strings.Contains(reason, "network unreachable")
}

// guardNetworkOutage pauses the scan when the device loses connectivity and
// resumes it once connectivity returns. Without this, a transient outage makes
// every remaining probe fail instantly ("network is unreachable") and the
// pipeline races to the end in seconds, ending the scan far too early with only
// the results found before the drop. Idempotent: only one guard runs at a time.
func (s *Scanner) guardNetworkOutage(label string, timeout time.Duration) {
	if s == nil {
		return
	}
	if !atomic.CompareAndSwapInt32(&s.netGuardActive, 0, 1) {
		return // a guard is already handling the outage
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	s.Pause()
	s.logf("[HEALTH] %s: device network outage detected — pausing scan until connectivity returns\n", label)
	go func() {
		defer atomic.StoreInt32(&s.netGuardActive, 0)
		for {
			if s.IsStopped() {
				s.Resume()
				return
			}
			// Recover on a quick anycast TCP check, not the Iranian health sites,
			// so the scan resumes even for users with no Iran ping.
			if quickConnectivityCheck(timeout) {
				s.Resume()
				s.logf("[HEALTH] %s: connectivity restored — resuming scan\n", label)
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()
}

func (s *Scanner) ensureTransportHealthy(ctx context.Context, label string, sites []string, timeout time.Duration, minReachable int) TransportHealthSummary {
	if ctx == nil {
		ctx = context.Background()
	}
	if minReachable <= 0 {
		minReachable = 1
	}
	if healthGateDisabled() {
		s.logf("[HEALTH] %s transport gate disabled via WHITE_DISABLE_HEALTH_GATE; skipping pre-scan check\n", label)
		return TransportHealthSummary{}
	}

	// Bound the gate so it can never block the scan forever on networks that
	// cannot reach the hardcoded Iranian health sites.
	deadline := time.Now().Add(transportHealthMaxWait)
	for {
		summary := s.logTransportHealth(ctx, label, sites, timeout)
		if summary.Reachable >= minReachable {
			if s != nil && s.IsPaused() {
				s.Resume()
				s.logf("[HEALTH] %s connectivity restored (%d/%d), resuming scan\n", label, summary.Reachable, summary.Total)
			}
			return summary
		}

		// The Iranian health sites are unreachable. If the device itself has
		// working internet (verified with a fast anycast TCP dial), do NOT pause —
		// the user may simply have no Iran ping, or the scan's own traffic is
		// crowding out the health probes. Proceed with the scan immediately.
		if quickConnectivityCheck(timeout) {
			s.logf("[HEALTH] %s Iranian sites unreachable (%d/%d) but device is online; proceeding without the health gate\n", label, summary.Reachable, summary.Total)
			if s != nil && s.IsPaused() {
				s.Resume()
			}
			return summary
		}

		if time.Now().After(deadline) {
			s.logf("[HEALTH] %s connectivity check inconclusive (%d/%d) after %s; proceeding with scan anyway\n", label, summary.Reachable, summary.Total, transportHealthMaxWait)
			if s != nil && s.IsPaused() {
				s.Resume()
			}
			return summary
		}

		if s != nil && !s.IsPaused() {
			s.Pause()
			s.logf("[HEALTH] %s device appears offline (%d/%d). Waiting up to %s for connectivity\n", label, summary.Reachable, summary.Total, transportHealthMaxWait)
		}

		select {
		case <-ctx.Done():
			if s != nil && s.IsPaused() {
				s.Resume()
			}
			return summary
		case <-time.After(defaultTransportPauseSleep):
		}
	}
}

func (s *Scanner) startTransportHealthMonitor(ctx context.Context, label string, sites []string, timeout time.Duration, minReachable int) func() {
	if ctx == nil {
		ctx = context.Background()
	}
	if minReachable <= 0 {
		minReachable = 1
	}
	if healthGateDisabled() {
		return func() {}
	}

	monitorCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(defaultTransportHealthInterval)
		defer ticker.Stop()
		// Debounce pausing: a single failed health check (common when a heavy
		// scan on a small VM crowds out the health probes themselves) must not
		// stall the whole scan. Only pause after several consecutive failures,
		// which indicates a genuine connectivity outage rather than contention.
		consecutiveFailures := 0
		for {
			select {
			case <-monitorCtx.Done():
				if s.IsPaused() {
					s.Resume()
				}
				return
			case <-ticker.C:
				summary := s.logTransportHealth(monitorCtx, label, sites, timeout)
				if summary.Reachable >= minReachable {
					consecutiveFailures = 0
					if s.IsPaused() {
						s.Resume()
						s.logf("[HEALTH] %s monitor resume: %d/%d reachable\n", label, summary.Reachable, summary.Total)
					}
					continue
				}
				consecutiveFailures++
				if consecutiveFailures < transportHealthFailuresToPause {
					s.logf("[HEALTH] %s monitor: health probe failed (%d/%d), %d/%d before pause\n", label, summary.Reachable, summary.Total, consecutiveFailures, transportHealthFailuresToPause)
					continue
				}
				// Iranian sites unreachable for several checks. Only pause if the
				// DEVICE is genuinely offline; if a quick anycast TCP dial succeeds,
				// the user just has no Iran ping (or the scan is crowding out the
				// probes) — keep scanning in that case.
				if quickConnectivityCheck(timeout) {
					consecutiveFailures = 0
					if s.IsPaused() {
						s.Resume()
						s.logf("[HEALTH] %s monitor: Iranian sites unreachable but device online; resuming\n", label)
					}
					continue
				}
				// Genuinely offline: PAUSE and keep retrying on every tick. The scan
				// is never ended or abandoned — it simply waits, and the next
				// successful check (Iranian sites OR the quick anycast dial above)
				// resumes it automatically. Pressing Stop is the only thing that
				// ends it.
				if !s.IsPaused() {
					s.Pause()
					s.logf("[HEALTH] %s monitor pause: device offline — holding scan and retrying connectivity every %s\n", label, defaultTransportHealthInterval)
				} else {
					s.logf("[HEALTH] %s monitor: still offline, retrying connectivity…\n", label)
				}
			}
		}
	}()
	return cancel
}

func probeTransportSite(ctx context.Context, site string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: true,
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+site+"/", nil)
	if err != nil {
		return false
	}
	request.Header.Set("User-Agent", "Mozilla/5.0")
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	return response.StatusCode >= 100 && response.StatusCode < 600
}

func defaultProxyTransferBenchmark(endpoint string, verifier proxyVerifier, timeout time.Duration) (float64, float64) {
	// Run multiple short attempts and take the best non-zero observed values.
	benchmarkTimeout := timeout
	if benchmarkTimeout < 8*time.Second {
		benchmarkTimeout = 8 * time.Second
	}
	if benchmarkTimeout > 15*time.Second {
		benchmarkTimeout = 15 * time.Second
	}

	// Try up to 2 attempts to reduce flakiness; take the best results.
	attempts := 2
	var bestDown float64
	var bestUp float64
	for i := 0; i < attempts; i++ {
		client, err := benchmarkHTTPClientForProxy(endpoint, verifier, benchmarkTimeout)
		if err != nil {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), benchmarkTimeout)
		down := benchmarkProxyDownload(ctx, client)
		up := benchmarkProxyUpload(ctx, client)
		cancel()
		if down > bestDown {
			bestDown = down
		}
		if up > bestUp {
			bestUp = up
		}
		if bestDown > 0 && bestUp > 0 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	return bestDown, bestUp
}

func benchmarkHTTPClientForProxy(endpoint string, verifier proxyVerifier, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableCompression:    true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: timeout,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       timeout,
		ForceAttemptHTTP2:     false,
	}

	switch verifier.(type) {
	case httpVerifier:
		proxyURL, err := url.Parse("http://" + endpoint)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	case socks5Verifier:
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialSOCKS5Proxy(ctx, endpoint, addr, timeout)
		}
	default:
		return nil, fmt.Errorf("unsupported proxy verifier")
	}

	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

func benchmarkProxyDownload(ctx context.Context, client *http.Client) float64 {
	if ctx == nil {
		ctx = context.Background()
	}
	attempts := 2
	var best float64
	for i := 0; i < attempts; i++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://speed.cloudflare.com/__down?bytes=262144", nil)
		if err != nil {
			return 0
		}
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			// retry
			time.Sleep(100 * time.Millisecond)
			continue
		}
		func() {
			defer response.Body.Close()
			// accept successful or redirect statuses (2xx,3xx)
			if response.StatusCode < 200 || response.StatusCode >= 400 {
				return
			}
			bytesRead, _ := io.Copy(io.Discard, response.Body)
			seconds := time.Since(started).Seconds()
			if bytesRead <= 0 || seconds <= 0 {
				return
			}
			val := float64(bytesRead) / 1024.0 / seconds
			if val > best {
				best = val
			}
		}()
		if best > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return best
}

func benchmarkProxyUpload(ctx context.Context, client *http.Client) float64 {
	if ctx == nil {
		ctx = context.Background()
	}
	attempts := 2
	var best float64
	for i := 0; i < attempts; i++ {
		body := bytes.NewReader(make([]byte, 262144))
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://speed.cloudflare.com/__up", body)
		if err != nil {
			return 0
		}
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Content-Length", strconv.Itoa(262144))
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		func() {
			defer response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 400 {
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			seconds := time.Since(started).Seconds()
			if seconds <= 0 {
				return
			}
			val := 256.0 / seconds
			if val > best {
				best = val
			}
		}()
		if best > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return best
}

func dialSOCKS5Proxy(ctx context.Context, proxyEndpoint, targetAddr string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyEndpoint)
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 auth rejected")
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	request := make([]byte, 0, 22)
	request = append(request, 0x05, 0x01, 0x00)
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		request = append(request, 0x01)
		request = append(request, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil && strings.Contains(host, ":") {
		request = append(request, 0x04)
		request = append(request, ip6...)
	} else {
		hostBytes := []byte(host)
		if len(hostBytes) == 0 || len(hostBytes) > 255 {
			_ = conn.Close()
			return nil, fmt.Errorf("invalid host")
		}
		request = append(request, 0x03, byte(len(hostBytes)))
		request = append(request, hostBytes...)
	}
	request = append(request, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(request); err != nil {
		_ = conn.Close()
		return nil, err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if header[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect failed")
	}
	skip := 0
	switch header[3] {
	case 0x01:
		skip = 6
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			_ = conn.Close()
			return nil, err
		}
		skip = int(lenBuf[0]) + 2
	case 0x04:
		skip = 18
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 reply type unsupported")
	}
	if skip > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(skip)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

