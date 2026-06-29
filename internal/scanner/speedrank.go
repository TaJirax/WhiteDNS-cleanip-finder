package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"whitedns-go/internal/storage"
)

// SpeedRankOptions tunes the Cloudflare-based download/upload/packet-loss
// benchmark used to rank already-passed clean IPs.
type SpeedRankOptions struct {
	// Port to connect to on each IP (TLS). Defaults to 443.
	Port int
	// Concurrency is the number of IPs benchmarked in parallel.
	Concurrency int
	// DownloadBytes is the payload size requested from /__down.
	DownloadBytes int
	// UploadBytes is the payload size posted to /__up.
	UploadBytes int
	// LossSamples is the number of latency probes per IP used to estimate
	// packet loss (failed connects / samples) and jitter.
	LossSamples int
	// Timeout bounds each individual network operation.
	Timeout time.Duration
	// SNI is the TLS server name / Host header used for the speed endpoint.
	SNI string
	// DownloadEndpoints are tried in order for the throughput/reachability
	// measurement; the first one that responds is used. Defaults to the
	// Cloudflare speed endpoint plus Google generate_204 and Cachefly.
	DownloadEndpoints []SpeedEndpoint
	// PauseFunc, if set, is polled before each IP is benchmarked; while it
	// returns true the worker blocks (cooperative pause). nil disables pausing.
	PauseFunc func() bool
}

// SpeedEndpoint describes one test target used for the throughput/reachability
// step. Multiple endpoints provide redundancy when one host is blocked.
type SpeedEndpoint struct {
	// Name is a short label shown in results/CSV.
	Name string
	// URL is the full HTTPS URL to fetch.
	URL string
	// Host overrides the TLS SNI / Host header; empty derives it from URL.
	Host string
	// PinToCandidate dials the candidate IP being ranked instead of resolving
	// the URL host. Use this only for endpoints served by that IP (Cloudflare
	// clean edges); generic fallbacks resolve normally.
	PinToCandidate bool
	// Reachability marks endpoints that only confirm connectivity (e.g. a
	// 204 response) rather than measuring meaningful throughput.
	Reachability bool
}

// DefaultSpeedEndpoints returns the ordered fallback list. downloadBytes is
// substituted into the Cloudflare endpoint.
func DefaultSpeedEndpoints(downloadBytes int) []SpeedEndpoint {
	return []SpeedEndpoint{
		{
			Name:           "cloudflare",
			URL:            fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", downloadBytes),
			Host:           "speed.cloudflare.com",
			PinToCandidate: true,
		},
		{
			Name:         "google-204",
			URL:          "https://www.google.com/generate_204",
			Reachability: true,
		},
		{
			Name: "cachefly",
			URL:  "https://cachefly.cachefly.net/50mb.test",
		},
	}
}

func (o *SpeedRankOptions) applyDefaults() {
	if o.Port <= 0 {
		o.Port = 443
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 16
	}
	if o.DownloadBytes <= 0 {
		o.DownloadBytes = 10 * 1024 * 1024 // 10 MB
	}
	if o.UploadBytes <= 0 {
		o.UploadBytes = 4 * 1024 * 1024 // 4 MB
	}
	if o.LossSamples <= 0 {
		o.LossSamples = 6
	}
	if o.Timeout <= 0 {
		o.Timeout = 12 * time.Second
	}
	if strings.TrimSpace(o.SNI) == "" {
		o.SNI = "speed.cloudflare.com"
	}
	if len(o.DownloadEndpoints) == 0 {
		o.DownloadEndpoints = DefaultSpeedEndpoints(o.DownloadBytes)
	}
}

// SpeedRankResult holds the benchmark outcome for one IP.
type SpeedRankResult struct {
	IP           string
	Port         int
	Reachable    bool
	DownloadMbps float64
	UploadMbps   float64
	LossPct      float64
	LatencyMs    float64
	JitterMs     float64
	Score        float64
	// Source is the name of the endpoint that produced the throughput number.
	Source string
	Error  string
}

// score is a composite ranking: reward throughput, penalize loss and latency.
// Higher is better. It is intentionally simple and explainable.
func (r *SpeedRankResult) computeScore() {
	if !r.Reachable {
		r.Score = 0
		return
	}
	throughput := r.DownloadMbps + 0.5*r.UploadMbps
	lossPenalty := 1.0 - (r.LossPct / 100.0)
	if lossPenalty < 0 {
		lossPenalty = 0
	}
	// Latency factor in [0,1]: 0 ms -> 1.0, 500 ms -> ~0.5, decays gently.
	latencyFactor := 1.0 / (1.0 + r.LatencyMs/250.0)
	r.Score = throughput * lossPenalty * latencyFactor
}

// SpeedRankIPs benchmarks each IP via the Cloudflare speed endpoint and returns
// results sorted best-first. progressCb (optional) is called after each IP with
// the number processed, the total, the count reachable, and the current IP.
func SpeedRankIPs(ctx context.Context, ips []string, opts SpeedRankOptions, progressCb func(processed, total, reachable int, currentIP string)) []SpeedRankResult {
	opts.applyDefaults()
	ips = dedupeIPs(ips)

	results := make([]SpeedRankResult, len(ips))
	total := len(ips)

	var (
		mu        sync.Mutex
		processed int
		reachable int
	)

	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for i, ip := range ips {
		select {
		case <-ctx.Done():
			// Fill remaining as unreachable/aborted and stop launching work.
			results[i] = SpeedRankResult{IP: ip, Port: opts.Port, Error: "aborted"}
			continue
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			res := benchmarkOneIP(ctx, ip, opts)

			mu.Lock()
			results[i] = res
			processed++
			if res.Reachable {
				reachable++
			}
			p, rch := processed, reachable
			mu.Unlock()

			if progressCb != nil {
				progressCb(p, total, rch, ip)
			}
		}(i, ip)
	}
	wg.Wait()

	sort.SliceStable(results, func(a, b int) bool {
		return results[a].Score > results[b].Score
	})
	return results
}

// waitWhilePaused blocks while opts.PauseFunc reports paused, returning early if
// the context is cancelled. It is a no-op when no PauseFunc is set.
func waitWhilePaused(ctx context.Context, opts SpeedRankOptions) {
	if opts.PauseFunc == nil {
		return
	}
	for opts.PauseFunc() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func benchmarkOneIP(ctx context.Context, ip string, opts SpeedRankOptions) SpeedRankResult {
	waitWhilePaused(ctx, opts)
	res := SpeedRankResult{IP: ip, Port: opts.Port}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", opts.Port))

	// --- Packet-loss + latency/jitter estimate via repeated TLS handshakes ---
	var latencies []float64
	failures := 0
	for s := 0; s < opts.LossSamples; s++ {
		waitWhilePaused(ctx, opts)
		select {
		case <-ctx.Done():
			res.Error = "aborted"
			return res
		default:
		}
		start := time.Now()
		conn, err := tlsDialSpeed(ctx, addr, opts)
		if err != nil {
			failures++
			continue
		}
		latencies = append(latencies, float64(time.Since(start).Milliseconds()))
		_ = conn.Close()
	}
	res.LossPct = float64(failures) / float64(opts.LossSamples) * 100.0
	res.LatencyMs, res.JitterMs = meanStdDev(latencies)

	if len(latencies) == 0 {
		// Completely unreachable: no point measuring throughput.
		res.Error = "no successful handshake"
		res.computeScore()
		return res
	}
	res.Reachable = true

	// --- Download / reachability throughput with ordered endpoint fallback ---
	gotThroughput := false
	var lastErr string
	for _, ep := range opts.DownloadEndpoints {
		waitWhilePaused(ctx, opts)
		select {
		case <-ctx.Done():
			res.Error = "aborted"
			return res
		default:
		}
		mbps, err := measureEndpoint(ctx, addr, ep, opts)
		if err != nil {
			lastErr = ep.Name + ": " + err.Error()
			continue
		}
		if res.Source == "" {
			res.Source = ep.Name
		}
		if !ep.Reachability {
			res.DownloadMbps = mbps
			res.Source = ep.Name
			gotThroughput = true
			break
		}
	}
	if !gotThroughput && res.Source == "" && lastErr != "" {
		res.Error = "download: " + lastErr
	}

	// --- Upload throughput (Cloudflare /__up only; pinned to candidate IP) ---
	waitWhilePaused(ctx, opts)
	if ctx.Err() == nil {
		if mbps, err := measureUpload(ctx, addr, opts); err == nil {
			res.UploadMbps = mbps
		}
	}

	res.computeScore()
	return res
}

// tlsDialSpeed performs a single TLS handshake to addr using the speed SNI.
func tlsDialSpeed(ctx context.Context, addr string, opts SpeedRankOptions) (net.Conn, error) {
	d := &net.Dialer{Timeout: opts.Timeout}
	dialCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	rawConn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         opts.SNI,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(opts.Timeout))
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// endpointHTTPClient returns an http.Client for a single endpoint. When
// pinToCandidate is set, all connections are forced to candidateAddr (the IP
// being ranked); otherwise the URL host is resolved normally. host sets the TLS
// SNI.
func endpointHTTPClient(candidateAddr, host string, pinToCandidate bool, opts SpeedRankOptions) *http.Client {
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &net.Dialer{Timeout: opts.Timeout}
		if pinToCandidate {
			address = candidateAddr
		}
		return d.DialContext(ctx, network, address)
	}
	transport := &http.Transport{
		DialContext: dial,
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
	}
	return &http.Client{Transport: transport}
}

// measureEndpoint fetches one endpoint and returns its download throughput in
// Mbps. Reachability-only endpoints return (0, nil) on success.
func measureEndpoint(ctx context.Context, candidateAddr string, ep SpeedEndpoint, opts SpeedRankOptions) (float64, error) {
	host := ep.Host
	if host == "" {
		host = hostFromURL(ep.URL)
	}
	client := endpointHTTPClient(candidateAddr, host, ep.PinToCandidate, opts)
	defer client.CloseIdleConnections()

	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ep.URL, nil)
	if err != nil {
		return 0, err
	}
	if host != "" {
		req.Host = host
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	n, copyErr := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start).Seconds()
	if ep.Reachability {
		return 0, nil
	}
	if copyErr != nil && n == 0 {
		return 0, copyErr
	}
	return mbps(n, elapsed), nil
}

// hostFromURL extracts the host (without port) from an https URL.
func hostFromURL(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Hostname()
	}
	return ""
}

func measureUpload(ctx context.Context, candidateAddr string, opts SpeedRankOptions) (float64, error) {
	client := endpointHTTPClient(candidateAddr, opts.SNI, true, opts)
	defer client.CloseIdleConnections()
	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	url := fmt.Sprintf("https://%s/__up", opts.SNI)
	body := &countingReader{remaining: opts.UploadBytes}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, body)
	if err != nil {
		return 0, err
	}
	req.Host = opts.SNI
	req.ContentLength = int64(opts.UploadBytes)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Content-Type", "application/octet-stream")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start).Seconds()
	sent := opts.UploadBytes - body.remaining
	return mbps(int64(sent), elapsed), nil
}

// countingReader streams a fixed number of zero bytes and tracks how many
// remain, so partial uploads can still be measured.
type countingReader struct {
	remaining int
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > c.remaining {
		n = c.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	c.remaining -= n
	return n, nil
}

func mbps(bytes int64, seconds float64) float64 {
	if seconds <= 0 || bytes <= 0 {
		return 0
	}
	return (float64(bytes) * 8.0) / seconds / 1_000_000.0
}

func meanStdDev(values []float64) (mean, std float64) {
	if len(values) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean = sum / float64(len(values))
	var variance float64
	for _, v := range values {
		variance += (v - mean) * (v - mean)
	}
	variance /= float64(len(values))
	return mean, math.Sqrt(variance)
}

func dedupeIPs(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		// Strip an optional :port so callers can pass ip:port endpoints.
		if host, _, ok := strings.Cut(ip, ":"); ok && net.ParseIP(host) != nil {
			ip = host
		}
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

// FormatSpeedRankLine renders one result as a compact, sortable display line.
func FormatSpeedRankLine(rank int, r SpeedRankResult) string {
	if !r.Reachable {
		reason := r.Error
		if reason == "" {
			reason = "unreachable"
		}
		return fmt.Sprintf("%3d. %-15s  DOWN --     UP --     LOSS 100%%   (%s)", rank, r.IP, reason)
	}
	src := r.Source
	if src == "" {
		src = "-"
	}
	return fmt.Sprintf("%3d. %-15s  DOWN %6.2f Mbps  UP %6.2f Mbps  LOSS %5.1f%%  RTT %5.0fms  jit %4.0fms  score %6.2f  via %s",
		rank, r.IP, r.DownloadMbps, r.UploadMbps, r.LossPct, r.LatencyMs, r.JitterMs, r.Score, src)
}

// WriteSpeedRankCSV writes ranked results to a timestamped CSV under the
// WhiteDNS logs directory and returns the file path.
func WriteSpeedRankCSV(dataDir string, results []SpeedRankResult) (string, error) {
	if dataDir == "" {
		dataDir = "."
	}
	outDir := filepath.Join(dataDir, "whitedns logs")
	stamp := time.Now().Format("20060102-150405")
	path := filepath.Join(outDir, fmt.Sprintf("speedrank-%s.csv", stamp))

	var b strings.Builder
	b.WriteString("rank,ip,port,reachable,download_mbps,upload_mbps,loss_pct,latency_ms,jitter_ms,score,source,error\n")
	for i, r := range results {
		b.WriteString(fmt.Sprintf("%d,%s,%d,%t,%.2f,%.2f,%.1f,%.0f,%.0f,%.2f,%s,%q\n",
			i+1, r.IP, r.Port, r.Reachable, r.DownloadMbps, r.UploadMbps, r.LossPct, r.LatencyMs, r.JitterMs, r.Score, r.Source, r.Error))
	}
	if err := storage.AtomicWriteText(path, b.String()); err != nil {
		return "", err
	}
	return path, nil
}
