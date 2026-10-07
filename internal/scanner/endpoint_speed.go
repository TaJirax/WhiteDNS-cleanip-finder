package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"whitedns-go/internal/antidpi"
)

type EndpointSpeedResult struct {
	Mbps      float64 `json:"mbps"`
	Bytes     int64   `json:"bytes"`
	Seconds   float64 `json:"seconds"`
	LatencyMs int64   `json:"latencyMs"`
	Endpoint  string  `json:"endpoint"`
}

func EndpointTransport(endpoint, kind string, options antidpi.Options, timeout time.Duration) (*http.Transport, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	raw := endpoint
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("select an IP:port or proxy endpoint")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
		if kind == "http" {
			port = "8080"
		}
		if kind == "socks5" {
			port = "1080"
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("invalid endpoint port")
	}
	address := net.JoinHostPort(parsed.Hostname(), port)
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{TLSClientConfig: applyScanTLSRoots(&tls.Config{MinVersion: tls.VersionTLS12}), TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	var dial func(context.Context, string, string) (net.Conn, error) = dialer.DialContext
	switch kind {
	case "ip":
		dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		}
	case "http":
		parsed.Host = address
		transport.Proxy = http.ProxyURL(parsed)
	case "socks5":
		var auth *proxy.Auth
		if parsed.User != nil {
			password, _ := parsed.User.Password()
			auth = &proxy.Auth{User: parsed.User.Username(), Password: password}
		}
		socks, err := proxy.SOCKS5("tcp", address, auth, dialer)
		if err != nil {
			return nil, err
		}
		contextual, ok := socks.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("proxy does not support cancellation")
		}
		dial = contextual.DialContext
	default:
		return nil, fmt.Errorf("speed tests support IP, HTTP proxy and SOCKS5 results")
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return antidpi.Wrap(ctx, conn, options), nil
	}
	return transport, nil
}
func MeasureEndpointDownload(ctx context.Context, endpoint, kind, rawURL string, seconds, maxMB int, options antidpi.Options) (EndpointSpeedResult, error) {
	if seconds < 1 || seconds > 60 || maxMB < 1 || maxMB > 1024 {
		return EndpointSpeedResult{}, fmt.Errorf("use 1-60 seconds and 1-1024 MB")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return EndpointSpeedResult{}, fmt.Errorf("enter a direct HTTP/HTTPS download URL")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	transport, err := EndpointTransport(endpoint, kind, options, time.Duration(seconds)*time.Second)
	if err != nil {
		return EndpointSpeedResult{}, err
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return EndpointSpeedResult{}, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return EndpointSpeedResult{}, err
	}
	defer response.Body.Close()
	latency := time.Since(start).Milliseconds()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return EndpointSpeedResult{}, fmt.Errorf("download returned HTTP %d; use a direct URL", response.StatusCode)
	}
	bytes, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, int64(maxMB)<<20))
	elapsed := time.Since(start).Seconds()
	if ctx.Err() == context.Canceled {
		return EndpointSpeedResult{}, ctx.Err()
	}
	if readErr != nil && ctx.Err() != context.DeadlineExceeded {
		return EndpointSpeedResult{}, readErr
	}
	if bytes == 0 {
		return EndpointSpeedResult{}, fmt.Errorf("no data transferred through this endpoint")
	}
	return EndpointSpeedResult{Mbps: float64(bytes) * 8 / elapsed / 1e6, Bytes: bytes, Seconds: elapsed, LatencyMs: latency, Endpoint: endpoint}, nil
}
func VerifyProxyTLS(endpoint, kind, testURL string, timeout time.Duration, options antidpi.Options) bool {
	if testURL == "" {
		testURL = "https://example.com/"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	transport, err := EndpointTransport(endpoint, kind, options, timeout)
	if err != nil {
		return false
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
	return err == nil && response.StatusCode >= 200 && response.StatusCode < 400
}
