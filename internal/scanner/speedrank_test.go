package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultSpeedEndpointsOrderAndNames(t *testing.T) {
	eps := DefaultSpeedEndpoints(10 * 1024 * 1024)
	if len(eps) != 4 {
		t.Fatalf("expected 4 download endpoints, got %d", len(eps))
	}
	wantNames := []string{"cloudflare", "cachefly", "hetzner", "google-204"}
	for i, want := range wantNames {
		if eps[i].Name != want {
			t.Fatalf("endpoint %d: want name %q, got %q", i, want, eps[i].Name)
		}
	}
	if !eps[0].PinToCandidate {
		t.Fatalf("cloudflare endpoint must be PinToCandidate")
	}
	if eps[1].PinToCandidate || eps[2].PinToCandidate || eps[3].PinToCandidate {
		t.Fatalf("only cloudflare should be PinToCandidate")
	}
	if !eps[3].Reachability {
		t.Fatalf("google-204 must be Reachability-only")
	}
	if eps[1].URL != "https://cachefly.cachefly.net/10mb.test" {
		t.Fatalf("unexpected cachefly URL: %s", eps[1].URL)
	}
	if eps[2].URL != "https://speed.hetzner.de/100MB.bin" {
		t.Fatalf("unexpected hetzner URL: %s", eps[2].URL)
	}
}

func TestMeasureUploadFallsBackOnFirstEndpointFailure(t *testing.T) {
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer okServer.Close()
	okHost := okServer.Listener.Addr().String()

	opts := SpeedRankOptions{
		UploadBytes: 1024,
		Timeout:     2 * time.Second,
		UploadEndpoints: []SpeedEndpoint{
			{Name: "broken", URL: "https://127.0.0.1:1/__up"}, // nothing listens here -> dial error
			{Name: "ok", URL: "http://" + okHost + "/post"},
		},
	}
	opts.applyDefaults()

	mbps, source, err := measureUpload(context.Background(), okHost, opts)
	if err != nil {
		t.Fatalf("expected fallback to succeed, got err: %v", err)
	}
	if source != "ok" {
		t.Fatalf("expected fallback source 'ok', got %q", source)
	}
	if mbps <= 0 {
		t.Fatalf("expected positive mbps, got %f", mbps)
	}
}

func TestDedupeIPsStripsPortsAndDropsNonIPs(t *testing.T) {
	// Mirrors what the IP-scan -> speed-test auto-chain feeds in: "ip:port"
	// tokens plus passed-domain names split in as peers.
	in := []string{"1.1.1.1:443", "gemini.google.com", "chatgpt.com", "8.8.8.8:443", "instagram.com", "1.1.1.1:443", " 9.9.9.9 "}
	got := dedupeIPs(in)

	want := map[string]bool{"1.1.1.1": true, "8.8.8.8": true, "9.9.9.9": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d unique IPs, got %d: %v", len(want), len(got), got)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Fatalf("unexpected token survived dedupe: %q (full: %v)", ip, got)
		}
	}
}

func TestDefaultUploadEndpointsOrderAndNames(t *testing.T) {
	eps := DefaultUploadEndpoints()
	wantNames := []string{"cloudflare", "postman-echo", "httpbin"}
	if len(eps) != len(wantNames) {
		t.Fatalf("expected %d upload endpoints, got %d", len(wantNames), len(eps))
	}
	for i, want := range wantNames {
		if eps[i].Name != want {
			t.Fatalf("endpoint %d: want name %q, got %q", i, want, eps[i].Name)
		}
	}
	if !eps[0].PinToCandidate {
		t.Fatalf("cloudflare upload endpoint must be PinToCandidate")
	}
}
