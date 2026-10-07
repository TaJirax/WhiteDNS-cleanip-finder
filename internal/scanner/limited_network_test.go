package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Limited network mode probes at most 3 domains of an endpoint at once, so a
// weak link is not flooded; otherwise the adaptive domain concurrency applies.
func TestLimitedNetworkCapsDomainsInFlight(t *testing.T) {
	var inFlight, peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(150 * time.Millisecond)
		inFlight.Add(-1)
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.Host)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	domains := []string{"alpha.example", "bravo.example", "charlie.example", "delta.example", "echo.example", "foxtrot.example"}

	for limited, want := range map[bool]int32{true: 3, false: 6} {
		peak.Store(0)
		opts := IPScanOptions{Ports: []int{port}, Timeout: 3 * time.Second, ProbeDomainsHTTP: domains, AdaptiveDomainConcurrency: 6, LimitedNetwork: limited}
		res := NewScanner(nil).probeHTTP(context.Background(), host, port, opts)
		if res.Status != "accept" || peak.Load() != want {
			t.Fatalf("limited=%v: %d domains at once (want %d), status %s", limited, peak.Load(), want, res.Status)
		}
	}
}
