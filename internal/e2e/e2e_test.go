package e2e

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeValidator marks a resolver OK when its last octet is even, panics on a
// sentinel, and can sleep to exercise timeout handling.
type fakeValidator struct {
	calls atomic.Int32
	sleep time.Duration
	panic string
}

func (f *fakeValidator) Validate(ctx context.Context, resolver string, opts Options) Result {
	f.calls.Add(1)
	if f.panic != "" && strings.HasPrefix(resolver, f.panic) {
		panic("boom")
	}
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-ctx.Done():
			return Result{Resolver: resolver, Reason: "timeout"}
		}
	}
	host := resolver
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	last := host[strings.LastIndex(host, ".")+1:]
	n, _ := strconv.Atoi(last)
	return Result{Resolver: resolver, OK: n%2 == 0, Reason: "ok"}
}

func TestRunOrderingAndVerdicts(t *testing.T) {
	resolvers := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}
	v := &fakeValidator{}
	got := Run(context.Background(), resolvers, Options{Domain: "t.example", PubKey: "k", Concurrency: 3}, v, nil)

	if len(got) != len(resolvers) {
		t.Fatalf("expected %d results, got %d", len(resolvers), len(got))
	}
	// Order must match input, one verdict each; even last-octet => OK.
	wantOK := []bool{false, true, false, true}
	for i, r := range got {
		if !strings.HasPrefix(r.Resolver, "1.1.1."+strconv.Itoa(i+1)) {
			t.Errorf("result %d out of order: %q", i, r.Resolver)
		}
		if r.OK != wantOK[i] {
			t.Errorf("result %d (%s): OK=%v want %v", i, r.Resolver, r.OK, wantOK[i])
		}
	}
	if v.calls.Load() != int32(len(resolvers)) {
		t.Errorf("validator called %d times, want %d", v.calls.Load(), len(resolvers))
	}

	passed := PassedResolvers(got)
	if len(passed) != 2 {
		t.Fatalf("expected 2 passed resolvers, got %v", passed)
	}
}

func TestRunPanicGuard(t *testing.T) {
	resolvers := []string{"10.0.0.2", "10.0.0.4", "10.0.0.6"}
	v := &fakeValidator{panic: "10.0.0.4"}
	got := Run(context.Background(), resolvers, Options{Domain: "t", PubKey: "k"}, v, nil)
	if len(got) != 3 {
		t.Fatalf("expected 3 results, got %d", len(got))
	}
	if got[1].OK || !strings.Contains(got[1].Reason, "panic") {
		t.Errorf("panicking resolver should yield non-OK panic reason, got %+v", got[1])
	}
	// Neighbors still validate normally.
	if !got[0].OK || !got[2].OK {
		t.Errorf("panic in one resolver must not affect others: %+v", got)
	}
}

func TestRunPerResolverTimeout(t *testing.T) {
	resolvers := []string{"8.8.8.8"}
	v := &fakeValidator{sleep: 2 * time.Second}
	start := time.Now()
	got := Run(context.Background(), resolvers, Options{Domain: "t", PubKey: "k", Timeout: 200 * time.Millisecond}, v, nil)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("per-resolver timeout not enforced: took %s", elapsed)
	}
	if got[0].OK {
		t.Errorf("timed-out resolver should not be OK: %+v", got[0])
	}
}

func TestRunContextCancel(t *testing.T) {
	resolvers := make([]string, 50)
	for i := range resolvers {
		resolvers[i] = "192.0.2." + strconv.Itoa(i)
	}
	v := &fakeValidator{sleep: 100 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	got := Run(ctx, resolvers, Options{Domain: "t", PubKey: "k", Concurrency: 2}, v, nil)
	if len(got) != len(resolvers) {
		t.Fatalf("expected one verdict per resolver even on cancel, got %d", len(got))
	}
	// At least the tail should be marked cancelled.
	cancelled := 0
	for _, r := range got {
		if r.Reason == "cancelled" {
			cancelled++
		}
	}
	if cancelled == 0 {
		t.Errorf("expected some resolvers marked cancelled")
	}
}

func TestNormalizeResolver(t *testing.T) {
	cases := map[string]string{
		"8.8.8.8":      "8.8.8.8:53",
		"8.8.8.8:5353": "8.8.8.8:5353",
		" 1.1.1.1 ":    "1.1.1.1:53",
		"not-an-ip":    "",
		"1.2.3.4:":     "",
		"example.com":  "",
	}
	for in, want := range cases {
		got, err := normalizeResolver(in, TransportUDP)
		if want == "" {
			if err == nil {
				t.Errorf("normalizeResolver(%q): expected error, got %q", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("normalizeResolver(%q) = %q,%v want %q", in, got, err, want)
		}
	}
}
