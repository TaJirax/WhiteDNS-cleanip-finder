package dnsscan

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterSpacesQueriesPerScope(t *testing.T) {
	if NewRateLimiter(0, 0, 1, 0) != nil {
		t.Fatal("zero rates must stay unlimited")
	}
	now := time.Now()
	l := NewRateLimiter(10, 0, 1, 0) // 100 ms apart, whole scan
	for i, want := range []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond} {
		if got := l.schedule(now, "192.0.2.1"); got != want {
			t.Fatalf("query %d waits %v, want %v", i, got, want)
		}
	}
	per := NewRateLimiter(0, 10, 2, 0) // per resolver, burst of two
	if per.schedule(now, "a") != 0 || per.schedule(now, "a") != 0 || per.schedule(now, "a") != 100*time.Millisecond {
		t.Fatal("burst must allow two back-to-back queries, then space them")
	}
	if per.schedule(now, "b") != 0 {
		t.Fatal("another resolver has its own slot")
	}
	ctx, cancel := context.WithCancel(WithRateLimiter(context.Background(), NewRateLimiter(1, 0, 1, 0)))
	if !waitDNSQuery(ctx, "a") {
		t.Fatal("first query waits for nothing")
	}
	cancel()
	if waitDNSQuery(ctx, "a") {
		t.Fatal("a stopped scan must not keep waiting")
	}
}
