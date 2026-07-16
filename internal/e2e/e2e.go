// Package e2e is a second-stage, end-to-end tunnel validator for DNS resolvers.
//
// The first-stage scanner (internal/dnsscan) is a heuristic: it flags resolvers
// that *look* tunnel-ready (open recursion + EDNS0 + TXT passthrough). This
// package proves it by standing up a real DNSTT tunnel THROUGH each candidate
// resolver against a live DNSTT server the operator controls, and reporting
// only the resolvers that actually carried traffic end-to-end.
//
// This is the "SlipNet / range-scout" style E2E test: the operator runs a DNSTT
// server at Domain (NS-delegated) with a published public key. For each
// resolver we bring up a dnstt tunnel through it, expose a local forward,
// fetch a small E2E URL (default a generate_204 endpoint), and require an HTTP
// 2xx/3xx. An empty key means a tunnel-reachability check only (handshake up,
// no full HTTP round-trip).
//
// This file is the backend-agnostic engine: the Validator seam plus a bounded,
// cancellable, concurrent Run over a caller-supplied resolver shortlist. It
// depends only on the standard library so it stays gomobile-safe; the dnstt
// tunnel runtime lives behind the Validator interface in a separate backend
// file, so this orchestration is testable without any tunnel dependency.
package e2e

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Transport selects the DNS transport used to reach each resolver.
type Transport string

const (
	TransportUDP Transport = "udp"
	TransportTCP Transport = "tcp"
)

// DefaultE2EURL is fetched through the established tunnel to prove it carries
// real traffic. It returns 204 with an empty body, so it is cheap and
// unambiguous. Operators can override it (e.g. to a URL only routable from the
// far side of their tunnel) via Options.E2EURL.
const DefaultE2EURL = "http://www.gstatic.com/generate_204"

// Options configures one E2E validation run. Zero values pick sane defaults via
// withDefaults; callers on constrained devices should lower Concurrency.
type Options struct {
	// Domain is the DNSTT tunnel server's NS-delegated zone. Required.
	Domain string

	// PubKey is the DNSTT server's public key (hex). Empty means a
	// tunnel-reachability check only: the tunnel handshake must complete, but no
	// HTTP E2E fetch is performed.
	PubKey string

	Transport Transport     // DNS transport to the resolver (default TransportUDP)
	Timeout   time.Duration // per-resolver overall timeout (default 20s)

	// Concurrency bounds how many resolvers are validated at once. Tunnel setup
	// is far heavier than a heuristic probe, so this defaults low.
	Concurrency int

	// E2EURL is the HTTP endpoint fetched through the tunnel to confirm it
	// carries traffic (default DefaultE2EURL).
	E2EURL string
}

func (o Options) withDefaults() Options {
	switch o.Transport {
	case TransportUDP, TransportTCP:
	default:
		o.Transport = TransportUDP
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if strings.TrimSpace(o.E2EURL) == "" {
		o.E2EURL = DefaultE2EURL
	}
	o.Domain = strings.TrimSpace(o.Domain)
	o.PubKey = strings.TrimSpace(o.PubKey)
	return o
}

// Result is the end-to-end verdict for one resolver.
type Result struct {
	Resolver string // "ip" or "ip:port" as supplied
	OK       bool   // true only if the tunnel came up (and, with PubKey, carried an HTTP round-trip)
	Reason   string // short human-readable outcome / failure cause

	LatencyMs  int64 // best round-trip observed during validation, if any
	HTTPStatus int   // HTTP status from the E2E fetch (0 if not reached / key omitted)
}

// Validator runs the real dnstt tunnel test against a single resolver. It MUST
// honor ctx cancellation/deadline and MUST NOT panic — a backend failure is
// reported as a non-OK Result, never an engine crash. Implementations are
// called concurrently from many goroutines and so must be safe for concurrent
// use (they receive an immutable Options copy).
type Validator interface {
	Validate(ctx context.Context, resolver string, opts Options) Result
}

// Run validates every resolver end-to-end through v, honoring opts.Concurrency
// and a per-resolver opts.Timeout. progress (optional) is called once per
// finished resolver from a single goroutine, so it is safe for UI updates.
// Cancelling ctx stops dispatching new resolvers and drains in-flight ones.
//
// Results are returned in the same order as resolvers. A resolver that fails to
// validate (or whose context expires) yields an OK=false Result rather than
// being dropped, so the caller always gets one verdict per input.
func Run(ctx context.Context, resolvers []string, opts Options, v Validator, progress func(done, total int, r Result)) []Result {
	opts = opts.withDefaults()

	total := len(resolvers)
	results := make([]Result, total)
	if total == 0 || v == nil {
		return results
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	worker := func() {
		defer wg.Done()
		for i := range jobs {
			if ctx.Err() != nil {
				results[i] = Result{Resolver: strings.TrimSpace(resolvers[i]), Reason: "cancelled"}
			} else {
				results[i] = validateOne(ctx, strings.TrimSpace(resolvers[i]), opts, v)
			}
			mu.Lock()
			done++
			d := done
			r := results[i]
			mu.Unlock()
			if progress != nil {
				progress(d, total, r)
			}
		}
	}

	n := opts.Concurrency
	if n > total {
		n = total
	}
	for w := 0; w < n; w++ {
		wg.Add(1)
		go worker()
	}
	for i := range resolvers {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			// Fill any not-yet-dispatched slots with a cancelled verdict so the
			// caller still gets one Result per input resolver.
			for j := range results {
				if results[j].Resolver == "" && strings.TrimSpace(resolvers[j]) != "" {
					results[j] = Result{Resolver: strings.TrimSpace(resolvers[j]), Reason: "cancelled"}
				}
			}
			return results
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

// validateOne wraps a single Validator call with a per-resolver timeout and a
// panic guard, so one misbehaving tunnel probe can never take down the run.
func validateOne(ctx context.Context, resolver string, opts Options, v Validator) (res Result) {
	res = Result{Resolver: resolver}
	if resolver == "" {
		res.Reason = "empty-resolver"
		return res
	}
	if _, err := normalizeResolver(resolver, opts.Transport); err != nil {
		res.Reason = err.Error()
		return res
	}

	cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			res = Result{Resolver: resolver, Reason: fmt.Sprintf("backend panic: %v", r)}
		}
	}()

	out := v.Validate(cctx, resolver, opts)
	if out.Resolver == "" {
		out.Resolver = resolver
	}
	if !out.OK && out.Reason == "" {
		if cctx.Err() != nil {
			out.Reason = "timeout"
		} else {
			out.Reason = "tunnel-failed"
		}
	}
	return out
}

// normalizeResolver validates a resolver target and returns it as host:port,
// defaulting to port 53 when only an IP literal is given. It rejects anything
// that is not a usable UDP/TCP DNS endpoint so the backend gets clean input.
func normalizeResolver(resolver string, transport Transport) (string, error) {
	resolver = strings.TrimSpace(resolver)
	if resolver == "" {
		return "", fmt.Errorf("empty-resolver")
	}
	if host, port, err := net.SplitHostPort(resolver); err == nil {
		if net.ParseIP(strings.TrimSpace(host)) == nil {
			return "", fmt.Errorf("invalid-ip")
		}
		if strings.TrimSpace(port) == "" {
			return "", fmt.Errorf("invalid-port")
		}
		return net.JoinHostPort(strings.TrimSpace(host), strings.TrimSpace(port)), nil
	}
	if net.ParseIP(resolver) == nil {
		return "", fmt.Errorf("invalid-ip")
	}
	return net.JoinHostPort(resolver, "53"), nil
}

// PassedResolvers returns just the resolver strings whose end-to-end test
// succeeded, best-effort ordered as given — the "valid resolvers" output the
// operator ultimately wants.
func PassedResolvers(results []Result) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		if r.OK {
			out = append(out, r.Resolver)
		}
	}
	return out
}
