package router

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// NewRouter creates a new Router instance
func NewRouter(cfg *RouterConfig) *Router {
	if cfg == nil {
		cfg = &RouterConfig{
			L1CacheTTLMs:           30000,  // 30 seconds
			L2CacheTTLMs:           300000, // 5 minutes
			HistoryTTLSec:          60,
			RaceMaxConcurrency:     4,
			RaceTimeoutMs:          8000,
			FailureQuarantineSec:   600,
			MaxPrimaryCandidates:   12,
			MaxSecondaryCandidates: 6,
		}
	}

	return &Router{
		domainCaches:   make(map[string]*DomainCache),
		endpointStats:  make(map[string]*EndpointStats),
		raceInProgress: make(map[string]bool),
		raceSem:        make(chan struct{}, cfg.RaceMaxConcurrency),
		config:         cfg,
		sessionMetrics: &SessionMetrics{
			StartTime: time.Now(),
		},
	}
}

// ResolveRoute finds the best endpoint for a domain
func (r *Router) ResolveRoute(domain string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cache, exists := r.domainCaches[domain]
	if !exists {
		cache = &DomainCache{
			ExpiryTime: time.Duration(r.config.L1CacheTTLMs) * time.Millisecond,
			History:    make(map[string]time.Time),
		}
		r.domainCaches[domain] = cache
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	// Clean expired entries
	r.cleanExpiredRoutes(cache)

	// L1 cache hit
	if len(cache.Primary) > 0 && time.Since(cache.Primary[0].LastUsed) < cache.ExpiryTime {
		r.recordL1Hit(domain)
		return cache.Primary[0].Endpoint, true
	}

	// L2 cache hit
	if len(cache.Secondary) > 0 {
		r.recordL2Hit(domain)
		ep := cache.Secondary[0].Endpoint
		// Promote to primary
		cache.Primary = []RouteEntry{{
			Endpoint:   ep,
			LatencyMs:  cache.Secondary[0].LatencyMs,
			LastUsed:   time.Now(),
			Score:      cache.Secondary[0].Score,
			IsVerified: cache.Secondary[0].IsVerified,
		}}
		return ep, true
	}

	// Cache miss
	return "", false
}

// RaceEndpoints runs a concurrent race to find fastest endpoint
func (r *Router) RaceEndpoints(domain string, candidates []string, timeout time.Duration) RaceCandidate {
	if len(candidates) == 0 {
		return RaceCandidate{}
	}

	// Limit concurrency
	r.raceSem <- struct{}{}
	defer func() { <-r.raceSem }()

	winChan := make(chan RaceCandidate, 1)

	// Concurrent connection attempts
	wg := sync.WaitGroup{}
	done := atomic.Bool{}

	for _, ep := range candidates {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			if done.Load() {
				return
			}

			// Try to connect
			start := time.Now()
			latency := r.probeEndpoint(endpoint, timeout)

			if latency > 0 {
				candidate := RaceCandidate{
					Endpoint:   endpoint,
					LatencyMs:  latency.Seconds() * 1000,
					WinTime:    start,
					WinLatency: latency,
				}

				// Attempt to win race
				select {
				case winChan <- candidate:
					done.Store(true)
					wg.Wait() // Let others finish gracefully
				default:
					// Another won
				}
			}
		}(ep)
	}

	// Wait with timeout
	ticker := time.NewTicker(timeout)
	defer ticker.Stop()

	var winner RaceCandidate
	select {
	case winner = <-winChan:
		r.recordRaceWin(domain, winner)
	case <-ticker.C:
		r.recordRaceFailure(domain)
	}

	wg.Wait()
	return winner
}

// RecordEndpointSuccess marks endpoint as working
func (r *Router) RecordEndpointSuccess(endpoint string, latencyMs float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	stats := r.getOrCreateStats(endpoint)
	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.SuccessCount++
	stats.LastSuccessTime = time.Now()
	stats.FailCount = 0
	stats.ConsecutiveFailures = 0

	// EWMA latency
	alpha := 0.2
	if stats.AvgLatencyMs == 0 {
		stats.AvgLatencyMs = latencyMs
	} else {
		stats.AvgLatencyMs = alpha*latencyMs + (1-alpha)*stats.AvgLatencyMs
	}

	// Clear quarantine on success
	stats.QuarantineUntil = time.Time{}
	stats.QuarantineReason = ""
}

// RecordEndpointFailure marks endpoint as failed
func (r *Router) RecordEndpointFailure(endpoint, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	stats := r.getOrCreateStats(endpoint)
	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.FailCount++
	stats.ConsecutiveFailures++
	stats.LastFailTime = time.Now()

	// Auto-quarantine
	if stats.ConsecutiveFailures >= 3 {
		stats.QuarantineUntil = time.Now().Add(time.Duration(r.config.FailureQuarantineSec) * time.Second)
		stats.QuarantineReason = reason
	}
}

// IsEndpointQuarantined checks quarantine status
func (r *Router) IsEndpointQuarantined(endpoint string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats, exists := r.endpointStats[endpoint]
	if !exists {
		return false
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if stats.QuarantineUntil.IsZero() {
		return false
	}

	return time.Now().Before(stats.QuarantineUntil)
}

// AddRouteToCache adds endpoint to domain's route cache
func (r *Router) AddRouteToCache(domain, endpoint string, latencyMs float64, isVerified bool) {
	r.mu.Lock()
	cache, exists := r.domainCaches[domain]
	if !exists {
		cache = &DomainCache{
			ExpiryTime: time.Duration(r.config.L1CacheTTLMs) * time.Millisecond,
			History:    make(map[string]time.Time),
		}
		r.domainCaches[domain] = cache
	}
	r.mu.Unlock()

	cache.mu.Lock()
	defer cache.mu.Unlock()

	entry := RouteEntry{
		Endpoint:   endpoint,
		LatencyMs:  latencyMs,
		LastUsed:   time.Now(),
		Score:      latencyMs,
		IsVerified: isVerified,
	}

	// Add to primary (hot)
	cache.Primary = append([]RouteEntry{entry}, cache.Primary...)
	if len(cache.Primary) > r.config.MaxPrimaryCandidates {
		cache.Primary = cache.Primary[:r.config.MaxPrimaryCandidates]
	}
}

// ClearDomainCache removes all routes for a domain
func (r *Router) ClearDomainCache(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.domainCaches, domain)
}

// ClearAllRoutes removes all cached routes
func (r *Router) ClearAllRoutes() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.domainCaches = make(map[string]*DomainCache)
}

// GetSessionMetrics returns a copy of session stats. Fields are protected by
// sessionMetrics.mu (see RecordHotStart/RecordColdStart/etc.), not r.mu, so
// that lock is used here too; copying the struct by value would also copy its
// embedded mutex, which is invalid, so each field is copied individually.
func (r *Router) GetSessionMetrics() SessionMetrics {
	m := r.sessionMetrics
	m.mu.RLock()
	defer m.mu.RUnlock()

	return SessionMetrics{
		StartTime:           m.StartTime,
		TotalRequests:       m.TotalRequests,
		HotStarts:           m.HotStarts,
		ColdStarts:          m.ColdStarts,
		L1Hits:              m.L1Hits,
		L2Hits:              m.L2Hits,
		RacesStarted:        m.RacesStarted,
		RaceWins:            m.RaceWins,
		RaceFailures:        m.RaceFailures,
		RaceTimesMs:         append([]float64(nil), m.RaceTimesMs...),
		SelectedLatenciesMs: append([]float64(nil), m.SelectedLatenciesMs...),
		Reroutes:            m.Reroutes,
		RerouteTimesMs:      append([]float64(nil), m.RerouteTimesMs...),
	}
}

// Helper methods
func (r *Router) getOrCreateStats(endpoint string) *EndpointStats {
	stats, exists := r.endpointStats[endpoint]
	if !exists {
		stats = &EndpointStats{}
		r.endpointStats[endpoint] = stats
	}
	return stats
}

func (r *Router) cleanExpiredRoutes(cache *DomainCache) {
	now := time.Now()
	ttl := time.Duration(r.config.L2CacheTTLMs) * time.Millisecond

	// Clean primary
	for i, entry := range cache.Primary {
		if now.Sub(entry.LastUsed) > ttl {
			cache.Primary = cache.Primary[i:]
			break
		}
	}

	// Clean secondary
	for i, entry := range cache.Secondary {
		if now.Sub(entry.LastUsed) > ttl {
			cache.Secondary = cache.Secondary[i:]
			break
		}
	}

	// Clean history
	for endpoint, timestamp := range cache.History {
		if now.Sub(timestamp) > time.Duration(r.config.HistoryTTLSec)*time.Second {
			delete(cache.History, endpoint)
		}
	}
}

func (r *Router) probeEndpoint(endpoint string, timeout time.Duration) time.Duration {
	// TCP connect with timeout
	// Simplified: just return a small latency to indicate success
	// In real implementation, this would do TCP/TLS handshake
	return time.Millisecond
}

func (r *Router) recordL1Hit(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sessionMetrics.mu.Lock()
	defer r.sessionMetrics.mu.Unlock()

	r.sessionMetrics.TotalRequests++
	r.sessionMetrics.HotStarts++
	r.sessionMetrics.L1Hits++
}

func (r *Router) recordL2Hit(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sessionMetrics.mu.Lock()
	defer r.sessionMetrics.mu.Unlock()

	r.sessionMetrics.TotalRequests++
	r.sessionMetrics.ColdStarts++
	r.sessionMetrics.L2Hits++
}

func (r *Router) recordRaceWin(domain string, candidate RaceCandidate) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sessionMetrics.mu.Lock()
	defer r.sessionMetrics.mu.Unlock()

	r.sessionMetrics.RacesStarted++
	r.sessionMetrics.RaceWins++
	r.sessionMetrics.RaceTimesMs = append(r.sessionMetrics.RaceTimesMs, candidate.LatencyMs)
	r.sessionMetrics.SelectedLatenciesMs = append(r.sessionMetrics.SelectedLatenciesMs, candidate.LatencyMs)
}

func (r *Router) recordRaceFailure(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sessionMetrics.mu.Lock()
	defer r.sessionMetrics.mu.Unlock()

	r.sessionMetrics.RacesStarted++
	r.sessionMetrics.RaceFailures++
}

type raceContext struct {
	domain     string
	candidates []string
	winChan    chan RaceCandidate
	timeout    time.Duration
}

// GetEndpointScore returns health score (lower = better)
func (r *Router) GetEndpointScore(endpoint string) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats, exists := r.endpointStats[endpoint]
	if !exists {
		return 700.0 // neutral
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if time.Now().Before(stats.QuarantineUntil) {
		return math.Inf(1) // quarantined
	}

	score := stats.AvgLatencyMs
	failPenalty := float64(stats.FailCount) * 250.0
	return score + failPenalty
}
