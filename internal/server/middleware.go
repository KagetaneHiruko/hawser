package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// AuthRateLimiter tracks failed authentication attempts per IP.
// Only failed attempts are recorded; successful auth is never throttled.
type AuthRateLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	limit    int           // max failures before blocking
	window   time.Duration // sliding window
	maxIPs   int           // cap on tracked IPs to bound memory
}

// NewAuthRateLimiter creates a rate limiter for failed auth attempts.
// Starts a background cleanup goroutine that runs every cleanupInterval.
func NewAuthRateLimiter(limit int, window time.Duration) *AuthRateLimiter {
	rl := &AuthRateLimiter{
		failures: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		maxIPs:   10000, // hard cap to prevent memory exhaustion
	}
	go rl.cleanupLoop()
	return rl
}

// RecordFailure records a failed auth attempt for the given IP.
func (rl *AuthRateLimiter) RecordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Hard cap: if too many IPs tracked, evict all (blunt but bounds memory)
	if len(rl.failures) >= rl.maxIPs {
		rl.failures = make(map[string][]time.Time)
	}

	now := time.Now()
	rl.failures[ip] = append(rl.pruneOld(ip, now), now)
}

// IsBlocked returns true if the IP has exceeded the failure limit.
func (rl *AuthRateLimiter) IsBlocked(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	valid := rl.pruneOld(ip, now)
	rl.failures[ip] = valid
	return len(valid) >= rl.limit
}

// pruneOld removes expired entries for an IP. Caller must hold rl.mu.
func (rl *AuthRateLimiter) pruneOld(ip string, now time.Time) []time.Time {
	cutoff := now.Add(-rl.window)
	var valid []time.Time
	for _, t := range rl.failures[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	return valid
}

// cleanupLoop periodically removes stale entries to bound memory.
func (rl *AuthRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-rl.window)
		for ip, attempts := range rl.failures {
			var valid []time.Time
			for _, t := range attempts {
				if t.After(cutoff) {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(rl.failures, ip)
			} else {
				rl.failures[ip] = valid
			}
		}
		rl.mu.Unlock()
	}
}

// getClientIP extracts the client IP from the request.
// Uses RemoteAddr only — Hawser is a direct-access agent, not behind a reverse proxy,
// so X-Forwarded-For / X-Real-IP headers are attacker-controlled and must not be trusted.
func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RecoveryMiddleware recovers from panics
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
