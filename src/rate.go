package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type rateEntry struct {
	Limiter  *rate.Limiter
	LastUsed time.Time
}

type rateBook struct {
	mu      sync.Mutex
	entries map[string]rateEntry
}

func newRateBook() *rateBook { return &rateBook{entries: map[string]rateEntry{}} }

func (b *rateBook) allowWindow(key string, window time.Duration, limit int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if window <= 0 || limit <= 0 {
		return false
	}

	entry, ok := b.entries[key]
	if !ok {
		refill := window / time.Duration(limit)
		if refill <= 0 {
			refill = time.Nanosecond
		}

		entry = rateEntry{Limiter: rate.NewLimiter(rate.Every(refill), limit)}
	}

	entry.LastUsed = time.Now()
	b.entries[key] = entry
	return entry.Limiter.Allow()
}

func (b *rateBook) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := time.Now().Add(-15 * time.Minute)

	for key, entry := range b.entries {
		if entry.LastUsed.Before(cutoff) {
			delete(b.entries, key)
		}
	}
}

func requestIP(r *http.Request, trustCloudflare bool) string {
	if trustCloudflare {
		if value := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(value) != nil {
			return value
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	return r.RemoteAddr
}
