// Package ratelimit provides per-key request rate limiting and spend budgets.
package ratelimit

import (
	"sync"
	"time"
)

// Limits configure the ceiling for a single key.
type Limits struct {
	RequestsPerMinute int     // 0 = unlimited
	BudgetTokens      int64   // 0 = unlimited cumulative token budget
	BudgetDollars     float64 // 0 = unlimited cumulative spend
	PricePer1KTokens  float64 // used to convert tokens -> dollars
}

type bucket struct {
	count     int
	windowEnd time.Time
	tokens    int64
	dollars   float64
}

// Limiter tracks usage per key.
type Limiter struct {
	mu      sync.Mutex
	limits  Limits
	buckets map[string]*bucket
}

func New(l Limits) *Limiter {
	return &Limiter{limits: l, buckets: map[string]*bucket{}}
}

// AllowRequest checks and consumes one request slot for the key.
func (l *Limiter) AllowRequest(key string, now time.Time) bool {
	if l.limits.RequestsPerMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucketFor(key, now)
	if b.count >= l.limits.RequestsPerMinute {
		return false
	}
	b.count++
	return true
}

// RecordUsage records token usage and reports whether the key is still
// within its budget.
func (l *Limiter) RecordUsage(key string, tokens int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{}
		l.buckets[key] = b
	}
	b.tokens += tokens
	b.dollars += float64(tokens) / 1000.0 * l.limits.PricePer1KTokens

	if l.limits.BudgetTokens > 0 && b.tokens > l.limits.BudgetTokens {
		return false
	}
	if l.limits.BudgetDollars > 0 && b.dollars > l.limits.BudgetDollars {
		return false
	}
	return true
}

// Usage returns cumulative token and dollar usage for a key.
func (l *Limiter) Usage(key string) (tokens int64, dollars float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.buckets[key]; b != nil {
		return b.tokens, b.dollars
	}
	return 0, 0
}

func (l *Limiter) bucketFor(key string, now time.Time) *bucket {
	b := l.buckets[key]
	if b == nil || now.After(b.windowEnd) {
		b = &bucket{windowEnd: now.Add(time.Minute)}
		l.buckets[key] = b
	}
	return b
}
