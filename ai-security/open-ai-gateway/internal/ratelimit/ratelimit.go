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

// HasBudget reports whether ANY cumulative budget (tokens or dollars) is
// configured for this limiter. It exists so callers can distinguish "no budget
// was configured, so nothing can be exceeded" from "a budget was configured and
// this response could not be accounted against it". Collapsing those two cases
// is what made token-budget enforcement decorative: an unaccountable completion
// served under an active budget is a bypass, while the same completion served
// under no budget is simply unthrottled by design.
func (l *Limiter) HasBudget() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limits.BudgetTokens > 0 || l.limits.BudgetDollars > 0
}

// OverBudget reports whether a key has already exhausted a configured cumulative
// budget. It exists so the gateway can deny BEFORE forwarding a request upstream,
// rather than only discovering the overage after the tokens have been spent.
// Returns false when no budget is configured, because there is then nothing to
// exceed - that is a deliberate configuration, not a failure to enforce.
func (l *Limiter) OverBudget(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		return false
	}
	if l.limits.BudgetTokens > 0 && b.tokens >= l.limits.BudgetTokens {
		return true
	}
	if l.limits.BudgetDollars > 0 && b.dollars >= l.limits.BudgetDollars {
		return true
	}
	return false
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
