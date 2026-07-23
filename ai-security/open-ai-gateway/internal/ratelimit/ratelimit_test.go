package ratelimit

import (
	"testing"
	"time"
)

func TestRequestRateLimit(t *testing.T) {
	l := New(Limits{RequestsPerMinute: 2})
	now := time.Now()
	if !l.AllowRequest("k", now) || !l.AllowRequest("k", now) {
		t.Fatal("first two requests should be allowed")
	}
	if l.AllowRequest("k", now) {
		t.Fatal("third request should be denied")
	}
	// New window resets the counter.
	if !l.AllowRequest("k", now.Add(61*time.Second)) {
		t.Fatal("request after window should be allowed")
	}
}

func TestTokenBudget(t *testing.T) {
	l := New(Limits{BudgetTokens: 100})
	if !l.RecordUsage("k", 60) {
		t.Fatal("within budget should be ok")
	}
	if l.RecordUsage("k", 60) {
		t.Fatal("exceeding budget should report false")
	}
	tokens, _ := l.Usage("k")
	if tokens != 120 {
		t.Fatalf("expected 120 tokens recorded, got %d", tokens)
	}
}
