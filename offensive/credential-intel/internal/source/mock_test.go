// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package source

import (
	"context"
	"testing"
)

func TestMockPwned(t *testing.T) {
	m := NewMock()
	a, err := m.Pwned(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Pwned: %v", err)
	}
	if !a.Pwned {
		t.Fatal("alice@example.com should be pwned in the sample")
	}
	if a.Count != 1 {
		t.Fatalf("count = %d, want 1", a.Count)
	}
	if len(a.Breaches) != 1 || a.Breaches[0].Title != "ExampleCorp Data Incident" {
		t.Fatalf("breaches = %+v", a.Breaches)
	}
	if a.IdentifierHash == "" {
		t.Fatal("answer must carry the redacted SHA-1 hash")
	}
}

func TestMockNotPwned(t *testing.T) {
	m := NewMock()
	a, err := m.Pwned(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("Pwned: %v", err)
	}
	if a.Pwned {
		t.Fatal("nobody@example.com should not be pwned")
	}
}

func TestMockEmptyIdentifier(t *testing.T) {
	m := NewMock()
	if _, err := m.Pwned(context.Background(), "  "); err == nil {
		t.Fatal("empty identifier should error")
	}
}

func TestMockCaseInsensitive(t *testing.T) {
	m := NewMock()
	a, _ := m.Pwned(context.Background(), "Alice@Example.COM")
	if !a.Pwned {
		t.Fatal("lookup should be case-insensitive")
	}
}
