// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"testing"
)

func TestMockDeterministic(t *testing.T) {
	m := NewMock()
	ctx := context.Background()
	r1, err := m.Probe(ctx, "github", "https://github.com/alice", "alice")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	r2, _ := m.Probe(ctx, "github", "https://github.com/alice", "alice")
	if r1.Found != r2.Found {
		t.Fatal("mock should be deterministic")
	}
	if r1.Service != "github" || r1.URL == "" {
		t.Fatalf("unexpected result: %+v", r1)
	}
}

func TestMockHitRatio(t *testing.T) {
	m := NewMock()
	m.HitRatio = 1.0
	r, _ := m.Probe(context.Background(), "x", "u", "u")
	if !r.Found {
		t.Fatal("HitRatio 1.0 should always hit")
	}
	m.HitRatio = 0
	r, _ = m.Probe(context.Background(), "x", "u", "u")
	if r.Found {
		t.Fatal("HitRatio 0 should never hit")
	}
}
