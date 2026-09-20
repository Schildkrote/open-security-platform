// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package source

import (
	"context"
	"fmt"
	"hash/fnv"
)

// Mock is an offline Source with a deterministic fake hit set. A username is
// "found" on a service when the FNV-1a hash of (service, username) falls in
// the low third of the hash space, so results are stable across runs and
// platforms with no network access.
type Mock struct {
	// HitRatio tunes the fake hit rate (0..1); defaults to 1/3.
	HitRatio float64
}

// NewMock returns a Mock source.
func NewMock() *Mock { return &Mock{HitRatio: 1 / 3} }

// Name implements Source.
func (m *Mock) Name() string { return "mock" }

// Probe implements Source with a deterministic offline fake.
func (m *Mock) Probe(_ context.Context, service, url, username string) (Result, error) {
	if m.HitRatio <= 0 {
		m.HitRatio = 1 / 3
	}
	h := fnv.New32a()
	fmt.Fprintf(h, "%s/%s", service, username)
	found := float64(h.Sum32())/4294967295.0 < m.HitRatio
	return Result{
		Service:   service,
		URL:       url,
		Found:     found,
		Uncertain: false,
		LatencyMS: 0,
	}, nil
}
