// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package probe mock implementations: deterministic, offline, CI-safe. Each
// mock mirrors one real Runner and returns a fixed, clearly-synthetic result
// so the gate/audit plumbing can be exercised without network access.
package probe

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"
)

// mockHash gives a deterministic 0..1 value from a string.
func mockHash(s string) float64 {
	h := fnv.New32a()
	fmt.Fprint(h, s)
	return float64(h.Sum32()) / 4294967295.0
}

// MockActiveScanner simulates a TCP/HTTP probe: a target is "open" when the
// mock hash of the target is in the top third.
type MockActiveScanner struct{}

func NewMockActiveScanner() *MockActiveScanner { return &MockActiveScanner{} }
func (m *MockActiveScanner) Name() string      { return "mock-active-scanner" }
func (m *MockActiveScanner) Feature() string   { return FeatureActiveScanning }

func (m *MockActiveScanner) Run(_ context.Context, target string, _ RunOpts) (*ProbeResult, error) {
	open := mockHash("tcp:"+target) < 1/3
	res := &ProbeResult{Feature: m.Feature(), Target: target, Found: open}
	if open {
		res.Detail = "tcp open (mock)"
		res.Evidence = map[string]any{"host": target, "port": target}
	} else {
		res.Detail = "tcp closed (mock)"
	}
	return res, nil
}

// MockRecoveryProber simulates a reset-flow probe: "found" (account exists)
// when the mock hash of the identifier is in the top third.
type MockRecoveryProber struct{}

func NewMockRecoveryProber() *MockRecoveryProber { return &MockRecoveryProber{} }
func (m *MockRecoveryProber) Name() string       { return "mock-recovery-prober" }
func (m *MockRecoveryProber) Feature() string    { return FeatureRecoveryProbing }

func (m *MockRecoveryProber) Run(_ context.Context, target string, opts RunOpts) (*ProbeResult, error) {
	ident := opts.Credential
	found := mockHash("reset:"+ident) < 1/3
	res := &ProbeResult{Feature: m.Feature(), Target: target, Found: found}
	if found {
		res.Detail = "differential: account likely exists (mock)"
	} else {
		res.Detail = "differential: no account (mock)"
	}
	return res, nil
}

// MockPeopleSearcher simulates a people-search hit: "found" when the mock
// hash of the query term is in the top third. Requires consent, like the
// real runner.
type MockPeopleSearcher struct{}

func NewMockPeopleSearcher() *MockPeopleSearcher { return &MockPeopleSearcher{} }
func (m *MockPeopleSearcher) Name() string       { return "mock-people-searcher" }
func (m *MockPeopleSearcher) Feature() string    { return FeaturePeopleSearch }

func (m *MockPeopleSearcher) Run(_ context.Context, target string, opts RunOpts) (*ProbeResult, error) {
	if !opts.Consent {
		return nil, fmt.Errorf("people-search requires subject consent (--consent)")
	}
	found := mockHash("people:"+opts.Credential) < 1/3
	res := &ProbeResult{Feature: m.Feature(), Target: target, Found: found}
	if found {
		res.Detail = "1 record (mock, redacted)"
		res.Evidence = map[string]any{"source": "mock", "records": 1}
	} else {
		res.Detail = "no records (mock)"
	}
	return res, nil
}

// MockAuthScraper simulates an authenticated scrape: always "found" with a
// fixed harvested-contact count, so the audit plumbing is exercised.
type MockAuthScraper struct{}

func NewMockAuthScraper() *MockAuthScraper { return &MockAuthScraper{} }
func (m *MockAuthScraper) Name() string    { return "mock-auth-scraper" }
func (m *MockAuthScraper) Feature() string { return FeatureAuthenticatedScrape }

func (m *MockAuthScraper) Run(_ context.Context, target string, opts RunOpts) (*ProbeResult, error) {
	if opts.Credential == "" {
		return nil, fmt.Errorf("authenticated-scrape requires a credential (env var)")
	}
	res := &ProbeResult{Feature: m.Feature(), Target: target, Found: true}
	res.Detail = "harvested 3 contacts (mock, redacted)"
	res.Evidence = map[string]any{"contacts": 3, "source": "mock"}
	return res, nil
}

// Runners returns a feature→Runner map for the mock set, for CLI use.
func MockRunners() map[string]Runner {
	return map[string]Runner{
		FeatureActiveScanning:      NewMockActiveScanner(),
		FeatureRecoveryProbing:     NewMockRecoveryProber(),
		FeaturePeopleSearch:        NewMockPeopleSearcher(),
		FeatureAuthenticatedScrape: NewMockAuthScraper(),
	}
}

// RealRunners returns a feature→Runner map for the real set (live-gated).
func RealRunners() map[string]Runner {
	return map[string]Runner{
		FeatureActiveScanning:      NewActiveScanner(),
		FeatureRecoveryProbing:     NewRecoveryProber(),
		FeaturePeopleSearch:        NewPeopleSearcher(),
		FeatureAuthenticatedScrape: NewAuthScraper(),
	}
}

// AllFeatures lists the four live features in canonical order.
func AllFeatures() []string {
	return []string{
		FeatureActiveScanning,
		FeatureRecoveryProbing,
		FeaturePeopleSearch,
		FeatureAuthenticatedScrape,
	}
}

// Enabled reports whether feature is in the enabled set.
func Enabled(enabled []string, feature string) bool {
	for _, f := range enabled {
		if f == feature {
			return true
		}
	}
	return false
}

// TrimSpace is a small helper kept local to avoid a strings import in every
// file that needs it.
func TrimSpace(s string) string { return strings.TrimSpace(s) }
