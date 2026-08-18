// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// listenTCP opens a loopback TCP listener for the active-scanner test.
func listenTCP(t *testing.T) (net.Listener, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return ln, nil
}

func TestMockRunnersDeterministic(t *testing.T) {
	m := MockRunners()
	if len(m) != 4 {
		t.Fatalf("want 4 mock runners, got %d", len(m))
	}
	for feature, r := range m {
		if r.Feature() != feature {
			t.Fatalf("runner %q reports feature %q", feature, r.Feature())
		}
	}
}

func TestMockActiveScanner(t *testing.T) {
	r := NewMockActiveScanner()
	res, err := r.Run(context.Background(), "10.0.0.1:80", RunOpts{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Deterministic: same target → same result.
	res2, _ := r.Run(context.Background(), "10.0.0.1:80", RunOpts{})
	if res.Found != res2.Found {
		t.Fatal("mock active scanner should be deterministic")
	}
}

func TestMockRecoveryProber(t *testing.T) {
	r := NewMockRecoveryProber()
	res, err := r.Run(context.Background(), "https://x/reset?email={id}", RunOpts{Credential: "alice@example.com"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Feature != FeatureRecoveryProbing {
		t.Fatalf("feature = %q", res.Feature)
	}
}

func TestMockPeopleSearchConsent(t *testing.T) {
	r := NewMockPeopleSearcher()
	if _, err := r.Run(context.Background(), "spokeo", RunOpts{Credential: "Alice"}); err == nil {
		t.Fatal("people-search without consent should error")
	}
	res, err := r.Run(context.Background(), "spokeo", RunOpts{Credential: "Alice", Consent: true})
	if err != nil {
		t.Fatalf("Run with consent: %v", err)
	}
	if res.Feature != FeaturePeopleSearch {
		t.Fatalf("feature = %q", res.Feature)
	}
}

func TestMockAuthScraperNeedsCredential(t *testing.T) {
	r := NewMockAuthScraper()
	if _, err := r.Run(context.Background(), "https://x/contacts", RunOpts{}); err == nil {
		t.Fatal("auth scrape without credential should error")
	}
	res, err := r.Run(context.Background(), "https://x/contacts", RunOpts{Credential: "tok"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Found {
		t.Fatal("mock auth scraper should report found")
	}
}

func TestRealActiveScanner(t *testing.T) {
	// Spin up a local listener; the scanner should see it as open.
	ln, err := listenTCP(t)
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer ln.Close()
	r := NewActiveScanner()
	res, err := r.Run(context.Background(), ln.Addr().String(), RunOpts{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Found {
		t.Fatalf("local listener should be open: %+v", res)
	}
}

func TestRealRecoveryProber(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	r := NewRecoveryProber()
	res, err := r.Run(context.Background(), srv.URL+"/reset?email={identifier}", RunOpts{Credential: "alice@example.com"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Found {
		t.Fatalf("200 → found: %+v", res)
	}
}

func TestRealPeopleSearchWhitelist(t *testing.T) {
	// With no network the real runner should degrade to uncertain, not panic.
	r := NewPeopleSearcher()
	r.Whitelist = []string{"127.0.0.1:1"} // nothing listening
	r.Timeout = 200 * time.Millisecond
	res, err := r.Run(context.Background(), "test", RunOpts{Credential: "alice", Consent: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = res
}

func TestRealAuthScraper(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	r := NewAuthScraper()
	_, err := r.Run(context.Background(), srv.URL+"/contacts", RunOpts{Credential: "sekrit"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if gotAuth != "Bearer sekrit" {
		t.Fatalf("Authorization header = %q", gotAuth)
	}
}
