// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPDifferential verifies found/not-found detection via response-code
// differentials against a local test server (offline in CI).
func TestHTTPDifferential(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Account URLs return 200; not-found tokens 404.
		if r.URL.Path == "/alice" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	_ = srv

	h := NewHTTP()
	r, err := h.Probe(context.Background(), "test", srv.URL+"/{username}", "alice")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !r.Found {
		t.Fatalf("want found=true (200 vs 404 differential), got %+v", r)
	}
}

func TestHTTPUncertainNoDifferential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // same code for both
	}))
	defer srv.Close()

	h := NewHTTP()
	r, err := h.Probe(context.Background(), "test", srv.URL+"/{username}", "bob")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if r.Found {
		t.Fatalf("403-everywhere should not report found: %+v", r)
	}
	if !r.Uncertain {
		t.Fatalf("403-everywhere should be uncertain: %+v", r)
	}
}

func TestHTTPRejectsBadScheme(t *testing.T) {
	h := NewHTTP()
	_, err := h.Probe(context.Background(), "test", "ftp://example.com/{username}", "carol")
	if err == nil {
		t.Fatal("want error for ftp scheme")
	}
}
