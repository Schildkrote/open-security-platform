// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hibpRangeHandler emulates the HIBP /range/{prefix} endpoint: it returns
// lines of "SUFFIX:count" for a known full hash.
func hibpRangeHandler(foundHash string, count int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		prefix := r.URL.Path[len("/range/"):]
		if len(prefix) != 5 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		lines := []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAA:12"}
		if foundHash != "" {
			lines = append(lines, foundHash[5:]+":"+itoa(count))
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Join(lines, "\n")))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestHIBPPwned(t *testing.T) {
	// SHA-1 of "alice@example.com" — compute at test time.
	full := sha1Hex("alice@example.com")
	srv := httptest.NewServer(hibpRangeHandler(full, 42))
	defer srv.Close()

	h := NewHIBP()
	h.BaseURL = srv.URL
	a, err := h.Pwned(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Pwned: %v", err)
	}
	if !a.Pwned {
		t.Fatalf("want pwned, got %+v", a)
	}
	if a.Count != 42 {
		t.Fatalf("count = %d, want 42", a.Count)
	}
	if a.IdentifierHash != full {
		t.Fatalf("hash mismatch: %s != %s", a.IdentifierHash, full)
	}
}

func TestHIBPNotPwned(t *testing.T) {
	srv := httptest.NewServer(hibpRangeHandler("", 0))
	defer srv.Close()

	h := NewHIBP()
	h.BaseURL = srv.URL
	a, err := h.Pwned(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("Pwned: %v", err)
	}
	if a.Pwned {
		t.Fatalf("want not pwned, got %+v", a)
	}
}

func TestHIBPRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	h := NewHIBP()
	h.BaseURL = srv.URL
	a, err := h.Pwned(context.Background(), "x@example.com")
	if err == nil {
		t.Fatal("want error on 429")
	}
	if !a.Uncertain {
		t.Fatalf("429 should mark uncertain: %+v", a)
	}
}

func TestHIBPEmptyIdentifier(t *testing.T) {
	h := NewHIBP()
	if _, err := h.Pwned(context.Background(), ""); err == nil {
		t.Fatal("empty identifier should error")
	}
}
