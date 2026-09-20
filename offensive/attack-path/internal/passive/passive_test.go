// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package passive

import (
	"testing"

	"github.com/Schildkrote/attack-path/internal/graph"
)

func TestStaticResolve(t *testing.T) {
	s := NewStatic()
	r, err := s.Resolve("example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Domain != "example.com" {
		t.Fatalf("domain = %q", r.Domain)
	}
	if len(r.Records) == 0 || len(r.Certs) == 0 || len(r.Techs) == 0 {
		t.Fatalf("incomplete report: %+v", r)
	}
}

func TestStaticResolveSubdomain(t *testing.T) {
	s := NewStatic()
	r, err := s.Resolve("www.example.com")
	if err != nil {
		t.Fatalf("Resolve subdomain: %v", err)
	}
	if r.Domain != "www.example.com" {
		t.Fatalf("domain = %q", r.Domain)
	}
}

func TestStaticResolveUnknown(t *testing.T) {
	s := NewStatic()
	if _, err := s.Resolve("unknown.example.net"); err == nil {
		t.Fatal("unknown domain should error")
	}
}

func TestAddDomainExposures(t *testing.T) {
	g := graph.New()
	s := NewStatic()
	n, err := AddDomainExposures(g, s, "example.com")
	if err != nil {
		t.Fatalf("AddDomainExposures: %v", err)
	}
	if n < 2 {
		t.Fatalf("added %d nodes, want >=2 (domain + A record)", n)
	}
	if !g.HasNode("domain:example.com") {
		t.Fatal("domain node missing")
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"EXAMPLE.com":            "example.com",
		"https://example.com/":   "example.com",
		"http://www.example.com": "www.example.com",
		"  example.com  ":        "example.com",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
