// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package passive provides offline-first passive domain intelligence:
// DNS record lookups, certificate transparency history, WHOIS basics, and
// tech-stack fingerprinting. The default source is a static sample (offline,
// CI-safe); a JSON table can be loaded for production use. No outbound
// network calls are made by the default source.
package passive

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DNSRecord is one DNS record for a domain.
type DNSRecord struct {
	Type  string `json:"type"` // A, AAAA, MX, NS, TXT, CNAME
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Cert is one certificate transparency entry.
type Cert struct {
	Domain   string `json:"domain"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	Serial   string `json:"serial"`
}

// Tech is one fingerprinted technology.
type Tech struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Cat     string `json:"category"` // web-server, cms, framework, analytics
}

// Report is the full passive-intel result for one domain.
type Report struct {
	Domain  string            `json:"domain"`
	Records []DNSRecord       `json:"records"`
	Certs   []Cert            `json:"certs"`
	Techs   []Tech            `json:"techs"`
	Whois   map[string]string `json:"whois,omitempty"`
}

// Source resolves a domain to a passive Report.
type Source interface {
	Name() string
	Resolve(domain string) (*Report, error)
}

// Static is a Source backed by an in-memory table (offline, CI-safe).
type Static struct {
	Domains map[string]*Report `json:"domains"`
}

// NewStatic returns a Static source preloaded with the built-in sample.
func NewStatic() *Static {
	s := &Static{Domains: map[string]*Report{}}
	if err := s.LoadTable(BuiltIn()); err != nil {
		// BuiltIn is trusted; ignore parse errors at construction.
	}
	return s
}

// LoadTable loads a JSON table shaped like:
//
//	{"domains": {"example.com": {"records": [...], "certs": [...], "techs": [...], "whois": {...}}}}
func (s *Static) LoadTable(data []byte) error {
	var raw struct {
		Domains map[string]*Report `json:"domains"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse passive table: %w", err)
	}
	for k, v := range raw.Domains {
		v.Domain = k
		s.Domains[k] = v
	}
	return nil
}

// Name implements Source.
func (s *Static) Name() string { return "static" }

// Resolve implements Source. Subdomains are resolved to their parent domain
// when the exact subdomain is not in the table (e.g. "www.example.com" →
// "example.com").
func (s *Static) Resolve(domain string) (*Report, error) {
	domain = normalizeDomain(domain)
	if r, ok := s.Domains[domain]; ok {
		return r, nil
	}
	// Try parent: strip leading subdomain labels one at a time.
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if r, ok := s.Domains[parent]; ok {
			r.Domain = domain
			return r, nil
		}
	}
	return nil, fmt.Errorf("domain %q not in passive table", domain)
}

// normalizeDomain lowercases and strips scheme/path.
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if i := strings.IndexByte(d, '/'); i >= 0 {
		d = d[:i]
	}
	return d
}

// BuiltIn returns the default passive table as JSON. Sample data is
// synthetic; extend with real CT logs / DNS / WHOIS feeds for production.
func BuiltIn() []byte {
	data := map[string]any{
		"domains": map[string]*Report{
			"example.com": {
				Records: []DNSRecord{
					{Type: "A", Name: "example.com", Value: "93.184.216.34"},
					{Type: "MX", Name: "example.com", Value: "mail.example.com"},
					{Type: "TXT", Name: "example.com", Value: "v=spf1 include:_spf.example.com ~all"},
					{Type: "NS", Name: "example.com", Value: "ns1.example.com"},
				},
				Certs: []Cert{
					{Domain: "example.com", Issuer: "Let's Encrypt R11", NotAfter: "2026-11-01", Serial: "01:ab:cd"},
					{Domain: "*.example.com", Issuer: "Let's Encrypt R10", NotAfter: "2026-09-01", Serial: "01:ef:01"},
				},
				Techs: []Tech{
					{Name: "nginx", Version: "1.24.0", Cat: "web-server"},
					{Name: "WordPress", Version: "6.5", Cat: "cms"},
				},
				Whois: map[string]string{
					"registrar": "Example Registrar",
					"created":   "1997-09-14",
					"expires":   "2027-09-13",
				},
			},
		},
	}
	b, _ := json.Marshal(data)
	return b
}
