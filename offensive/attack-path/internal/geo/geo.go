// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package geo provides offline IP/phone geolocation enrichment for attack
// graph nodes. The default source is a built-in static table (deterministic,
// offline, CI-safe); a user-supplied MaxMind-style JSON table can be loaded
// for production use. No network calls are made by the default source.
package geo

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// GeoInfo is the enrichment payload for one identifier.
type GeoInfo struct {
	Identifier string `json:"identifier"`
	Kind       string `json:"kind"` // "ip" or "phone"
	Country    string `json:"country"`
	Region     string `json:"region"`
	City       string `json:"city"`
	ASN        string `json:"asn"`
	Org        string `json:"org"`
	Tz         string `json:"tz"`
}

// Lookup enriches an IP address or E.164 phone number.
type Lookup interface {
	Name() string
	IP(ip string) (GeoInfo, bool)
	Phone(e164 string) (GeoInfo, bool)
}

// Static is a Lookup backed by in-memory tables.
type Static struct {
	IPs    map[string]GeoInfo `json:"ips"`
	Phones map[string]GeoInfo `json:"phones"`
}

// NewStatic returns a Static lookup preloaded with the built-in sample
// table (documentation-grade coverage; extend via LoadTable).
func NewStatic() *Static {
	s := &Static{IPs: map[string]GeoInfo{}, Phones: map[string]GeoInfo{}}
	s.LoadTable(BuiltIn())
	return s
}

// LoadTable loads a JSON table of shape:
//
//	{"ips": {"192.0.2.0/24": {...}}, "phones": {"+49": {...}}}
//
// IP entries may use CIDR prefixes; lookups walk the table for the most
// specific matching prefix. Phone entries match by longest E.164 prefix.
func (s *Static) LoadTable(data []byte) error {
	var raw struct {
		IPs    map[string]GeoInfo `json:"ips"`
		Phones map[string]GeoInfo `json:"phones"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse geo table: %w", err)
	}
	for k, v := range raw.IPs {
		v.Identifier = k
		v.Kind = "ip"
		s.IPs[k] = v
	}
	for k, v := range raw.Phones {
		v.Identifier = k
		v.Kind = "phone"
		s.Phones[k] = v
	}
	return nil
}

// Name implements Lookup.
func (s *Static) Name() string { return "static" }

// IP implements Lookup by longest-prefix match over CIDR keys.
func (s *Static) IP(ip string) (GeoInfo, bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return GeoInfo{}, false
	}
	best, bestLen := GeoInfo{}, -1
	for prefix, info := range s.IPs {
		n, ok := cidrPrefixLen(prefix)
		if !ok {
			// Treat as exact IP.
			if prefix == ip && 32 > bestLen {
				best, bestLen = info, 32
			}
			continue
		}
		if n > bestLen && ipInCIDR(ip, prefix) {
			best, bestLen = info, n
		}
	}
	if bestLen < 0 {
		return GeoInfo{}, false
	}
	best.Identifier = ip
	return best, true
}

// Phone implements Lookup by longest E.164 prefix match.
func (s *Static) Phone(e164 string) (GeoInfo, bool) {
	e164 = normalizePhone(e164)
	if e164 == "" {
		return GeoInfo{}, false
	}
	var best GeoInfo
	bestLen := 0
	for prefix, info := range s.Phones {
		if strings.HasPrefix(e164, prefix) && len(prefix) > bestLen {
			best, bestLen = info, len(prefix)
		}
	}
	if bestLen == 0 {
		return GeoInfo{}, false
	}
	best.Identifier = e164
	return best, true
}

// cidrPrefixLen parses "a.b.c.d/N" and returns N, or (0,false).
func cidrPrefixLen(s string) (int, bool) {
	i := strings.LastIndexByte(s, '/')
	if i < 0 {
		return 0, false
	}
	n := 0
	for _, r := range s[i+1:] {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, n >= 0 && n <= 32
}

// ipInCIDR reports whether ip (dotted quad) falls in cidr "a.b.c.d/N".
// It compares only the top N bits of the 32-bit address.
func ipInCIDR(ip, cidr string) bool {
	parts := strings.SplitN(cidr, "/", 2)
	base, n := parts[0], 0
	if len(parts) == 2 {
		for _, r := range parts[1] {
			if r < '0' || r > '9' {
				return false
			}
			n = n*10 + int(r-'0')
		}
	} else {
		n = 32
	}
	if n > 32 {
		return false
	}
	ipB, err := parseOctets(ip)
	if err != nil {
		return false
	}
	baseB, err := parseOctets(base)
	if err != nil {
		return false
	}
	// Compare the top n bits octet by octet.
	for i := 0; i < 4 && n > 0; i++ {
		bits := n
		if bits > 8 {
			bits = 8
		}
		mask := byte(0xFF<<(8-bits)) & 0xFF
		if (ipB[i] & mask) != (baseB[i] & mask) {
			return false
		}
		n -= 8
	}
	return true
}

func parseOctets(s string) ([4]byte, error) {
	var out [4]byte
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return out, fmt.Errorf("bad ip %q", s)
	}
	for i, p := range parts {
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				return out, fmt.Errorf("bad ip octet %q", p)
			}
			n = n*10 + int(r-'0')
		}
		if n > 255 {
			return out, fmt.Errorf("ip octet out of range %q", p)
		}
		out[i] = byte(n)
	}
	return out, nil
}

// normalizePhone reduces a phone number to E.164-ish form: strip spaces,
// dashes, parens; ensure a leading +.
func normalizePhone(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '+' || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out != "" && out[0] != '+' {
		out = "+" + out
	}
	return out
}

// BuiltIn returns the default static geo table as JSON. It is a small,
// clearly synthetic sample; extend it with real MaxMind/Carrier data for
// production use.
func BuiltIn() []byte {
	data := map[string]any{
		"ips": map[string]GeoInfo{
			"192.0.2.0/24":    {Country: "US", Region: "CA", City: "San Francisco", ASN: "AS54113", Org: "Example Inc", Tz: "America/Los_Angeles"},
			"198.51.100.0/24": {Country: "DE", Region: "BE", City: "Berlin", ASN: "AS24940", Org: "Example DE", Tz: "Europe/Berlin"},
			"203.0.113.0/24":  {Country: "SG", Region: "", City: "Singapore", ASN: "AS45102", Org: "Example SG", Tz: "Asia/Singapore"},
		},
		"phones": map[string]GeoInfo{
			"+1":  {Country: "US", Tz: "America/New_York"},
			"+49": {Country: "DE", Tz: "Europe/Berlin"},
			"+33": {Country: "FR", Tz: "Europe/Paris"},
			"+44": {Country: "GB", Tz: "Europe/London"},
			"+65": {Country: "SG", Tz: "Asia/Singapore"},
			"+86": {Country: "CN", Tz: "Asia/Shanghai"},
			"+91": {Country: "IN", Tz: "Asia/Kolkata"},
			"+55": {Country: "BR", Tz: "America/Sao_Paulo"},
		},
	}
	b, _ := json.Marshal(data)
	return b
}

// SortByCountry sorts a slice of GeoInfo by country (for stable reports).
func SortByCountry(xs []GeoInfo) {
	sort.Slice(xs, func(i, j int) bool { return xs[i].Country < xs[j].Country })
}
