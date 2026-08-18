// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package geo

import "testing"

func TestStaticIPLongestPrefix(t *testing.T) {
	s := NewStatic()
	info, ok := s.IP("192.0.2.55")
	if !ok {
		t.Fatal("192.0.2.55 should match 192.0.2.0/24")
	}
	if info.Country != "US" {
		t.Fatalf("country = %q", info.Country)
	}
	if info.Identifier != "192.0.2.55" {
		t.Fatalf("identifier = %q", info.Identifier)
	}
}

func TestStaticIPNoMatch(t *testing.T) {
	s := NewStatic()
	if _, ok := s.IP("10.0.0.1"); ok {
		t.Fatal("10.0.0.1 should not match the sample table")
	}
}

func TestStaticPhone(t *testing.T) {
	s := NewStatic()
	info, ok := s.Phone("+49 30 123456")
	if !ok {
		t.Fatal("German number should match +49")
	}
	if info.Country != "DE" {
		t.Fatalf("country = %q", info.Country)
	}
	if info.Identifier != "+4930123456" {
		t.Fatalf("normalized identifier = %q", info.Identifier)
	}
}

func TestStaticPhoneNoMatch(t *testing.T) {
	s := NewStatic()
	if _, ok := s.Phone("+9991234567"); ok {
		t.Fatal("unknown country code should not match")
	}
}

func TestLoadCustomTable(t *testing.T) {
	s := &Static{IPs: map[string]GeoInfo{}, Phones: map[string]GeoInfo{}}
	err := s.LoadTable([]byte(`{"ips":{"10.1.0.0/16":{"Country":"ZZ","City":"Testville"}}}`))
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	info, ok := s.IP("10.1.2.3")
	if !ok {
		t.Fatal("10.1.2.3 should match 10.1.0.0/16")
	}
	if info.Country != "ZZ" || info.City != "Testville" {
		t.Fatalf("info = %+v", info)
	}
}

func TestCIDR(t *testing.T) {
	cases := []struct {
		ip, cidr string
		want     bool
	}{
		{"192.168.1.5", "192.168.0.0/16", true},
		{"192.168.2.5", "192.168.1.0/24", false},
		{"10.0.0.1", "10.0.0.1", true},
		{"10.0.0.2", "10.0.0.1", false},
		{"172.16.5.4", "172.16.0.0/12", true},
		{"172.32.0.1", "172.16.0.0/12", false},
	}
	for _, c := range cases {
		if got := ipInCIDR(c.ip, c.cidr); got != c.want {
			t.Errorf("ipInCIDR(%q, %q) = %v, want %v", c.ip, c.cidr, got, c.want)
		}
	}
}
