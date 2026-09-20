// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package shodan

import (
	"context"
	"testing"
)

func TestParseSimple(t *testing.T) {
	q, err := Parse("product:nginx port:443")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(q.Groups) != 1 || len(q.Groups[0]) != 2 {
		t.Fatalf("want 1 group of 2 terms, got %+v", q.Groups)
	}
	if q.Groups[0][0].Key != "product" || q.Groups[0][0].Value != "nginx" {
		t.Fatalf("term 0 wrong: %+v", q.Groups[0][0])
	}
}

func TestParseQuoted(t *testing.T) {
	q, err := Parse(`org:"Acme Corp" city:frankfurt`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(q.Groups) != 1 || len(q.Groups[0]) != 2 {
		t.Fatalf("want 2 terms, got %+v", q.Groups)
	}
	if q.Groups[0][0].Value != "Acme Corp" {
		t.Fatalf("quoted value wrong: %q", q.Groups[0][0].Value)
	}
}

func TestParseOR(t *testing.T) {
	q, err := Parse("port:22 || port:3389")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(q.Groups) != 2 {
		t.Fatalf("want 2 OR-groups, got %d", len(q.Groups))
	}
}

func TestParseEmpty(t *testing.T) {
	if _, err := Parse("   "); err == nil {
		t.Fatal("empty dork should error")
	}
}

func TestParseBadTerm(t *testing.T) {
	if _, err := Parse("notakeyvalue"); err == nil {
		t.Fatal("non key:value term should error")
	}
}

func TestPortsAndValue(t *testing.T) {
	q, _ := Parse("port:22 product:nginx || port:443")
	ports := q.Ports()
	if len(ports) != 2 {
		t.Fatalf("ports = %v", ports)
	}
	if q.Value("product") != "nginx" {
		t.Fatalf("Value(product) = %q", q.Value("product"))
	}
	if !q.Contains("port", "22") {
		t.Fatal("Contains(port,22) should be true")
	}
}

func TestMockQueryFilters(t *testing.T) {
	m := NewMock()
	all, err := m.Query(context.Background(), "port:22")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(all) != 1 || all[0].Port != 22 {
		t.Fatalf("port:22 → %+v", all)
	}
	nginx, _ := m.Query(context.Background(), "product:nginx")
	if len(nginx) != 2 {
		t.Fatalf("product:nginx → %d devices, want 2", len(nginx))
	}
	both, _ := m.Query(context.Background(), "product:nginx port:443")
	if len(both) != 1 || both[0].Port != 443 {
		t.Fatalf("product:nginx port:443 → %+v", both)
	}
}
