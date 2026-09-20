// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package probe

import (
	"testing"
)

func TestMaskEmail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"jane.doe@example.com", "j****@example.com"},
		{"ab@x.com", "a***@x.com"},
		{"a@x.com", "a***@x.com"},
		{"no-at-sign", "***"},
	}
	for _, c := range cases {
		if got := MaskEmail(c.in); got != c.want {
			t.Errorf("MaskEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMaskPhone(t *testing.T) {
	cases := []struct{ in, want string }{
		{"555-123-4567", "********67"},
		{"+1 555 123 4567", "*********67"},
		{"12", "**"},
		{"1", "*"},
	}
	for _, c := range cases {
		if got := MaskPhone(c.in); got != c.want {
			t.Errorf("MaskPhone(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactString(t *testing.T) {
	in := "Contact jane.doe@example.com or call 555-123-4567 for details"
	got := RedactString(in)
	want := "Contact j****@example.com or call ********67 for details"
	if got != want {
		t.Errorf("RedactString:\n got  %q\n want %q", got, want)
	}
}

func TestHashPII(t *testing.T) {
	h1 := HashPII("jane doe")
	h2 := HashPII("jane doe")
	h3 := HashPII("john smith")
	if h1 != h2 {
		t.Error("HashPII not deterministic")
	}
	if h1 == h3 {
		t.Error("HashPII collision for different inputs")
	}
	if len(h1) != 12 {
		t.Errorf("HashPII length = %d, want 12", len(h1))
	}
}

func TestRedactEvidence(t *testing.T) {
	e := map[string]any{
		"email":   "jane.doe@example.com",
		"phone":   "555-123-4567",
		"count":   3,
		"note":    "call 555-123-4567 or email x@y.z",
		"nomatch": "hello world",
	}
	out := RedactEvidence(e)
	if out["email"] != "j****@example.com" {
		t.Errorf("email = %v", out["email"])
	}
	if out["phone"] != "********67" {
		t.Errorf("phone = %v", out["phone"])
	}
	if out["count"] != 3 {
		t.Errorf("count = %v", out["count"])
	}
	if out["note"] != "call ********67 or email x***@y.z" {
		t.Errorf("note = %v", out["note"])
	}
}
