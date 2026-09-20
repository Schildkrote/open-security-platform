// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package service

import "testing"

func TestBuiltInCatalog(t *testing.T) {
	c := BuiltIn()
	if len(c) == 0 {
		t.Fatal("built-in catalog is empty")
	}
	for _, s := range c {
		if s.Name == "" || s.URL == "" {
			t.Fatalf("incomplete service: %+v", s)
		}
	}
	if c.Lookup("github") == nil {
		t.Fatal("github should be in the built-in catalog")
	}
}

func TestFilter(t *testing.T) {
	c := BuiltIn()
	kept := c.Filter([]string{"github"})
	if len(kept) != 1 || kept[0].Name != "github" {
		t.Fatalf("Filter([github]) = %+v", kept)
	}
	if len(c.Filter(nil)) != len(c) {
		t.Fatal("Filter(nil) should keep everything")
	}
}

func TestBuildURL(t *testing.T) {
	out, err := BuildURL("https://x.example/{username}", "alice")
	if err != nil {
		t.Fatalf("BuildURL: %v", err)
	}
	if out != "https://x.example/alice" {
		t.Fatalf("BuildURL = %q", out)
	}
	if _, err := BuildURL("https://x.example/{username}", ""); err == nil {
		t.Fatal("empty username should error")
	}
}
