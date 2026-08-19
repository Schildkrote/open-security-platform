// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package osinttaxonomy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenHash pins the taxonomy file so drift is caught in CI (same pattern as
// platform/lawful-basis). If you change taxonomy.json, run
// `go test -run TestGoldenHash -update` to re-pin.
var goldenHash = "47ed0e08ea2096a55f14e092fdcbddb309a0485de11efd8aee4e6c4e7ec1a0fd"

func TestGoldenHash(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("taxonomy.json"))
	if err != nil {
		t.Fatalf("read taxonomy.json: %v", err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != goldenHash {
		t.Errorf("taxonomy.json hash drift:\n  got  %s\n  want %s\nrun: go test -run TestGoldenHash -update", got, goldenHash)
	}
}

func TestLoad(t *testing.T) {
	tax, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tax.Version != 1 {
		t.Errorf("version = %d, want 1", tax.Version)
	}
	if len(tax.Categories) == 0 {
		t.Fatal("no categories loaded")
	}
}

func TestByIDs(t *testing.T) {
	tax, _ := Load()
	for _, id := range []string{"breach-credential", "username-enum", "people-search", "social-scoring", "biometric-scrape"} {
		if _, err := tax.ByID(id); err != nil {
			t.Errorf("ByID(%q): %v", id, err)
		}
	}
	if _, err := tax.ByID("no-such"); err == nil {
		t.Error("ByID(no-such) should fail")
	}
}

func TestLiveFeaturesFor(t *testing.T) {
	tax, _ := Load()
	feats, err := tax.LiveFeaturesFor("people-search")
	if err != nil {
		t.Fatalf("LiveFeaturesFor: %v", err)
	}
	want := []string{"people-search"}
	if len(feats) != 1 || feats[0] != want[0] {
		t.Errorf("LiveFeaturesFor(people-search) = %v, want %v", feats, want)
	}
}

func TestSourceWhitelistFor(t *testing.T) {
	tax, _ := Load()
	wl, err := tax.SourceWhitelistFor("people-search")
	if err != nil {
		t.Fatalf("SourceWhitelistFor: %v", err)
	}
	if len(wl) < 5 {
		t.Errorf("people-search whitelist too short: %v", wl)
	}
}

func TestBasisFor(t *testing.T) {
	tax, _ := Load()
	b, _ := tax.BasisFor("biometric-scrape")
	if b != "prohibited" {
		t.Errorf("BasisFor(biometric-scrape) = %q, want prohibited", b)
	}
	b, _ = tax.BasisFor("biometric-categorise")
	if b != "requires_dpia" {
		t.Errorf("BasisFor(biometric-categorise) = %q, want requires_dpia", b)
	}
}

func TestValidate(t *testing.T) {
	// Re-parse and re-validate (catches duplicate IDs, empty fields).
	var tax Taxonomy
	if err := json.Unmarshal(taxonomyJSON, &tax); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := tax.validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}
