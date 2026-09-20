// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package osinttaxonomy is the canonical OSINT category taxonomy (Phase 3,
// the single source of truth that live-recon, username-enum, and the
// people-search source whitelist all read from). It mirrors the pattern of
// Pattern: one JSON file, a Go loader, a golden hash test.
//
// The taxonomy is NOT a policy engine — it maps OSINT categories to the
// components that implement them, their live-gate features, and (for
// sensitive rows) the default lawful basis. Consumers use it to:
//   - build source whitelists (people-search)
//   - discover live-gate features (live-recon, username-enum)
//   - enforce basis gates where a lawful basis applies
package osinttaxonomy

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed taxonomy.json
var taxonomyJSON []byte

// Category is one OSINT category with the components that implement it.
type Category struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Description     string      `json:"description"`
	Components      []Component `json:"components"`
	SourceWhitelist []string    `json:"source_whitelist,omitempty"`
}

// Component is a single implementation of a category (a repo path + live-gate features).
type Component struct {
	ID           string   `json:"id"`
	Repo         string   `json:"repo"`
	Path         string   `json:"path"`
	Mode         string   `json:"mode"` // real | partial | pending
	Live         bool     `json:"live"`
	LiveFeatures []string `json:"live_features,omitempty"`
	Basis        string   `json:"basis,omitempty"` // prohibited | requires_dpia | consent (sensitive rows)
	Notes        string   `json:"notes,omitempty"`
}

// Taxonomy is the root of taxonomy.json.
type Taxonomy struct {
	Version    int        `json:"version"`
	Updated    string     `json:"updated"`
	Categories []Category `json:"categories"`
}

// Load parses and validates the embedded taxonomy.
func Load() (*Taxonomy, error) {
	var t Taxonomy
	if err := json.Unmarshal(taxonomyJSON, &t); err != nil {
		return nil, fmt.Errorf("osinttaxonomy: unmarshal: %w", err)
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

func (t *Taxonomy) validate() error {
	seen := map[string]bool{}
	for _, c := range t.Categories {
		if c.ID == "" {
			return fmt.Errorf("osinttaxonomy: category with empty id")
		}
		if seen[c.ID] {
			return fmt.Errorf("osinttaxonomy: duplicate category id %q", c.ID)
		}
		seen[c.ID] = true
		for _, comp := range c.Components {
			if comp.ID == "" || comp.Repo == "" || comp.Path == "" {
				return fmt.Errorf("osinttaxonomy: category %q has component with empty id/repo/path", c.ID)
			}
			if !comp.Live && len(comp.LiveFeatures) > 0 {
				return fmt.Errorf("osinttaxonomy: component %q has live_features but live=false", comp.ID)
			}
		}
	}
	return nil
}

// ByID returns a category by its id.
func (t *Taxonomy) ByID(id string) (*Category, error) {
	for i := range t.Categories {
		if t.Categories[i].ID == id {
			return &t.Categories[i], nil
		}
	}
	return nil, fmt.Errorf("osinttaxonomy: unknown category %q", id)
}

// LiveFeaturesFor returns the union of live-gate features across all
// components in a category (the set a consumer must register in its livegate).
func (t *Taxonomy) LiveFeaturesFor(categoryID string) ([]string, error) {
	cat, err := t.ByID(categoryID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, comp := range cat.Components {
		for _, f := range comp.LiveFeatures {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// SourceWhitelistFor returns the source whitelist for a category (empty if none).
func (t *Taxonomy) SourceWhitelistFor(categoryID string) ([]string, error) {
	cat, err := t.ByID(categoryID)
	if err != nil {
		return nil, err
	}
	return cat.SourceWhitelist, nil
}

// BasisFor returns the default lawful basis for a sensitive category ("" if none).
func (t *Taxonomy) BasisFor(categoryID string) (string, error) {
	cat, err := t.ByID(categoryID)
	if err != nil {
		return "", err
	}
	if len(cat.Components) == 0 {
		return "", nil
	}
	return cat.Components[0].Basis, nil
}
