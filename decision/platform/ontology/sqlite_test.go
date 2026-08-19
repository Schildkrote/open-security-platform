// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package ontology

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteRoundTrip(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC().Truncate(time.Second)

	_, _ = s.UpsertObject(Object{
		ID: "person:alice", Type: TypePerson, Classification: "restricted",
		Properties: map[string]any{"label": "alice", "pseudo": "2bd8"},
		Provenance: Provenance{Source: "obp"},
		CreatedAt:  now, UpdatedAt: now,
	})
	_, _ = s.UpsertObject(Object{
		ID: "vehicle:ABC123", Type: TypeVehicle,
		Properties: map[string]any{"plate": "ABC123", "state": "CA"},
		Provenance: Provenance{Source: "alpr", ExternalID: "ABC123"},
		CreatedAt:  now, UpdatedAt: now,
	})
	_, _ = s.AddLink(Link{Type: LinkAssociatedWith, From: "person:alice", To: "vehicle:ABC123",
		Provenance: Provenance{Source: "obp"}})

	path := filepath.Join(t.TempDir(), "store.sqlite")
	if err := s.SaveSQLite(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := LoadSQLite(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := len(got.QueryObjects(Query{})); n != 2 {
		t.Fatalf("objects = %d, want 2", n)
	}
	p, ok := got.Get("person:alice")
	if !ok {
		t.Fatal("person:alice missing")
	}
	if p.Classification != "restricted" {
		t.Errorf("classification = %q", p.Classification)
	}
	if p.Properties["pseudo"] != "2bd8" {
		t.Errorf("properties = %v", p.Properties)
	}
	if p.Provenance.Source != "obp" {
		t.Errorf("provenance = %+v", p.Provenance)
	}
	links := got.Neighbors("person:alice", false)
	if len(links) != 1 || links[0].From != "person:alice" || links[0].To != "vehicle:ABC123" {
		t.Fatalf("links = %+v", links)
	}
	if len(got.Links) != 1 {
		t.Fatalf("link map = %d, want 1", len(got.Links))
	}

	// Save must be repeatable (idempotent full replace).
	if err := s.SaveSQLite(path); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	got2, err := LoadSQLite(path)
	if err != nil {
		t.Fatalf("re-load: %v", err)
	}
	if n := len(got2.QueryObjects(Query{})); n != 2 {
		t.Fatalf("re-load objects = %d, want 2", n)
	}
}

func TestSQLiteEmptyStore(t *testing.T) {
	s := NewStore()
	path := filepath.Join(t.TempDir(), "empty.sqlite")
	if err := s.SaveSQLite(path); err != nil {
		t.Fatalf("save empty: %v", err)
	}
	got, err := LoadSQLite(path)
	if err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if n := len(got.QueryObjects(Query{})); n != 0 {
		t.Fatalf("objects = %d, want 0", n)
	}
}
