// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package ontology

import "testing"

func TestUpsertLinkExpandPath(t *testing.T) {
	s := NewStore()
	if _, err := s.UpsertObject(Object{ID: "person:alice", Type: TypePerson, Properties: map[string]any{"pseudo": "a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertObject(Object{ID: "vehicle:xyz", Type: TypeVehicle, Properties: map[string]any{"plate": "ABC123"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertObject(Object{ID: "location:gate", Type: TypeLocation}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddLink(Link{Type: LinkAssociatedWith, From: "person:alice", To: "vehicle:xyz"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddLink(Link{Type: LinkObservedAt, From: "vehicle:xyz", To: "location:gate"}); err != nil {
		t.Fatal(err)
	}
	objs, links := s.Expand("person:alice", 2)
	if len(objs) < 3 || len(links) < 2 {
		t.Fatalf("expand: objs=%d links=%d", len(objs), len(links))
	}
	path := s.Path("person:alice", "location:gate", 4)
	if len(path) != 2 {
		t.Fatalf("path len=%d", len(path))
	}
	q := s.QueryObjects(Query{Type: TypeVehicle, PropertyEq: map[string]any{"plate": "ABC123"}})
	if len(q) != 1 {
		t.Fatalf("query %d", len(q))
	}
}

func TestSaveLoad(t *testing.T) {
	s := NewStore()
	_, _ = s.UpsertObject(Object{ID: "person:bob", Type: TypePerson})
	dir := t.TempDir()
	path := dir + "/s.json"
	if err := s.SaveJSON(path); err != nil {
		t.Fatal(err)
	}
	s2, err := LoadJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get("person:bob"); !ok {
		t.Fatal("missing bob")
	}
}

func TestUnknownType(t *testing.T) {
	s := NewStore()
	if _, err := s.UpsertObject(Object{ID: "x:1", Type: "Nope"}); err == nil {
		t.Fatal("want error")
	}
}
