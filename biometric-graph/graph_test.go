// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"testing"

	"github.com/Schildkrote/lawful-basis"
)

func TestUpsertAndNameLocal(t *testing.T) {
	g := New("agency-a")
	n := g.UpsertPerson("alice", "Alice Example", basis.CatGeneral, "case-1")
	if n.ID == "" || n.Agency != "agency-a" {
		t.Fatalf("bad node: %+v", n)
	}
	if g.LocalName(n.ID) != "Alice Example" {
		t.Fatal("local name not stored")
	}
	// Node itself must not carry the display name.
	if _, ok := n.Props["name"]; ok {
		t.Fatal("name must not be on the node")
	}
}

func TestIdentityLinkComponent(t *testing.T) {
	g := New("a")
	a := g.UpsertPerson("alice", "Alice", basis.CatGeneral, "c1")
	b := g.UpsertPerson("alice-case2", "Alice", basis.CatGeneral, "c2")
	g.LinkIdentity(a.ID, b.ID, 0.95, "link")
	comp := g.Component(a.ID)
	if len(comp) != 2 {
		t.Fatalf("component = %v", comp)
	}
}

func TestShareRequiresConsentAndDPIA(t *testing.T) {
	g := New("a")
	g.UpsertPerson("alice", "Alice", basis.CatGeneral, "c1")
	_, d, err := g.Share(false, false)
	if err == nil || d.Outcome != basis.RequiresConsent {
		t.Fatalf("want requires_consent, got %+v err=%v", d, err)
	}
	_, d, err = g.Share(true, false)
	if err == nil || d.Outcome != basis.RequiresDPIA {
		t.Fatalf("want requires_dpia, got %+v err=%v", d, err)
	}
	bundle, d, err := g.Share(true, true)
	if err != nil || !d.Allowed() {
		t.Fatalf("share should work: %v %v", err, d)
	}
	if len(bundle.Nodes) != 1 {
		t.Fatalf("bundle nodes = %d", len(bundle.Nodes))
	}
}

func TestImportStripsNames(t *testing.T) {
	a := New("agency-a")
	n := a.UpsertPerson("alice", "Alice Secret", basis.CatGeneral, "c1")
	bundle, _, err := a.Share(true, true)
	if err != nil {
		t.Fatal(err)
	}
	b := New("agency-b")
	nn, ne := b.Import(bundle)
	if nn != 1 || ne != 0 {
		t.Fatalf("import nN=%d nE=%d", nn, ne)
	}
	if b.LocalName(n.ID) != "" {
		t.Fatal("imported graph must not carry foreign names")
	}
	got, ok := b.Node(n.ID)
	if !ok || got.Props["imported_from"] != "agency-a" {
		t.Fatalf("import marker missing: %+v", got)
	}
}

func TestMatchEvent(t *testing.T) {
	g := New("a")
	p := g.UpsertPerson("alice", "Alice", basis.CatGeneral, "c1")
	g.AddMatchEvent("probe-pseudo-1", p.ID, 0.91, "c1")
	if len(g.Edges()) != 1 {
		t.Fatalf("edges = %d", len(g.Edges()))
	}
}

func TestDOT(t *testing.T) {
	g := New("a")
	g.UpsertPerson("alice", "Alice", basis.CatGeneral, "c1")
	s := g.DOT()
	if s == "" || s[:7] != "digraph" {
		t.Fatalf("bad dot: %q", s)
	}
}
