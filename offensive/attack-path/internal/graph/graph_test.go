package graph

import "testing"

func TestAddAndQuery(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "a", Type: TypeExposure, Exposure: true})
	g.AddNode(Node{ID: "b", Type: TypeAsset})
	g.AddNode(Node{ID: "c", Type: TypeCritical, Critical: true})
	g.AddEdge(Edge{From: "a", To: "b", Type: "reach", Weight: 0.8})
	g.AddEdge(Edge{From: "b", To: "c", Type: "exploit", Weight: 0.5})

	if len(g.Entries()) != 1 || g.Entries()[0].ID != "a" {
		t.Fatalf("expected one entry 'a', got %+v", g.Entries())
	}
	if len(g.Criticals()) != 1 || g.Criticals()[0].ID != "c" {
		t.Fatalf("expected one critical 'c', got %+v", g.Criticals())
	}
	if len(g.OutEdges("a")) != 1 {
		t.Fatalf("expected 1 out edge from a")
	}
}

func TestExploitabilityParsing(t *testing.T) {
	n := Node{ID: "x", Props: map[string]string{"exploitability": "0.6"}}
	if n.Exploitability() != 0.6 {
		t.Fatalf("expected 0.6, got %f", n.Exploitability())
	}
	if (Node{ID: "y"}).Exploitability() != 1.0 {
		t.Fatal("default exploitability should be 1.0")
	}
	// Out-of-range clamps.
	hi := Node{ID: "z", Props: map[string]string{"exploitability": "5"}}
	if hi.Exploitability() != 1.0 {
		t.Fatalf("expected clamp to 1.0, got %f", hi.Exploitability())
	}
}

func TestEdgeWeightClamped(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "a"})
	g.AddNode(Node{ID: "b"})
	g.AddEdge(Edge{From: "a", To: "b", Weight: 3})
	if g.OutEdges("a")[0].Weight != 1 {
		t.Fatal("edge weight > 1 should clamp to 1")
	}
}
