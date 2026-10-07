package ingest

import (
	"fmt"
	"math"
	"testing"

	"github.com/Schildkrote/attack-path/internal/graph"
)

const scenario = `{
  "name": "test",
  "nodes": [
    {"id":"in","type":"exposure","exposure":true},
    {"id":"db","type":"critical","critical":true}
  ],
  "edges": [{"from":"in","to":"db","type":"reach","weight":0.9}]
}`

func TestLoad(t *testing.T) {
	g, d, err := Load([]byte(scenario))
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "test" {
		t.Fatalf("expected name 'test', got %q", d.Name)
	}
	if len(g.Nodes()) != 2 || len(g.Entries()) != 1 || len(g.Criticals()) != 1 {
		t.Fatalf("unexpected graph: %+v", g.Nodes())
	}
}

func TestLoadRejectsUnknownEdgeNode(t *testing.T) {
	bad := `{"nodes":[{"id":"in","type":"exposure"}],"edges":[{"from":"in","to":"ghost"}]}`
	if _, _, err := Load([]byte(bad)); err == nil {
		t.Fatal("expected error for edge referencing unknown node")
	}
}

func TestLoadRejectsBadJSON(t *testing.T) {
	if _, _, err := Load([]byte("{not json")); err == nil {
		t.Fatal("expected parse error")
	}
}

// AP-5: scenario budgets and weight validation.

func TestBuildRejectsNonFiniteWeight(t *testing.T) {
	// encoding/json cannot express NaN literally, so construct it in Go.
	d := Descriptor{
		Name:  "nan-weight",
		Nodes: []graph.Node{{ID: "in", Type: "exposure", Exposure: true}, {ID: "db", Type: "critical", Critical: true}},
		Edges: []graph.Edge{{From: "in", To: "db", Weight: math.NaN()}},
	}
	if _, err := Build(&d); err == nil {
		t.Fatal("expected error for NaN edge weight (AP-5)")
	}

	d2 := Descriptor{
		Name:  "inf-weight",
		Nodes: d.Nodes,
		Edges: []graph.Edge{{From: "in", To: "db", Weight: math.Inf(1)}},
	}
	if _, err := Build(&d2); err == nil {
		t.Fatal("expected error for Inf edge weight (AP-5)")
	}
}

func TestBuildAcceptsFiniteWeights(t *testing.T) {
	d := Descriptor{
		Name:  "ok",
		Nodes: []graph.Node{{ID: "in", Type: "exposure", Exposure: true}, {ID: "db", Type: "critical", Critical: true}},
		Edges: []graph.Edge{{From: "in", To: "db", Weight: 0.9}},
	}
	if _, err := Build(&d); err != nil {
		t.Fatalf("finite weights should build: %v", err)
	}
}

func TestBuildRejectsOversizedScenario(t *testing.T) {
	d := Descriptor{Name: "huge"}
	for i := 0; i <= maxNodes; i++ {
		d.Nodes = append(d.Nodes, graph.Node{ID: fmt.Sprintf("n%d", i)})
	}
	if _, err := Build(&d); err == nil {
		t.Fatal("expected node-budget error (AP-5)")
	}
}
