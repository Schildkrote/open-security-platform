package analysis

import (
	"testing"

	"github.com/Schildkrote/attack-path/internal/graph"
	"github.com/Schildkrote/attack-path/internal/path"
)

func buildTwoPaths() *graph.Graph {
	g := graph.New()
	g.AddNode(graph.Node{ID: "in", Type: graph.TypeExposure, Exposure: true})
	g.AddNode(graph.Node{ID: "a", Type: graph.TypeAsset})
	g.AddNode(graph.Node{ID: "goal1", Type: graph.TypeCritical, Critical: true})
	g.AddNode(graph.Node{ID: "goal2", Type: graph.TypeCritical, Critical: true})
	g.AddEdge(graph.Edge{From: "in", To: "a", Weight: 0.9})
	g.AddEdge(graph.Edge{From: "a", To: "goal1", Weight: 0.9})
	g.AddEdge(graph.Edge{From: "a", To: "goal2", Weight: 0.9})
	return g
}

func TestChokePoints(t *testing.T) {
	paths := path.FindPaths(buildTwoPaths(), 0)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	nodes, _ := ChokePoints(paths)
	// "a" lies on both paths -> highest node choke count.
	if nodes[0].ID != "a" || nodes[0].PathCount != 2 {
		t.Fatalf("expected node 'a' with count 2, got %+v", nodes[0])
	}
}

func TestRemediationRanksByPathsBroken(t *testing.T) {
	paths := path.FindPaths(buildTwoPaths(), 0)
	recs := Remediation(paths, 3)
	if len(recs) == 0 {
		t.Fatal("expected recommendations")
	}
	if recs[0].ID != "a" || recs[0].PathsBroken != 2 {
		t.Fatalf("top remediation should be node 'a' breaking 2 paths, got %+v", recs[0])
	}
}
