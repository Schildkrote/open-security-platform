package path

import (
	"testing"

	"github.com/Schildkrote/attack-path/internal/graph"
)

func buildLinear() *graph.Graph {
	g := graph.New()
	g.AddNode(graph.Node{ID: "in", Type: graph.TypeExposure, Exposure: true})
	g.AddNode(graph.Node{ID: "mid", Type: graph.TypeAsset})
	g.AddNode(graph.Node{ID: "goal", Type: graph.TypeCritical, Critical: true})
	g.AddEdge(graph.Edge{From: "in", To: "mid", Weight: 0.8})
	g.AddEdge(graph.Edge{From: "mid", To: "goal", Weight: 0.5})
	return g
}

func TestFindLinearPath(t *testing.T) {
	paths := FindPaths(buildLinear(), 0)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	p := paths[0]
	if p.String() != "in -> mid -> goal" {
		t.Fatalf("unexpected path: %s", p.String())
	}
	if p.Hops != 2 {
		t.Fatalf("expected 2 hops, got %d", p.Hops)
	}
	// risk = entry(1.0) * 0.8 * 0.5 = 0.4
	if p.Risk < 0.39 || p.Risk > 0.41 {
		t.Fatalf("expected risk ~0.4, got %f", p.Risk)
	}
}

func TestPathsRankedByRisk(t *testing.T) {
	g := graph.New()
	g.AddNode(graph.Node{ID: "in", Type: graph.TypeExposure, Exposure: true})
	g.AddNode(graph.Node{ID: "easy", Type: graph.TypeAsset})
	g.AddNode(graph.Node{ID: "hard", Type: graph.TypeAsset})
	g.AddNode(graph.Node{ID: "goal", Type: graph.TypeCritical, Critical: true})
	g.AddEdge(graph.Edge{From: "in", To: "easy", Weight: 0.9})
	g.AddEdge(graph.Edge{From: "easy", To: "goal", Weight: 0.9})
	g.AddEdge(graph.Edge{From: "in", To: "hard", Weight: 0.2})
	g.AddEdge(graph.Edge{From: "hard", To: "goal", Weight: 0.2})

	paths := FindPaths(g, 0)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	if paths[0].Nodes[1] != "easy" {
		t.Fatalf("higher-risk path should rank first, got %s", paths[0].String())
	}
	if paths[0].Risk <= paths[1].Risk {
		t.Fatal("paths should be sorted by descending risk")
	}
}

func TestCycleDoesNotHang(t *testing.T) {
	g := graph.New()
	g.AddNode(graph.Node{ID: "in", Type: graph.TypeExposure, Exposure: true})
	g.AddNode(graph.Node{ID: "a", Type: graph.TypeAsset})
	g.AddNode(graph.Node{ID: "b", Type: graph.TypeAsset})
	g.AddNode(graph.Node{ID: "goal", Type: graph.TypeCritical, Critical: true})
	g.AddEdge(graph.Edge{From: "in", To: "a", Weight: 0.9})
	g.AddEdge(graph.Edge{From: "a", To: "b", Weight: 0.9})
	g.AddEdge(graph.Edge{From: "b", To: "a", Weight: 0.9}) // cycle
	g.AddEdge(graph.Edge{From: "b", To: "goal", Weight: 0.9})

	paths := FindPaths(g, 10)
	if len(paths) == 0 {
		t.Fatal("expected at least one path despite cycle")
	}
}
