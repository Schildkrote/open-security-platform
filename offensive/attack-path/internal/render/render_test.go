package render

import (
	"strings"
	"testing"

	"github.com/Schildkrote/attack-path/internal/analysis"
	"github.com/Schildkrote/attack-path/internal/graph"
	"github.com/Schildkrote/attack-path/internal/path"
)

func build() *graph.Graph {
	g := graph.New()
	g.AddNode(graph.Node{ID: "in", Type: graph.TypeExposure, Name: "Internet", Exposure: true})
	g.AddNode(graph.Node{ID: "db", Type: graph.TypeCritical, Name: "Prod DB", Critical: true})
	g.AddEdge(graph.Edge{From: "in", To: "db", Type: "reach", Weight: 0.9})
	return g
}

func TestDOT(t *testing.T) {
	g := build()
	paths := path.FindPaths(g, 0)
	dot := DOT(g, paths)
	if !strings.Contains(dot, "digraph attack_path") {
		t.Fatal("missing digraph header")
	}
	if !strings.Contains(dot, `"in" -> "db"`) {
		t.Fatal("missing edge")
	}
	if !strings.Contains(dot, "doublecircle") {
		t.Fatal("critical node should be doublecircle")
	}
}

func TestJSONAndText(t *testing.T) {
	g := build()
	paths := path.FindPaths(g, 0)
	recs := analysis.Remediation(paths, 3)
	js := JSON("scenario", paths, recs)
	if !strings.Contains(js, `"path_count": 1`) {
		t.Fatalf("unexpected JSON: %s", js)
	}
	txt := Text("scenario", paths, recs)
	if !strings.Contains(txt, "Found 1 attack path") {
		t.Fatalf("unexpected text: %s", txt)
	}
}
