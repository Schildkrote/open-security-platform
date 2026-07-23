// Package render outputs the graph and analysis as DOT, JSON, or text.
package render

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/example/attack-path/internal/analysis"
	"github.com/example/attack-path/internal/graph"
	"github.com/example/attack-path/internal/path"
)

var colors = map[string]string{
	graph.TypeExposure:   "orange",
	graph.TypeAsset:      "lightblue",
	graph.TypeIdentity:   "lightyellow",
	graph.TypePermission: "lavender",
	graph.TypeVuln:       "salmon",
	graph.TypeData:       "palegreen",
	graph.TypeCritical:   "red",
}

// DOT renders the graph as Graphviz, highlighting attack-path edges.
func DOT(g *graph.Graph, paths []path.Path) string {
	pathEdges := map[string]bool{}
	for _, p := range paths {
		for _, e := range p.Edges {
			pathEdges[e] = true
		}
	}
	var b strings.Builder
	b.WriteString("digraph attack_path {\n  rankdir=LR;\n  node [style=filled];\n")
	for _, n := range g.Nodes() {
		color := colors[n.Type]
		if color == "" {
			color = "white"
		}
		shape := "box"
		if n.Critical || n.Type == graph.TypeCritical {
			shape = "doublecircle"
		}
		fmt.Fprintf(&b, "  %q [label=%q, shape=%s, fillcolor=%s];\n", n.ID, n.Name+" ("+n.Type+")", shape, color)
	}
	for _, n := range g.Nodes() {
		for _, e := range g.OutEdges(n.ID) {
			attrs := fmt.Sprintf("label=%q", e.Type)
			if pathEdges[e.From+"->"+e.To] {
				attrs += ", color=red, penwidth=2"
			}
			fmt.Fprintf(&b, "  %q -> %q [%s];\n", e.From, e.To, attrs)
		}
	}
	b.WriteString("}\n")
	return b.String()
}

// Report bundles paths and remediation for JSON/text output.
type Report struct {
	Scenario    string                    `json:"scenario"`
	PathCount   int                       `json:"path_count"`
	Paths       []path.Path               `json:"paths"`
	Remediation []analysis.Recommendation `json:"remediation"`
}

// JSON renders the full report as JSON.
func JSON(scenario string, paths []path.Path, recs []analysis.Recommendation) string {
	rep := Report{Scenario: scenario, PathCount: len(paths), Paths: paths, Remediation: recs}
	b, _ := json.MarshalIndent(rep, "", "  ")
	return string(b)
}

// Text renders a human-readable summary.
func Text(scenario string, paths []path.Path, recs []analysis.Recommendation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Attack Path Analysis: %s\n", scenario)
	fmt.Fprintf(&b, "Found %d attack path(s) to critical assets:\n\n", len(paths))
	for i, p := range paths {
		fmt.Fprintf(&b, "  %d. [risk %.3f, %d hops] %s\n", i+1, p.Risk, p.Hops, p.String())
	}
	b.WriteString("\nTop remediation (cut these to break the most paths):\n")
	for _, r := range recs {
		fmt.Fprintf(&b, "  - %s\n", r.Advice)
	}
	return b.String()
}
