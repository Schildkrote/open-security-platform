// Package ingest loads an attack graph from a JSON scenario descriptor.
package ingest

import (
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/Schildkrote/attack-path/internal/graph"
)

// maxNodes/maxEdges bound scenario size (AP-5): a hostile/huge scenario can
// otherwise burn unbounded memory during ingestion.
const (
	maxNodes = 10000
	maxEdges = 50000
)

// Descriptor is the JSON schema for a scenario.
type Descriptor struct {
	Name  string       `json:"name"`
	Nodes []graph.Node `json:"nodes"`
	Edges []graph.Edge `json:"edges"`
}

// Load parses a scenario from JSON bytes into a Graph.
func Load(data []byte) (*graph.Graph, *Descriptor, error) {
	var d Descriptor
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, nil, fmt.Errorf("parse scenario: %w", err)
	}
	g, err := Build(&d)
	if err != nil {
		return nil, nil, err
	}
	return g, &d, nil
}

// Build constructs a Graph from a Descriptor (used by Load and the third-party
// importers in importers.go). Scenario budgets (AP-5): rejects descriptors
// above maxNodes/maxEdges and edge weights that are NaN or Inf.
func Build(d *Descriptor) (*graph.Graph, error) {
	if len(d.Nodes) > maxNodes {
		return nil, fmt.Errorf("scenario exceeds node budget: %d > %d", len(d.Nodes), maxNodes)
	}
	if len(d.Edges) > maxEdges {
		return nil, fmt.Errorf("scenario exceeds edge budget: %d > %d", len(d.Edges), maxEdges)
	}
	g := graph.New()
	for _, n := range d.Nodes {
		if n.ID == "" {
			return nil, fmt.Errorf("node missing id")
		}
		g.AddNode(n)
	}
	for _, e := range d.Edges {
		if !g.HasNode(e.From) || !g.HasNode(e.To) {
			return nil, fmt.Errorf("edge %s->%s references unknown node", e.From, e.To)
		}
		if math.IsNaN(e.Weight) || math.IsInf(e.Weight, 0) {
			return nil, fmt.Errorf("edge %s->%s has non-finite weight", e.From, e.To)
		}
		g.AddEdge(e)
	}
	return g, nil
}

// LoadFile reads and parses a scenario file.
func LoadFile(path string) (*graph.Graph, *Descriptor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Load(data)
}
