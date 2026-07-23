// Package ingest loads an attack graph from a JSON scenario descriptor.
package ingest

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/example/attack-path/internal/graph"
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
	g := graph.New()
	for _, n := range d.Nodes {
		if n.ID == "" {
			return nil, nil, fmt.Errorf("node missing id")
		}
		g.AddNode(n)
	}
	for _, e := range d.Edges {
		if !g.HasNode(e.From) || !g.HasNode(e.To) {
			return nil, nil, fmt.Errorf("edge %s->%s references unknown node", e.From, e.To)
		}
		g.AddEdge(e)
	}
	return g, &d, nil
}

// LoadFile reads and parses a scenario file.
func LoadFile(path string) (*graph.Graph, *Descriptor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Load(data)
}
