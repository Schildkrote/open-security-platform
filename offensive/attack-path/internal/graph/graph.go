// Package graph models assets, identities, permissions, vulnerabilities and
// data as a directed graph used to find attack paths.
package graph

import "strconv"

// Node types used across scenarios.
const (
	TypeExposure   = "exposure"   // internet-facing / initial foothold
	TypeAsset      = "asset"      // host / service / resource
	TypeIdentity   = "identity"   // user / role / service account
	TypePermission = "permission" // entitlement that enables a step
	TypeVuln       = "vuln"       // exploitable weakness
	TypeData       = "data"       // data store
	TypeCritical   = "critical"   // crown-jewel target
)

// Node is a vertex in the attack graph.
type Node struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Name     string            `json:"name"`
	Critical bool              `json:"critical,omitempty"`
	Exposure bool              `json:"exposure,omitempty"`
	Props    map[string]string `json:"props,omitempty"`
}

// Exploitability returns the node's exploitability factor in (0,1].
func (n Node) Exploitability() float64 {
	if n.Props == nil {
		return 1.0
	}
	if v, ok := n.Props["exploitability"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return clamp01(f)
		}
	}
	return 1.0
}

// Edge is a directed relationship that an attacker can traverse.
type Edge struct {
	From   string  `json:"from"`
	To     string  `json:"to"`
	Type   string  `json:"type"`
	Weight float64 `json:"weight"` // traversal likelihood in (0,1]
}

// Graph is a directed attack graph.
type Graph struct {
	nodes map[string]Node
	out   map[string][]Edge
	order []string
}

func New() *Graph {
	return &Graph{nodes: map[string]Node{}, out: map[string][]Edge{}}
}

func (g *Graph) AddNode(n Node) {
	if _, ok := g.nodes[n.ID]; !ok {
		g.order = append(g.order, n.ID)
	}
	g.nodes[n.ID] = n
}

func (g *Graph) AddEdge(e Edge) {
	if e.Weight <= 0 || e.Weight > 1 {
		e.Weight = 1
	}
	g.out[e.From] = append(g.out[e.From], e)
}

func (g *Graph) Node(id string) (Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

func (g *Graph) HasNode(id string) bool {
	_, ok := g.nodes[id]
	return ok
}

func (g *Graph) Nodes() []Node {
	out := make([]Node, 0, len(g.order))
	for _, id := range g.order {
		out = append(out, g.nodes[id])
	}
	return out
}

func (g *Graph) OutEdges(id string) []Edge {
	return g.out[id]
}

// Entries returns exposure nodes (possible initial footholds).
func (g *Graph) Entries() []Node {
	var out []Node
	for _, n := range g.Nodes() {
		if n.Exposure || n.Type == TypeExposure {
			out = append(out, n)
		}
	}
	return out
}

// Criticals returns crown-jewel target nodes.
func (g *Graph) Criticals() []Node {
	var out []Node
	for _, n := range g.Nodes() {
		if n.Critical || n.Type == TypeCritical {
			out = append(out, n)
		}
	}
	return out
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
