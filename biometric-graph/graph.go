// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package graph models cross-case / cross-agency person graphs.
// Nodes are pseudonymous persons; edges are observed co-occurrences or
// identity links. Names stay in an agency-local mapping table.
package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Schildkrote/lawful-basis"
)

// Node is a pseudonymous person.
type Node struct {
	ID       string            `json:"id"` // subject_pseudo
	Agency   string            `json:"agency"`
	CaseID   string            `json:"case_id,omitempty"`
	Category string            `json:"category"`
	Props    map[string]string `json:"props,omitempty"`
}

// Edge links two person nodes.
type Edge struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	Type   string    `json:"type"` // identity_link | co_occurrence | match_event
	Weight float64   `json:"weight"`
	CaseID string    `json:"case_id,omitempty"`
	At     time.Time `json:"at,omitempty"`
}

// NameMap is agency-local and never exported across agencies.
type NameMap map[string]string // pseudo -> display name

// Graph is a directed person graph.
type Graph struct {
	Agency string
	nodes  map[string]Node
	out    map[string][]Edge
	order  []string
	names  NameMap
}

// New returns an empty graph for agency.
func New(agency string) *Graph {
	return &Graph{
		Agency: agency,
		nodes:  map[string]Node{},
		out:    map[string][]Edge{},
		names:  NameMap{},
	}
}

// Pseudo hashes a stable identifier.
func Pseudo(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// UpsertPerson adds or updates a person node. displayName is stored only in
// the local name map (never on the node).
func (g *Graph) UpsertPerson(clientKey, displayName, category, caseID string) Node {
	id := Pseudo(g.Agency + ":" + clientKey)
	n := Node{
		ID: id, Agency: g.Agency, CaseID: caseID, Category: category,
		Props: map[string]string{},
	}
	if _, ok := g.nodes[id]; !ok {
		g.order = append(g.order, id)
	}
	g.nodes[id] = n
	if displayName != "" {
		g.names[id] = displayName
	}
	return n
}

// LinkIdentity connects two person nodes (same real person, possibly across cases).
func (g *Graph) LinkIdentity(a, b string, weight float64, caseID string) {
	if weight <= 0 || weight > 1 {
		weight = 1
	}
	e := Edge{From: a, To: b, Type: "identity_link", Weight: weight, CaseID: caseID, At: time.Now().UTC()}
	g.out[a] = append(g.out[a], e)
	// Undirected semantically: also reverse.
	g.out[b] = append(g.out[b], Edge{From: b, To: a, Type: "identity_link", Weight: weight, CaseID: caseID, At: e.At})
}

// LinkCoOccurrence records that two persons were observed together.
func (g *Graph) LinkCoOccurrence(a, b string, weight float64, caseID string) {
	if weight <= 0 || weight > 1 {
		weight = 0.5
	}
	e := Edge{From: a, To: b, Type: "co_occurrence", Weight: weight, CaseID: caseID, At: time.Now().UTC()}
	g.out[a] = append(g.out[a], e)
}

// AddMatchEvent records a match event edge from a probe pseudo to a gallery person.
func (g *Graph) AddMatchEvent(probePseudo, personID string, score float64, caseID string) {
	e := Edge{
		From: probePseudo, To: personID, Type: "match_event",
		Weight: score, CaseID: caseID, At: time.Now().UTC(),
	}
	if _, ok := g.nodes[probePseudo]; !ok {
		g.nodes[probePseudo] = Node{ID: probePseudo, Agency: g.Agency, Category: basis.CatGeneral, CaseID: caseID}
		g.order = append(g.order, probePseudo)
	}
	g.out[probePseudo] = append(g.out[probePseudo], e)
}

// Node returns a node by id.
func (g *Graph) Node(id string) (Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// Nodes returns nodes in insertion order.
func (g *Graph) Nodes() []Node {
	out := make([]Node, 0, len(g.order))
	for _, id := range g.order {
		out = append(out, g.nodes[id])
	}
	return out
}

// Edges returns all edges.
func (g *Graph) Edges() []Edge {
	var out []Edge
	for _, id := range g.order {
		out = append(out, g.out[id]...)
	}
	return out
}

// LocalName resolves a pseudo to a display name (agency-local only).
func (g *Graph) LocalName(id string) string { return g.names[id] }

// Component returns the connected component (undirected over identity_link)
// containing id.
func (g *Graph) Component(id string) []string {
	seen := map[string]bool{}
	var walk func(string)
	walk = func(cur string) {
		if seen[cur] {
			return
		}
		seen[cur] = true
		for _, e := range g.out[cur] {
			if e.Type == "identity_link" {
				walk(e.To)
			}
		}
	}
	walk(id)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ExportBundle is the cross-agency share payload: nodes + edges only,
// never the name map. Caller must pass lawful-basis for cross_agency_share.
type ExportBundle struct {
	FromAgency string `json:"from_agency"`
	Nodes      []Node `json:"nodes"`
	Edges      []Edge `json:"edges"`
}

// Export builds a share bundle. Names are stripped.
func (g *Graph) Export() ExportBundle {
	return ExportBundle{FromAgency: g.Agency, Nodes: g.Nodes(), Edges: g.Edges()}
}

// Import merges a foreign bundle (nodes + edges). Does not import names.
// Requires a permitted cross_agency_share decision (checked by caller).
func (g *Graph) Import(b ExportBundle) (int, int) {
	nN, nE := 0, 0
	for _, n := range b.Nodes {
		if _, ok := g.nodes[n.ID]; !ok {
			g.order = append(g.order, n.ID)
			nN++
		}
		// Keep first-seen agency label; mark foreign.
		if n.Props == nil {
			n.Props = map[string]string{}
		}
		n.Props["imported_from"] = b.FromAgency
		g.nodes[n.ID] = n
	}
	for _, e := range b.Edges {
		g.out[e.From] = append(g.out[e.From], e)
		nE++
	}
	return nN, nE
}

// Share decides + exports under lawful-basis.
func (g *Graph) Share(hasConsent, dpia bool) (ExportBundle, basis.Decision, error) {
	d := basis.Decide(basis.Request{
		Purpose:          basis.PurposeCrossAgencyShare,
		HasConsent:       hasConsent,
		DPIAAcknowledged: dpia,
		Category:         basis.CatGeneral,
		RetentionDays:    30,
	})
	if !d.Allowed() {
		return ExportBundle{}, d, fmt.Errorf("share refused: %s", d.Reason)
	}
	return g.Export(), d, nil
}

// DOT renders a simple Graphviz digraph (pseudos only).
func (g *Graph) DOT() string {
	var b strings.Builder
	b.WriteString("digraph persons {\n")
	for _, n := range g.Nodes() {
		label := n.ID[:12]
		fmt.Fprintf(&b, "  %q [label=%q];\n", n.ID, label+"@"+n.Agency)
	}
	for _, e := range g.Edges() {
		fmt.Fprintf(&b, "  %q -> %q [label=%q];\n", e.From, e.To, e.Type)
	}
	b.WriteString("}\n")
	return b.String()
}

// MarshalJSON exports public graph state (no names).
func (g *Graph) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Agency string `json:"agency"`
		Nodes  []Node `json:"nodes"`
		Edges  []Edge `json:"edges"`
	}{Agency: g.Agency, Nodes: g.Nodes(), Edges: g.Edges()})
}
