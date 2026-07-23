// Package analysis identifies choke points and prioritizes remediation.
package analysis

import (
	"sort"

	"github.com/example/attack-path/internal/path"
)

// ChokePoint is a node or edge that lies on multiple attack paths.
type ChokePoint struct {
	Kind      string `json:"kind"` // "node" | "edge"
	ID        string `json:"id"`
	PathCount int    `json:"path_count"`
}

// ChokePoints ranks nodes and edges by how many attack paths traverse them.
// Cutting a high-count choke point breaks the most attack paths.
func ChokePoints(paths []path.Path) (nodes []ChokePoint, edges []ChokePoint) {
	nodeCount := map[string]int{}
	edgeCount := map[string]int{}
	for _, p := range paths {
		for _, n := range p.Nodes {
			nodeCount[n]++
		}
		for _, e := range p.Edges {
			edgeCount[e]++
		}
	}
	for id, c := range nodeCount {
		nodes = append(nodes, ChokePoint{Kind: "node", ID: id, PathCount: c})
	}
	for id, c := range edgeCount {
		edges = append(edges, ChokePoint{Kind: "edge", ID: id, PathCount: c})
	}
	sortChoke(nodes)
	sortChoke(edges)
	return nodes, edges
}

func sortChoke(cps []ChokePoint) {
	sort.Slice(cps, func(i, j int) bool {
		if cps[i].PathCount != cps[j].PathCount {
			return cps[i].PathCount > cps[j].PathCount
		}
		return cps[i].ID < cps[j].ID
	})
}

// Recommendation proposes a remediation and how many paths it would break.
type Recommendation struct {
	ChokePoint
	PathsBroken int    `json:"paths_broken"`
	Advice      string `json:"advice"`
}

// Remediation returns the top choke points to cut, ranked by paths broken.
func Remediation(paths []path.Path, top int) []Recommendation {
	nodes, edges := ChokePoints(paths)
	var recs []Recommendation
	for _, n := range nodes {
		recs = append(recs, Recommendation{
			ChokePoint:  n,
			PathsBroken: n.PathCount,
			Advice:      "Harden/segment node '" + n.ID + "' (patch, remove exposure, or least-privilege) to break " + itoa(n.PathCount) + " path(s).",
		})
	}
	for _, e := range edges {
		recs = append(recs, Recommendation{
			ChokePoint:  e,
			PathsBroken: e.PathCount,
			Advice:      "Sever relationship '" + e.ID + "' (revoke permission / network control) to break " + itoa(e.PathCount) + " path(s).",
		})
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].PathsBroken > recs[j].PathsBroken })
	if top > 0 && len(recs) > top {
		recs = recs[:top]
	}
	return recs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
