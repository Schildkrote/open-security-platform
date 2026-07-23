// Package path enumerates and scores attack paths from exposures to critical assets.
package path

import (
	"sort"
	"strings"

	"github.com/Schildkrote/attack-path/internal/graph"
)

// Path is a single attack path through the graph.
type Path struct {
	Nodes []string `json:"nodes"`
	Edges []string `json:"edges"`
	Risk  float64  `json:"risk"`
	Hops  int      `json:"hops"`
}

func (p Path) String() string {
	return strings.Join(p.Nodes, " -> ")
}

// FindPaths enumerates simple paths from any exposure node to any critical
// node, bounded by maxDepth to keep enumeration finite.
func FindPaths(g *graph.Graph, maxDepth int) []Path {
	if maxDepth <= 0 {
		maxDepth = 12
	}
	critical := map[string]bool{}
	for _, n := range g.Criticals() {
		critical[n.ID] = true
	}

	var results []Path
	visited := map[string]bool{}

	var dfs func(nodeID string, nodes []string, edges []string, risk float64)
	dfs = func(nodeID string, nodes []string, edges []string, risk float64) {
		if critical[nodeID] && len(nodes) > 1 {
			results = append(results, Path{
				Nodes: append([]string(nil), nodes...),
				Edges: append([]string(nil), edges...),
				Risk:  risk,
				Hops:  len(edges),
			})
			return // stop extending once a critical asset is reached
		}
		if len(edges) >= maxDepth {
			return
		}
		visited[nodeID] = true
		defer func() { visited[nodeID] = false }()

		n, _ := g.Node(nodeID)
		for _, e := range g.OutEdges(nodeID) {
			if visited[e.To] {
				continue
			}
			next, _ := g.Node(e.To)
			// Path risk multiplies traversal likelihoods and node exploitability,
			// so longer/harder paths score lower (0..1, higher = more dangerous).
			stepRisk := e.Weight * next.Exploitability()
			dfs(e.To, append(nodes, e.To), append(edges, e.From+"->"+e.To), risk*stepRisk)
			_ = n
		}
	}

	for _, entry := range g.Entries() {
		dfs(entry.ID, []string{entry.ID}, nil, entry.Exploitability())
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Risk != results[j].Risk {
			return results[i].Risk > results[j].Risk
		}
		return results[i].Hops < results[j].Hops
	})
	return results
}
