// Third-party graph importers (Phase 4): turn external attack-graph / posture
// data into a Descriptor that Build() turns into an attack graph.
//   - BloodHound CE: AD/identity attack-path graph (nodes + relationship edges).
//   - Prowler: cloud-posture findings (failed checks become exposure nodes).
package ingest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Schildkrote/attack-path/internal/graph"
)

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- BloodHound -------------------------------------------------------------

type bhNode struct {
	ID         string         `json:"id"`
	Label      string         `json:"label"`
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties"`
}

type bhEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	From   string `json:"from"`
	To     string `json:"to"`
	Label  string `json:"label"`
	Type   string `json:"type"`
}

type bloodhound struct {
	Nodes []bhNode `json:"nodes"`
	Edges []bhEdge `json:"edges"`
	Data  *struct {
		Nodes []bhNode `json:"nodes"`
		Edges []bhEdge `json:"edges"`
	} `json:"data"`
}

// LoadBloodHound parses a BloodHound graph export (top-level or nested under
// "data") into a Descriptor.
func LoadBloodHound(data []byte) (*Descriptor, error) {
	var bh bloodhound
	if err := json.Unmarshal(data, &bh); err != nil {
		return nil, fmt.Errorf("parse bloodhound: %w", err)
	}
	nodes, edges := bh.Nodes, bh.Edges
	if bh.Data != nil {
		nodes, edges = bh.Data.Nodes, bh.Data.Edges
	}
	d := &Descriptor{Name: "bloodhound"}
	for _, n := range nodes {
		props := map[string]string{}
		for k, v := range n.Properties {
			props[k] = fmt.Sprint(v)
		}
		d.Nodes = append(d.Nodes, graph.Node{
			ID:    n.ID,
			Type:  firstNonEmpty(n.Type, n.Label, "Entity"),
			Name:  firstNonEmpty(n.Name, n.ID),
			Props: props,
		})
	}
	for _, e := range edges {
		d.Edges = append(d.Edges, graph.Edge{
			From:   firstNonEmpty(e.From, e.Source),
			To:     firstNonEmpty(e.To, e.Target),
			Type:   firstNonEmpty(e.Type, e.Label, "related"),
			Weight: 1.0,
		})
	}
	return d, nil
}

// --- Prowler ----------------------------------------------------------------

type prowlerFinding struct {
	Severity     string `json:"Severity"`
	CheckID      string `json:"CheckID"`
	ResourceID   string `json:"ResourceId"`
	ResourceName string `json:"ResourceName"`
	Status       string `json:"Status"`
	Region       string `json:"Region"`
}

// LoadProwler parses Prowler findings (a JSON array) into exposure nodes. Only
// failing checks (Status == "FAIL", or unset) become nodes.
func LoadProwler(data []byte) (*Descriptor, error) {
	var findings []prowlerFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parse prowler: %w", err)
	}
	d := &Descriptor{Name: "prowler"}
	for i, f := range findings {
		if f.Status != "" && !strings.EqualFold(f.Status, "FAIL") {
			continue
		}
		id := firstNonEmpty(f.ResourceID, fmt.Sprintf("finding-%d", i))
		d.Nodes = append(d.Nodes, graph.Node{
			ID:       id,
			Type:     "cloud-resource",
			Name:     firstNonEmpty(f.ResourceName, id),
			Exposure: true,
			Props: map[string]string{
				"severity": strings.ToLower(firstNonEmpty(f.Severity, "medium")),
				"check":    f.CheckID,
				"region":   f.Region,
			},
		})
	}
	return d, nil
}
