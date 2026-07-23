package ingest

import (
	"testing"
)

func TestLoadBloodHound(t *testing.T) {
	data := []byte(`{
      "data": {
        "nodes": [
          {"id": "u1", "label": "User", "name": "alice@corp"},
          {"id": "g1", "label": "Group", "name": "Domain Admins", "properties": {"admincount": 1}}
        ],
        "edges": [
          {"source": "u1", "target": "g1", "label": "MemberOf"}
        ]
      }
    }`)
	d, err := LoadBloodHound(data)
	if err != nil {
		t.Fatalf("LoadBloodHound: %v", err)
	}
	if len(d.Nodes) != 2 || len(d.Edges) != 1 {
		t.Fatalf("got %d nodes, %d edges", len(d.Nodes), len(d.Edges))
	}
	g, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !g.HasNode("u1") || !g.HasNode("g1") {
		t.Error("expected both nodes in graph")
	}
	if d.Nodes[1].Props["admincount"] != "1" {
		t.Errorf("expected admincount prop, got %v", d.Nodes[1].Props)
	}
}

func TestLoadBloodHoundTopLevel(t *testing.T) {
	data := []byte(`{"nodes":[{"id":"a","type":"Computer","name":"DC01"}],"edges":[]}`)
	d, err := LoadBloodHound(data)
	if err != nil {
		t.Fatalf("LoadBloodHound: %v", err)
	}
	if len(d.Nodes) != 1 || d.Nodes[0].Type != "Computer" {
		t.Fatalf("unexpected nodes: %+v", d.Nodes)
	}
}

func TestLoadProwler(t *testing.T) {
	data := []byte(`[
      {"Severity":"critical","CheckID":"iam-1","ResourceId":"arn:aws:iam::1:role/admin","ResourceName":"admin","Status":"FAIL","Region":"us-east-1"},
      {"Severity":"low","CheckID":"s3-1","ResourceId":"arn:aws:s3:::ok","Status":"PASS"}
    ]`)
	d, err := LoadProwler(data)
	if err != nil {
		t.Fatalf("LoadProwler: %v", err)
	}
	if len(d.Nodes) != 1 {
		t.Fatalf("expected 1 exposure node (FAIL only), got %d", len(d.Nodes))
	}
	n := d.Nodes[0]
	if !n.Exposure || n.Props["severity"] != "critical" || n.Props["check"] != "iam-1" {
		t.Errorf("unexpected node: %+v", n)
	}
	if _, err := Build(d); err != nil {
		t.Fatalf("Build: %v", err)
	}
}
