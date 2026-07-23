package ingest

import "testing"

const scenario = `{
  "name": "test",
  "nodes": [
    {"id":"in","type":"exposure","exposure":true},
    {"id":"db","type":"critical","critical":true}
  ],
  "edges": [{"from":"in","to":"db","type":"reach","weight":0.9}]
}`

func TestLoad(t *testing.T) {
	g, d, err := Load([]byte(scenario))
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "test" {
		t.Fatalf("expected name 'test', got %q", d.Name)
	}
	if len(g.Nodes()) != 2 || len(g.Entries()) != 1 || len(g.Criticals()) != 1 {
		t.Fatalf("unexpected graph: %+v", g.Nodes())
	}
}

func TestLoadRejectsUnknownEdgeNode(t *testing.T) {
	bad := `{"nodes":[{"id":"in","type":"exposure"}],"edges":[{"from":"in","to":"ghost"}]}`
	if _, _, err := Load([]byte(bad)); err == nil {
		t.Fatal("expected error for edge referencing unknown node")
	}
}

func TestLoadRejectsBadJSON(t *testing.T) {
	if _, _, err := Load([]byte("{not json")); err == nil {
		t.Fatal("expected parse error")
	}
}
