// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package enrich

import (
	"context"
	"testing"

	"github.com/Schildkrote/attack-path/internal/geo"
	"github.com/Schildkrote/attack-path/internal/graph"
	"github.com/Schildkrote/attack-path/internal/shodan"
)

func TestAddShodanExposures(t *testing.T) {
	g := graph.New()
	src := shodan.NewMock()
	n, err := AddShodanExposures(context.Background(), g, src, "port:22")
	if err != nil {
		t.Fatalf("AddShodanExposures: %v", err)
	}
	if n != 1 {
		t.Fatalf("added %d nodes, want 1", n)
	}
	node, ok := g.Node("shodan:198.51.100.5:22")
	if !ok {
		t.Fatal("shodan node missing")
	}
	if node.Props["product"] != "OpenSSH" {
		t.Fatalf("product = %q", node.Props["product"])
	}
	// Idempotent: second call adds 0.
	n2, _ := AddShodanExposures(context.Background(), g, src, "port:22")
	if n2 != 0 {
		t.Fatalf("second call added %d, want 0", n2)
	}
}

func TestAddGeoEnrichment(t *testing.T) {
	g := graph.New()
	g.AddNode(graph.Node{
		ID: "web", Type: graph.TypeExposure, Name: "web", Exposure: true,
		Props: map[string]string{"ip": "192.0.2.10"},
	})
	g.AddNode(graph.Node{
		ID: "support", Type: graph.TypeIdentity, Name: "support",
		Props: map[string]string{"phone": "+4930123456"},
	})
	g.AddNode(graph.Node{ID: "internal", Type: graph.TypeAsset, Name: "internal"})
	n := AddGeoEnrichment(g, geo.NewStatic())
	if n != 2 {
		t.Fatalf("enriched %d nodes, want 2", n)
	}
	web, _ := g.Node("web")
	if web.Props["geo_country"] != "US" {
		t.Fatalf("web geo_country = %q", web.Props["geo_country"])
	}
	sup, _ := g.Node("support")
	if sup.Props["geo_country"] != "DE" {
		t.Fatalf("support geo_country = %q", sup.Props["geo_country"])
	}
}
