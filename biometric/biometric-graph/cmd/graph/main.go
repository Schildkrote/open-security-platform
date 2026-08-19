// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Schildkrote/biometric-graph"
)

func main() {
	agency := flag.String("agency", "agency-a", "agency id")
	action := flag.String("action", "demo", "demo | export | dot")
	consent := flag.Bool("consent", false, "client consent for share")
	dpia := flag.Bool("dpia", false, "DPiA acknowledged for share")
	format := flag.String("format", "text", "text|json")
	flag.Parse()

	g := graph.New(*agency)
	alice := g.UpsertPerson("alice", "Alice Example", "general", "case-1")
	alice2 := g.UpsertPerson("alice-mirror", "Alice Example", "general", "case-2")
	g.LinkIdentity(alice.ID, alice2.ID, 0.97, "case-link")
	g.AddMatchEvent("probe-"+alice.ID[:8], alice.ID, 0.93, "case-1")

	switch *action {
	case "dot":
		fmt.Print(g.DOT())
	case "export":
		bundle, d, err := g.Share(*consent, *dpia)
		if err != nil {
			log.Fatalf("export refused: %v (basis=%s)", err, d.Outcome)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(bundle)
	default:
		if *format == "json" {
			b, _ := json.MarshalIndent(g, "", "  ")
			fmt.Println(string(b))
			return
		}
		fmt.Printf("graph agency=%s nodes=%d edges=%d\n", g.Agency, len(g.Nodes()), len(g.Edges()))
		for _, n := range g.Nodes() {
			name := g.LocalName(n.ID)
			if name == "" {
				name = "(no local name)"
			}
			fmt.Printf("  node %s… name=%q case=%s\n", n.ID[:12], name, n.CaseID)
		}
		comp := g.Component(alice.ID)
		fmt.Printf("  identity component of alice: %d nodes\n", len(comp))
	}
}
