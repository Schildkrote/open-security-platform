// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Schildkrote/ontology"
)

func main() {
	storePath := flag.String("store", "", "ontology store JSON")
	id := flag.String("id", "", "object id")
	format := flag.String("format", "md", "md|json")
	flag.Parse()
	if *storePath == "" || *id == "" {
		log.Fatal("-store and -id required")
	}
	s, err := ontology.LoadJSON(*storePath)
	if err != nil {
		log.Fatal(err)
	}
	o, ok := s.Get(*id)
	if !ok {
		log.Fatalf("not found: %s", *id)
	}
	links := s.Neighbors(*id, true)
	if *format == "json" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"object": o, "links": links})
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Dossier: %s\n\n", o.ID)
	fmt.Fprintf(&b, "- **Type:** %s\n- **Classification:** %s\n- **Source:** %s\n\n", o.Type, o.Classification, o.Provenance.Source)
	fmt.Fprintf(&b, "## Properties\n\n")
	for k, v := range o.Properties {
		fmt.Fprintf(&b, "- `%s`: %v\n", k, v)
	}
	fmt.Fprintf(&b, "\n## Links (%d)\n\n", len(links))
	for _, l := range links {
		fmt.Fprintf(&b, "- `%s` --**%s**--> `%s`\n", l.From, l.Type, l.To)
	}
	fmt.Print(b.String())
}
