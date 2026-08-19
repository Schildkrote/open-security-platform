// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Schildkrote/ontology"
)

func main() {
	storePath := flag.String("store", "", "ontology store JSON")
	from := flag.String("from", "", "start object id")
	to := flag.String("to", "", "optional path target")
	depth := flag.Int("depth", 2, "expand depth")
	format := flag.String("format", "text", "text|json")
	flag.Parse()
	if *storePath == "" || *from == "" {
		log.Fatal("-store and -from required")
	}
	s, err := ontology.LoadJSON(*storePath)
	if err != nil {
		log.Fatal(err)
	}
	if *to != "" {
		path := s.Path(*from, *to, *depth+2)
		if *format == "json" {
			_ = json.NewEncoder(os.Stdout).Encode(path)
			return
		}
		fmt.Printf("path %s → %s (%d hops)\n", *from, *to, len(path))
		for _, l := range path {
			fmt.Printf("  %s --%s--> %s\n", l.From, l.Type, l.To)
		}
		return
	}
	objs, links := s.Expand(*from, *depth)
	if *format == "json" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"objects": objs, "links": links})
		return
	}
	fmt.Printf("expand %s depth=%d objects=%d links=%d\n", *from, *depth, len(objs), len(links))
	for _, o := range objs {
		fmt.Printf("  OBJ %s (%s)\n", o.ID, o.Type)
	}
	for _, l := range links {
		fmt.Printf("  LNK %s --%s--> %s\n", l.From, l.Type, l.To)
	}
}
