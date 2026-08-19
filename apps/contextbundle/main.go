// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Schildkrote/aip"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/policy"
)

func main() {
	storePath := flag.String("store", "", "ontology store JSON")
	root := flag.String("root", "", "root object id")
	depth := flag.Int("depth", 2, "expand depth")
	purpose := flag.String("purpose", policy.PurposeInvestigation, "policy purpose")
	role := flag.String("role", policy.RoleAgent, "policy role")
	hasCase := flag.Bool("case", false, "has case context")
	caseID := flag.String("case-id", "", "case id")
	hasWarrant := flag.Bool("warrant", false, "has warrant")
	warrantID := flag.String("warrant-id", "", "warrant id")
	out := flag.String("out", "", "write JSON bundle path (optional)")
	format := flag.String("format", "md", "md|json")
	flag.Parse()

	if *storePath == "" || *root == "" {
		log.Fatal("-store and -root required")
	}
	s, err := ontology.LoadJSON(*storePath)
	if err != nil {
		log.Fatal(err)
	}
	b, err := aip.Export(s, aip.ExportOptions{
		RootID: *root, Depth: *depth,
		Purpose: *purpose, Role: *role,
		HasCase: *hasCase, CaseID: *caseID,
		HasWarrant: *hasWarrant, WarrantID: *warrantID,
		IncludeHints: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	if *out != "" {
		if err := aip.WriteJSON(*out, b); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(b)
	default:
		fmt.Print(b.Markdown())
	}
}
