// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Schildkrote/connector-alpr"
	obpconnector "github.com/Schildkrote/connector-obp"
	ospconnector "github.com/Schildkrote/connector-osp"
	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/policy"
)

// Fixture is a batch hydrate file.
type Fixture struct {
	Hotlist  []alpr.HotlistEntry     `json:"hotlist"`
	Plates   []alpr.PlateEvent       `json:"plates"`
	OSP      []ospconnector.Finding  `json:"osp"`
	OBP      []obpconnector.MatchHit `json:"obp"`
	StoreOut string                  `json:"store_out"`
}

func main() {
	fixturePath := flag.String("fixture", "", "JSON fixture path")
	storeOut := flag.String("out", "/tmp/odp-store.json", "output store path")
	flag.Parse()
	if *fixturePath == "" {
		log.Fatal("-fixture required")
	}
	b, err := os.ReadFile(*fixturePath)
	if err != nil {
		log.Fatal(err)
	}
	var fix Fixture
	if err := json.Unmarshal(b, &fix); err != nil {
		log.Fatal(err)
	}
	if fix.StoreOut != "" {
		*storeOut = fix.StoreOut
	}

	s := ontology.NewStore()
	logChain := audit.New()

	for _, f := range fix.OSP {
		if _, err := ospconnector.Ingest(s, f); err != nil {
			log.Fatalf("osp: %v", err)
		}
	}
	for _, h := range fix.OBP {
		if _, err := obpconnector.Ingest(s, h); err != nil {
			log.Fatalf("obp: %v", err)
		}
	}

	ing := &alpr.Ingestor{Store: s, Log: logChain, Hotlist: alpr.NewHotlist(fix.Hotlist)}
	ctx := alpr.IngestContext{Actor: "ingest-cli", Role: policy.RoleOfficer, Purpose: policy.PurposePatrolAlert}
	hits := 0
	for _, ev := range fix.Plates {
		if ev.TS.IsZero() {
			ev.TS = time.Now().UTC()
		}
		r := ing.Ingest(ctx, ev)
		if r.Error != "" {
			log.Fatalf("alpr: %s", r.Error)
		}
		if r.HotHit {
			hits++
		}
	}

	if err := s.SaveJSON(*storeOut); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ingested osp=%d obp=%d plates=%d hot_hits=%d → %s\n",
		len(fix.OSP), len(fix.OBP), len(fix.Plates), hits, *storeOut)
}
