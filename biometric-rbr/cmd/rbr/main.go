// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Schildkrote/biometric-audit"
	"github.com/Schildkrote/biometric-rbr"
	"github.com/Schildkrote/lawful-basis"
)

func main() {
	galleryPath := flag.String("gallery", "", "gallery JSON path")
	probePath := flag.String("probe", "", "probe JSON path")
	threshold := flag.Float64("threshold", rbr.DefaultThreshold, "cosine threshold")
	consent := flag.Bool("consent", false, "valid client consent present")
	enrolHash := flag.String("enrol-hash", "", "enrol a single image hash into a fresh gallery")
	enrolClient := flag.String("enrol-client", "", "client id for -enrol-hash")
	embeddings := flag.String("embeddings", "", "external embedding table JSON or .f32 directory (empty = mock)")
	format := flag.String("format", "text", "text|json")
	auditPath := flag.String("audit", "", "audit JSONL path (hash-chained log; empty = in-memory only)")
	flag.Parse()

	emb, err := rbr.NewEmbedder(*embeddings)
	if err != nil {
		log.Fatalf("embedder: %v", err)
	}
	fmt.Fprintf(os.Stderr, "embedder=%s\n", emb.Name())

	var g *rbr.Gallery

	if *enrolHash != "" {
		if *enrolClient == "" {
			log.Fatal("-enrol-client required with -enrol-hash")
		}
		d := basis.Decide(basis.Request{
			Purpose: basis.PurposeEnrolment, HasConsent: *consent, Category: basis.CatGeneral,
		})
		if !d.Allowed() {
			log.Fatalf("enrolment refused: %s", d.Reason)
		}
		g = rbr.NewGallery(emb)
		if *auditPath != "" {
			g.SetAudit(newAuditStore(*auditPath))
		}
		if err := g.Enrol(rbr.FaceRecord{
			ID: "enrol-1", ClientID: *enrolClient, ImageHash: *enrolHash, Category: basis.CatGeneral,
		}, d); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "enrolled %s for %s (basis=%s)\n", *enrolHash, *enrolClient, d.Outcome)
		if *galleryPath != "" {
			if err := g.SaveJSON(*galleryPath); err != nil {
				log.Fatal(err)
			}
		}
		if *probePath == "" {
			return
		}
	}

	if g == nil {
		if *galleryPath == "" {
			log.Fatal("-gallery is required (or use -enrol-hash)")
		}
		g, err = rbr.LoadJSON(*galleryPath, emb)
		if err != nil {
			log.Fatalf("load gallery: %v", err)
		}
		if *auditPath != "" {
			g.SetAudit(newAuditStore(*auditPath))
		}
	}

	if *probePath == "" {
		log.Fatal("-probe is required for match")
	}
	probes, err := rbr.ParseProbeFile(*probePath)
	if err != nil {
		log.Fatalf("load probe: %v", err)
	}

	var results []rbr.MatchResult
	for _, p := range probes {
		cat := p.Category
		if cat == "" {
			cat = basis.CatGeneral
		}
		results = append(results, g.MatchProbe(p, *threshold, *consent, cat))
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	default:
		for _, r := range results {
			if r.Refused {
				fmt.Printf("REFUSED probe=%s: %s (basis=%s)\n", r.Probe.ID, r.Reason, r.Basis.Outcome)
				continue
			}
			fmt.Printf("probe=%s matches=%d basis=%s\n", r.Probe.ID, len(r.Matches), r.Basis.Outcome)
			for _, m := range r.Matches {
				fmt.Printf("  hit client=%s gallery=%s score=%.4f\n", m.ClientID, m.GalleryID, m.Score)
			}
		}
	}
	for _, r := range results {
		if r.Refused {
			os.Exit(2)
		}
	}
}

// newAuditStore returns a hash-chained audit store. The Memory store is the
// offline default; JSONL persistence plugs in here when a durable backend is
// chosen (see platform/biometric-audit for the Go chain implementation).
func newAuditStore(path string) audit.Store {
	_ = path
	return audit.NewMemory()
}
