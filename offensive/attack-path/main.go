// Command attack-path analyzes attack paths in a scenario graph.
//
// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Schildkrote/attack-path/internal/analysis"
	"github.com/Schildkrote/attack-path/internal/enrich"
	"github.com/Schildkrote/attack-path/internal/geo"
	"github.com/Schildkrote/attack-path/internal/ingest"
	"github.com/Schildkrote/attack-path/internal/passive"
	"github.com/Schildkrote/attack-path/internal/path"
	"github.com/Schildkrote/attack-path/internal/render"
	"github.com/Schildkrote/attack-path/internal/shodan"
)

func main() {
	scenario := flag.String("scenario", "examples/scenario.json", "path to scenario JSON")
	format := flag.String("format", "text", "output format: text | json | dot")
	maxDepth := flag.Int("maxdepth", 12, "max path depth")
	top := flag.Int("top", 5, "number of remediation recommendations")

	// Enrichment flags (mock/offline by default).
	shodanDork := flag.String("shodan", "", "shodan dork to resolve into exposure nodes (mock|shodan source)")
	shodanSource := flag.String("shodan-source", "mock", "shodan source: mock | shodan (live-gated, needs -shodan-key)")
	shodanKey := flag.String("shodan-key", "", "Shodan API key (or env SHODAN_API_KEY)")
	geoEnrich := flag.Bool("geo", false, "enrich nodes with ip/phone geo context (static table, offline)")
	geoTable := flag.String("geo-table", "", "geo table JSON file (overrides built-in table)")
	domain := flag.String("domain", "", "passive domain intelligence: resolve domain into exposure nodes (offline table)")
	domainTable := flag.String("domain-table", "", "passive domain table JSON file (overrides built-in)")

	flag.Parse()

	if *shodanKey == "" {
		*shodanKey = os.Getenv("SHODAN_API_KEY")
	}
	if *geoEnrich || *shodanDork != "" {
		fmt.Fprintln(os.Stderr, "enrich: on (offline static table by default; live Shodan needs -shodan-source shodan -shodan-key)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	g, desc, err := ingest.LoadFile(*scenario)
	if err != nil {
		log.Fatalf("load scenario: %v", err)
	}

	// Shodan dork → exposure nodes.
	if *shodanDork != "" {
		var src shodan.Source
		switch *shodanSource {
		case "mock":
			src = shodan.NewMock()
		case "shodan":
			if *shodanKey == "" {
				log.Fatal("-shodan-source shodan requires -shodan-key (or SHODAN_API_KEY)")
			}
			api := shodan.NewAPI()
			api.APIKey = *shodanKey
			src = api
		default:
			log.Fatalf("unknown -shodan-source %q (mock|shodan)", *shodanSource)
		}
		n, err := enrich.AddShodanExposures(ctx, g, src, *shodanDork)
		if err != nil {
			log.Fatalf("shodan enrich: %v", err)
		}
		fmt.Fprintf(os.Stderr, "shodan: +%d exposure nodes from dork %q\n", n, *shodanDork)
	}

	// Geo enrichment (static, offline).
	if *geoEnrich {
		lk := geo.NewStatic()
		if *geoTable != "" {
			if err := lk.LoadTable(readFile(*geoTable)); err != nil {
				log.Fatalf("geo table: %v", err)
			}
		}
		n := enrich.AddGeoEnrichment(g, lk)
		fmt.Fprintf(os.Stderr, "geo: enriched %d nodes\n", n)
	}

	// Passive domain intelligence (static, offline).
	if *domain != "" {
		src := passive.NewStatic()
		if *domainTable != "" {
			if err := src.LoadTable(readFile(*domainTable)); err != nil {
				log.Fatalf("domain table: %v", err)
			}
		}
		n, err := passive.AddDomainExposures(g, src, *domain)
		if err != nil {
			log.Fatalf("domain enrich: %v", err)
		}
		fmt.Fprintf(os.Stderr, "domain: +%d exposure nodes from %q\n", n, *domain)
	}

	paths := path.FindPaths(g, *maxDepth)
	recs := analysis.Remediation(paths, *top)
	name := desc.Name
	if name == "" {
		name = *scenario
	}

	switch *format {
	case "json":
		fmt.Println(render.JSON(name, paths, recs))
	case "dot":
		fmt.Print(render.DOT(g, paths))
	default:
		fmt.Print(render.Text(name, paths, recs))
	}
	_ = os.Stdout
}

func readFile(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		log.Fatalf("read %s: %v", p, err)
	}
	return b
}
