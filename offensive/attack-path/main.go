// Command attack-path analyzes attack paths in a scenario graph.
//
// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Schildkrote/attack-path/internal/analysis"
	"github.com/Schildkrote/attack-path/internal/auditlog"
	"github.com/Schildkrote/attack-path/internal/enrich"
	"github.com/Schildkrote/attack-path/internal/geo"
	"github.com/Schildkrote/attack-path/internal/ingest"
	"github.com/Schildkrote/attack-path/internal/passive"
	"github.com/Schildkrote/attack-path/internal/path"
	"github.com/Schildkrote/attack-path/internal/render"
	"github.com/Schildkrote/attack-path/internal/shodan"
	"github.com/Schildkrote/platform/livegate"
)

// flags holds the parsed CLI configuration.
type flags struct {
	scenario     *string
	format       *string
	maxDepth     *int
	top          *int
	shodanDork   *string
	shodanSource *string
	geoEnrich    *bool
	geoTable     *string
	domain       *string
	domainTable  *string
	live         *string
	auditPath    *string
}

// newFlagSet registers all CLI flags into a fresh FlagSet (testable; see
// main_test.go). Credentials are never on argv (AP-1): the Shodan API key is
// read from the SHODAN_API_KEY environment variable only.
func newFlagSet() (*flag.FlagSet, *flags) {
	fs := flag.NewFlagSet("attack-path", flag.ExitOnError)
	f := &flags{}
	f.scenario = fs.String("scenario", "examples/scenario.json", "path to scenario JSON")
	f.format = fs.String("format", "text", "output format: text | json | dot")
	f.maxDepth = fs.Int("maxdepth", 12, "max path depth")
	f.top = fs.Int("top", 5, "number of remediation recommendations")

	// Enrichment flags (mock/offline by default).
	f.shodanDork = fs.String("shodan", "", "shodan dork to resolve into exposure nodes (mock|shodan source)")
	f.shodanSource = fs.String("shodan-source", "mock", "shodan source: mock | shodan (live-gated: --live active-scanning + SHODAN_API_KEY env)")
	f.geoEnrich = fs.Bool("geo", false, "enrich nodes with ip/phone geo context (static table, offline)")
	f.geoTable = fs.String("geo-table", "", "geo table JSON file (overrides built-in table)")
	f.domain = fs.String("domain", "", "passive domain intelligence: resolve domain into exposure nodes (offline table)")
	f.domainTable = fs.String("domain-table", "", "passive domain table JSON file (overrides built-in)")

	// Live-gate + audit flags (mock/offline by default; see AGENTS.md).
	f.live = fs.String("live", "", "comma-separated live features to enable (see --live-help)")
	f.auditPath = fs.String("audit-path", "", "audit log JSONL path (records live actions; empty = in-memory only)")
	fs.Bool("live-help", false, "print the live-gate policy table and exit")
	return fs, f
}

// resolveLive parses the -live spec and honors -live-help.
func resolveLive(fs *flag.FlagSet, spec string) []string {
	if fs.Lookup("live-help").Value.(flag.Getter).String() == "true" {
		fmt.Fprint(os.Stderr, livegate.Summary(nil))
		os.Exit(0)
	}
	enabled, err := livegate.Parse(spec)
	if err != nil {
		log.Fatalf("-live: %v", err)
	}
	fmt.Fprint(os.Stderr, livegate.Summary(enabled))
	return enabled
}

// liveGateError enforces the AP-2 policy gate: the live Shodan source is only
// reachable when --live active-scanning is enabled; the mock path stays fully
// offline and ungated.
func liveGateError(enabled []string, source string) error {
	isLive := source == "shodan"
	if isLive && !livegate.Enabled(enabled, livegate.FeatureActiveScanning) {
		return errLiveGateRequired
	}
	return nil
}

// errLiveGateRequired is returned when the live Shodan source is selected
// without the active-scanning live feature.
var errLiveGateRequired = fmt.Errorf("-shodan-source shodan requires --live active-scanning (mock path stays offline: -shodan-source mock)")

func main() {
	fs, f := newFlagSet()
	_ = fs.Parse(os.Args[1:])
	enabled := resolveLive(fs, *f.live)

	audit, err := auditlog.Open(*f.auditPath)
	if err != nil {
		log.Fatalf("audit log: %v", err)
	}

	if *f.geoEnrich || *f.shodanDork != "" {
		fmt.Fprintln(os.Stderr, "enrich: on (offline static table by default; live Shodan needs --live active-scanning + SHODAN_API_KEY)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	g, desc, err := ingest.LoadFile(*f.scenario)
	if err != nil {
		log.Fatalf("load scenario: %v", err)
	}

	// Shodan dork → exposure nodes.
	if *f.shodanDork != "" {
		if err := liveGateError(enabled, *f.shodanSource); err != nil {
			log.Fatal(err)
		}
		src, err := newShodanSource(*f.shodanSource, shodanKeyFromEnv())
		if err != nil {
			log.Fatalf("shodan source: %v", err)
		}
		n, err := enrich.AddShodanExposures(ctx, g, src, *f.shodanDork)
		if err != nil {
			log.Fatalf("shodan enrich: %v", err)
		}
		fmt.Fprintf(os.Stderr, "shodan: +%d exposure nodes from dork %q\n", n, *f.shodanDork)
		gateState := "off"
		if livegate.Enabled(enabled, livegate.FeatureActiveScanning) {
			gateState = "active-scanning:ON"
		}
		// Audit-log the live/passive enrichment: source, dork, device count —
		// never key material (AP-3).
		if _, err := audit.Record(gateState, *f.shodanSource, *f.shodanDork, n, time.Now().UTC().Format(time.RFC3339)); err != nil {
			log.Fatalf("audit record: %v", err)
		}
	}

	// Geo enrichment (static, offline).
	if *f.geoEnrich {
		lk := geo.NewStatic()
		if *f.geoTable != "" {
			if err := lk.LoadTable(readFile(*f.geoTable)); err != nil {
				log.Fatalf("geo table: %v", err)
			}
		}
		n := enrich.AddGeoEnrichment(g, lk)
		fmt.Fprintf(os.Stderr, "geo: enriched %d nodes\n", n)
	}

	// Passive domain intelligence (static, offline).
	if *f.domain != "" {
		src := passive.NewStatic()
		if *f.domainTable != "" {
			if err := src.LoadTable(readFile(*f.domainTable)); err != nil {
				log.Fatalf("domain table: %v", err)
			}
		}
		n, err := passive.AddDomainExposures(g, src, *f.domain)
		if err != nil {
			log.Fatalf("domain enrich: %v", err)
		}
		fmt.Fprintf(os.Stderr, "domain: +%d exposure nodes from %q\n", n, *f.domain)
	}

	paths := path.FindPaths(g, *f.maxDepth)
	recs := analysis.Remediation(paths, *f.top)
	name := desc.Name
	if name == "" {
		name = *f.scenario
	}

	switch *f.format {
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

// shodanKeyFromEnv reads the Shodan API key from the environment only (AP-1):
// argv is visible in ps output and shell history, and the safety model
// requires credentials "only in memory or an env var (never argv, never the
// audit log)". An empty value is valid — the mock source needs no key.
func shodanKeyFromEnv() string {
	return os.Getenv("SHODAN_API_KEY")
}

// newShodanSource resolves the -shodan-source selector into a Source. The
// live API source requires a key from the environment.
func newShodanSource(selector, key string) (shodan.Source, error) {
	switch selector {
	case "mock":
		return shodan.NewMock(), nil
	case "shodan":
		if key == "" {
			return nil, fmt.Errorf("-shodan-source shodan requires the SHODAN_API_KEY environment variable")
		}
		api := shodan.NewAPI()
		api.APIKey = key
		return api, nil
	default:
		return nil, fmt.Errorf("unknown -shodan-source %q (mock|shodan)", selector)
	}
}
