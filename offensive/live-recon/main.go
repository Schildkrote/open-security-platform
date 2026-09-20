// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Command live-recon runs the four live-gated recon features (active
// scanning, recovery probing, people search, authenticated scraping). It
// defaults to mock mode (offline); each feature is opt-in via -live and the
// real path is only reached with -real plus the required scope/credential.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Schildkrote/live-recon/internal/probe"

	"github.com/Schildkrote/platform/livegate"
)

func main() {
	feature := flag.String("feature", "", "feature: active-scanning | recovery-probing | people-search | authenticated-scrape | recovery-reveal")
	target := flag.String("target", "", "target (host:port for active-scanning; URL template for the rest)")
	live := flag.String("live", "", "comma-separated live features to enable (default: none = mock-only)")
	real := flag.Bool("real", false, "use the real (network) runner for the enabled feature")
	credential := flag.String("credential", "", "identifier/credential (env LIVE_RECON_CREDENTIAL also read)")
	consent := flag.Bool("consent", false, "subject consent (required for people-search and recovery-reveal)")
	sources := flag.String("sources", "", "comma-separated people-search sources to query (default: first whitelisted source)")
	aggressive := flag.Bool("aggressive", false, "enable the nmap/nuclei sub-gate of active-scanning (requires external binaries)")
	nuclei := flag.String("nuclei", "", "nuclei template dir to run with -aggressive (default: skip)")
	format := flag.String("format", "text", "output: text | json")
	flag.Parse()

	if *feature == "" || *target == "" {
		log.Fatal("-feature and -target are required")
	}
	if *credential == "" {
		*credential = os.Getenv("LIVE_RECON_CREDENTIAL")
	}

	enabled, err := parseLive(*live)
	if err != nil {
		log.Fatalf("-live: %v", err)
	}
	printGate(enabled)

	if !livegate.Enabled(enabled, *feature) {
		if *real {
			log.Fatalf("feature %q is not enabled (pass -live %s)", *feature, *feature)
		}
		// Mock path: always available, offline.
		fmt.Fprintf(os.Stderr, "mock mode: feature %q (offline, no live gate required)\n", *feature)
	}

	var runner probe.Runner
	switch {
	case *real && livegate.Enabled(enabled, *feature):
		runner = probe.RealRunners()[*feature]
	default:
		runner = probe.MockRunners()[*feature]
	}
	if runner == nil {
		log.Fatalf("unknown feature %q", *feature)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	res, err := runner.Run(ctx, *target, probe.RunOpts{
		Consent:        *consent,
		Credential:     *credential,
		Sources:        *sources,
		Aggressive:     *aggressive,
		NucleiTemplate: *nuclei,
	})
	if err != nil {
		log.Fatalf("run: %v", err)
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			log.Fatalf("encode: %v", err)
		}
	default:
		fmt.Print(renderText(res))
	}
}

// parseLive uses the shared platform/livegate parser (single source of truth).
func parseLive(spec string) ([]string, error) {
	return livegate.Parse(spec)
}

// printGate shows the live-gate state at the start of every run.
func printGate(enabled []string) {
	fmt.Fprint(os.Stderr, livegate.Summary(enabled))
}

func renderText(res *probe.ProbeResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "live-recon: %s target=%q\n", res.Feature, res.Target)
	status := "no result"
	switch {
	case res.Found:
		status = "found"
	case res.Uncertain:
		status = "uncertain"
	default:
		status = "not found"
	}
	fmt.Fprintf(&b, "  status=%s detail=%q (%dms)\n", status, res.Detail, res.LatencyMS)
	if len(res.Evidence) > 0 {
		for k, v := range res.Evidence {
			fmt.Fprintf(&b, "  evidence.%s=%v\n", k, v)
		}
	}
	return b.String()
}
