// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

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
)

func main() {
	feature := flag.String("feature", "", "feature: active-scanning | recovery-probing | people-search | authenticated-scrape")
	target := flag.String("target", "", "target (host:port for active-scanning; URL template for the rest)")
	live := flag.String("live", "", "comma-separated live features to enable (default: none = mock-only)")
	real := flag.Bool("real", false, "use the real (network) runner for the enabled feature")
	credential := flag.String("credential", "", "identifier/credential (env LIVE_RECON_CREDENTIAL also read)")
	consent := flag.Bool("consent", false, "subject consent (required for people-search)")
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

	if !probe.Enabled(enabled, *feature) {
		if *real {
			log.Fatalf("feature %q is not enabled (pass -live %s)", *feature, *feature)
		}
		// Mock path: always available, offline.
		fmt.Fprintf(os.Stderr, "mock mode: feature %q (offline, no live gate required)\n", *feature)
	}

	var runner probe.Runner
	switch {
	case *real && probe.Enabled(enabled, *feature):
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
		Consent:    *consent,
		Credential: *credential,
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

// parseLive splits a comma-separated feature list, validating each.
func parseLive(spec string) ([]string, error) {
	if spec == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range strings.Split(spec, ",") {
		f := strings.TrimSpace(raw)
		if f == "" {
			continue
		}
		if !validFeature(f) {
			return nil, fmt.Errorf("unknown feature %q (valid: %s)", f, strings.Join(probe.AllFeatures(), ", "))
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}

func validFeature(f string) bool {
	for _, v := range probe.AllFeatures() {
		if v == f {
			return true
		}
	}
	return false
}

// printGate shows the live-gate state at the start of every run.
func printGate(enabled []string) {
	fmt.Fprintln(os.Stderr, "live-gate: "+gateSummary(enabled))
}

func gateSummary(enabled []string) string {
	var parts []string
	for _, f := range probe.AllFeatures() {
		state := "off"
		if probe.Enabled(enabled, f) {
			state = "ON"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", f, state))
	}
	return strings.Join(parts, " ")
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
