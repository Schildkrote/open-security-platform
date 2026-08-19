// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

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

	"github.com/Schildkrote/credential-intel/internal/source"

	"github.com/Schildkrote/platform/livegate"
)

func main() {
	ident := flag.String("id", "", "identifier to look up (email or SHA-1 hash) (required)")
	mode := flag.String("mode", "mock", "source: mock | hibp (hibp is live-gated)")
	apiKey := flag.String("api-key", "", "HIBP API key (optional; env HIBP_API_KEY also read)")
	breaches := flag.Bool("breaches", false, "hibp mode: also fetch the breach list for the identifier")
	format := flag.String("format", "text", "output: text | json")
	mockFile := flag.String("mock-file", "", "mock source: JSON file with sample breaches")
	live := flag.String("live", "", "comma-separated livegate features (hibp requires people-search or leave empty to allow with notice-only legacy; prefer -live people-search for PII lookups)")
	flag.Parse()

	if *ident == "" {
		log.Fatal("-id is required")
	}
	if *apiKey == "" {
		*apiKey = os.Getenv("HIBP_API_KEY")
	}

	var src source.Source
	var hibp *source.HIBP
	switch *mode {
	case "mock":
		if *mockFile != "" {
			src = source.NewMockFile(*mockFile)
		} else {
			src = source.NewMock()
		}
	case "hibp":
		hibp = source.NewHIBP()
		if *apiKey != "" {
			hibp.APIKey = *apiKey
		}
		src = hibp
	default:
		log.Fatalf("unknown -mode %q (mock|hibp)", *mode)
	}

	enabled, err := livegate.Parse(*live)
	if err != nil {
		log.Fatalf("-live: %v", err)
	}
	if *mode == "hibp" {
		// HIBP is outbound network. Require an explicit livegate acknowledgment.
		// Closest registered exception is people-search (PII-adjacent lookup);
		// k-anonymity still applies in the HIBP client (prefix only).
		if !livegate.Enabled(enabled, livegate.FeaturePeopleSearch) {
			log.Fatal("hibp mode is live-gated: pass -live people-search (and optional subject consent ops policy). Mock mode needs no gate.")
		}
		fmt.Fprint(os.Stderr, livegate.Summary(enabled))
		fmt.Fprintln(os.Stderr, "credential-intel/hibp: k-anonymity range request; only SHA-1 prefix leaves the machine")
	} else if len(enabled) > 0 {
		fmt.Fprint(os.Stderr, livegate.Summary(enabled))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := src.Pwned(ctx, *ident)
	if err != nil {
		log.Fatalf("lookup: %v", err)
	}
	if *breaches && hibp != nil {
		b, err := hibp.Breaches(ctx, *ident)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: breach list: %v\n", err)
		} else {
			a.Breaches = b
		}
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(a); err != nil {
			log.Fatalf("encode: %v", err)
		}
	default:
		fmt.Print(renderText(a))
	}
}

func renderText(a source.Answer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "credential-intel: lookup of %s via %s\n", a.IdentifierHash, a.Source)
	if !a.Pwned {
		b.WriteString("  not found in sample/known breaches\n")
		return b.String()
	}
	fmt.Fprintf(&b, "  PWNED (k-anon count: %d)\n", a.Count)
	for _, br := range a.Breaches {
		fmt.Fprintf(&b, "  - %s (%d)\n", br.Title, br.Year)
	}
	return b.String()
}
