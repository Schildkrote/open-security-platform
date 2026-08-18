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

	"github.com/Schildkrote/username-enum/internal/engine"
	"github.com/Schildkrote/username-enum/internal/service"
	"github.com/Schildkrote/username-enum/internal/source"
)

func main() {
	username := flag.String("username", "", "username to enumerate (required)")
	mode := flag.String("mode", "mock", "source: mock | http (http is live-gated)")
	services := flag.String("services", "", "comma-separated service names to probe (default: all)")
	maxProbes := flag.Int("max-probes", 25, "max probes per run (live run-cap)")
	intervalMS := flag.Int("interval-ms", 200, "milliseconds between probes (http mode)")
	format := flag.String("format", "text", "output: text | json")
	flag.Parse()

	if *username == "" {
		log.Fatal("-username is required")
	}

	catalog := service.BuiltIn().Filter(splitCSV(*services))
	if len(catalog) == 0 {
		log.Fatal("no services selected (check -services names)")
	}

	var src source.Source
	switch *mode {
	case "mock":
		src = source.NewMock()
	case "http":
		src = source.NewHTTP()
	default:
		log.Fatalf("unknown -mode %q (mock|http)", *mode)
	}

	// Live-gate note: http mode makes outbound GET requests to the service
	// catalog, so it is the live path of this component. The mock path is
	// fully offline. See AGENTS.md safety model for the gate conditions.
	if *mode == "http" {
		fmt.Fprintln(os.Stderr, "live-gate: username-enum/http (read-only GETs, scope = -services, cap = -max-probes)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	res, err := engine.Run(ctx, catalog, src, *username, engine.Options{
		MaxProbes: *maxProbes,
		Interval:  time.Duration(*intervalMS) * time.Millisecond,
	})
	if err != nil && res == nil {
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

func renderText(res *engine.RunResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "username-enum: %q via %s\n", res.Username, res.Source)
	fmt.Fprintf(&b, "probes=%d found=%d uncertain=%d duration=%s\n\n",
		res.Total, res.Found, countUncertain(res), human(res.Duration))
	if res.Found == 0 {
		b.WriteString("no hits (or all uncertain)\n")
		return b.String()
	}
	for _, r := range res.Hits {
		mark := "found"
		if r.Uncertain {
			mark = "uncertain"
		}
		fmt.Fprintf(&b, "  [%s] %-16s %s (%dms)\n", mark, r.Service, r.URL, r.LatencyMS)
	}
	return b.String()
}

func countUncertain(res *engine.RunResult) int {
	n := 0
	for _, r := range res.Results {
		if r.Uncertain {
			n++
		}
	}
	return n
}

func human(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return d.String()
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
