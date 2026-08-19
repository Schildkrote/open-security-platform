// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Schildkrote/lawful-basis"
)

func main() {
	purpose := flag.String("purpose", "enrolment", "purpose identifier")
	regime := flag.String("regime", "gdpr", "legal regime")
	category := flag.String("category", "general", "subject category")
	retention := flag.Int("retention", 30, "requested retention days")
	consent := flag.Bool("consent", false, "valid client consent present")
	dpia := flag.Bool("dpia", false, "DPiA acknowledged")
	le := flag.Bool("le", false, "operator is law enforcement")
	format := flag.String("format", "text", "text|json")
	flag.Parse()

	d := basis.Decide(basis.Request{
		Purpose:          *purpose,
		Regime:           *regime,
		Category:         *category,
		RetentionDays:    *retention,
		HasConsent:       *consent,
		DPIAAcknowledged: *dpia,
		IsLawEnforcement: *le,
	})

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Printf("lawful-basis: outcome=%s allowed=%v\n", d.Outcome, d.Allowed())
		fmt.Printf("  purpose=%s regime=%s category=%s\n", d.Purpose, d.Regime, d.Category)
		fmt.Printf("  retention_max_days=%d\n", d.RetentionMax)
		fmt.Printf("  reason: %s\n", d.Reason)
	}
	if !d.Allowed() {
		os.Exit(2)
	}
}
