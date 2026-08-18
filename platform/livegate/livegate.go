// Package livegate implements the `--live` policy gate for offensive
// components: it defines the default-off gate, the per-feature exceptions, and
// the evidence rules that every live action must honor.
package livegate

import (
	"fmt"
	"strings"
)

// Feature identifiers for the live-gate exceptions (items 6-9 of the safety
// model). A component's live capabilities are a subset of these.
const (
	FeatureActiveScanning      = "active-scanning"      // item 6
	FeatureRecoveryProbing     = "recovery-probing"     // item 7
	FeaturePeopleSearch        = "people-search"        // item 8
	FeatureAuthenticatedScrape = "authenticated-scrape" // item 9
)

// AllFeatures lists every registered live feature, in canonical order.
var AllFeatures = []string{
	FeatureActiveScanning,
	FeatureRecoveryProbing,
	FeaturePeopleSearch,
	FeatureAuthenticatedScrape,
}

// Exception documents the policy exception that allows one live feature.
// It is the single source of truth the CLI surfaces and the audit trail
// references; tests compare against it, so changing it changes behavior.
type Exception struct {
	Feature    string `json:"feature"`
	Name       string `json:"name"`
	Summary    string `json:"summary"`
	Flag       string `json:"flag"`
	Conditions string `json:"conditions"`
}

// Exceptions maps each live feature to its policy exception. All four are
// opt-in per invocation, default OFF; CI and the test suite run with none
// enabled (mock-only).
var Exceptions = map[string]Exception{
	FeatureActiveScanning: {
		Feature:    FeatureActiveScanning,
		Name:       "Active attack-surface scanning",
		Summary:    "Outbound port/service probes, HTTP requests and vulnerability templates against in-scope targets.",
		Flag:       "--live active-scanning",
		Conditions: "explicit scope list per invocation; only GET/HEAD/OPTIONS or read-only probes; no auth bypass, exploit or DoS templates; per-host rate limit (default 5 req/s); evidence redacted and audit-logged; max 5 min per run.",
	},
	FeatureRecoveryProbing: {
		Feature:    FeatureRecoveryProbing,
		Name:       "Account-recovery and account-existence probing",
		Summary:    "Queries password-reset, masked-detail and account-existence endpoints for differential responses.",
		Flag:       "--live recovery-probing",
		Conditions: "explicit target + identifier list; at most one state-changing request per identifier (one reset request, one reveal); global cap 10 identifiers per run; no credential submission; differential results recorded in the audit log; at-least-daily cadence per identifier.",
	},
	FeaturePeopleSearch: {
		Feature:    FeaturePeopleSearch,
		Name:       "People-search and background-check aggregation",
		Summary:    "Lookup of personal records (people finders, voter records, contact aggregators) by name, email or phone.",
		Flag:       "--live people-search",
		Conditions: "explicit subject consent flag (--consent) required at run time; read-only GETs to whitelisted sources; results cached and redacted (full names hashed in the audit log); no PII written to stdout unredacted without -verbose; data-minimization: one query per run per source.",
	},
	FeatureAuthenticatedScrape: {
		Feature:    FeatureAuthenticatedScrape,
		Name:       "Authenticated platform scraping and contact harvesting",
		Summary:    "Harvesting of contacts, emails and phone numbers from platforms using a user-supplied session credential.",
		Flag:       "--live authenticated-scrape",
		Conditions: "user-supplied credential held only in memory or an env var (never argv, never the audit log); read-only API/page access, no posts or profile edits; per-platform rate limit (default 1 req/5s); harvested PII written to a redacted report by default; session discarded at run end.",
	},
}

// Enabled reports whether feature is in the enabled set.
func Enabled(enabled []string, feature string) bool {
	for _, f := range enabled {
		if f == feature {
			return true
		}
	}
	return false
}

// Valid reports whether feature is a registered live feature.
func Valid(feature string) bool {
	_, ok := Exceptions[feature]
	return ok
}

// Parse splits a comma-separated --live value into a normalized feature set,
// rejecting unknown features. An empty input yields an empty set.
func Parse(spec string) ([]string, error) {
	if spec == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range splitCSV(spec) {
		f := raw
		if !Valid(f) {
			return nil, fmt.Errorf("unknown live feature %q (valid: %s)", f, joinCSV(AllFeatures))
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// splitCSV splits s on commas and trims surrounding whitespace, dropping
// empty parts.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// joinCSV joins parts with ", ".
func joinCSV(parts []string) string {
	return strings.Join(parts, ", ")
}

// Summary returns a human-readable table of all exceptions and which are
// enabled for this run. Used by CLIs to print the gate state at start.
func Summary(enabled []string) string {
	var b strings.Builder
	b.WriteString("Live-gate policy exceptions (default OFF; CI runs mock-only):\n")
	for _, f := range AllFeatures {
		e := Exceptions[f]
		state := "off"
		if Enabled(enabled, f) {
			state = "ON"
		}
		fmt.Fprintf(&b, "  [%s] %-22s %s (%s)\n", state, f, e.Summary, e.Conditions)
	}
	return b.String()
}
