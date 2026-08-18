// Package source defines the username-enum connector interface and its
// implementations.
//
// A Source answers "does service S have an account for username U?" The
// mock source is fully offline (deterministic fake hit set) and is used by
// tests and CI; the real source performs read-only HTTP probes against
// in-scope services and is only reachable with an explicit scope list.
package source

import "context"

// Result is the answer to one username probe against one service.
type Result struct {
	Service   string `json:"service"`    // service name (e.g. "github")
	URL       string `json:"url"`        // probed URL (redacted for mock)
	Found     bool   `json:"found"`      // account exists (true/false/uncertain)
	Uncertain bool   `json:"uncertain"`  // inconclusive (rate limit, no differential)
	LatencyMS int64  `json:"latency_ms"` // wall time of the probe
}

// Source is the connector interface for username enumeration backends.
type Source interface {
	// Name identifies the source implementation ("mock" or "http").
	Name() string
	// Probe reports whether username exists on service, probed via url.
	Probe(ctx context.Context, service, url, username string) (Result, error)
}
