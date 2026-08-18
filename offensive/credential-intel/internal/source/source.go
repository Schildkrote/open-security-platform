// Package source defines the credential-intel connector interface and its
// implementations.
//
// A Source answers breach / credential-recovery questions about a
// normalized identifier (email address or SHA-1 password hash). The mock
// source is fully offline (bundled sample data) and is used by tests and CI;
// the HIBP source is the real connector (PwnedPasswords k-anonymity API).
package source

import "context"

// Breach is one breach record affecting an identifier.
type Breach struct {
	Title    string `json:"title"`
	Name     string `json:"name"`
	Year     int    `json:"year"`
	DataType string `json:"data_type"` // e.g. "Email addresses", "Password hashes"
	Logo     string `json:"logo"`
}

// Answer is the result of one lookup.
type Answer struct {
	IdentifierHash string   `json:"identifier_sha1"` // redacted: SHA-1 of the input
	Source         string   `json:"source"`
	Pwned          bool     `json:"pwned"`
	Count          int      `json:"count"` // occurrences across breaches (k-anon: 0 means <1000)
	Breaches       []Breach `json:"breaches"`
	Uncertain      bool     `json:"uncertain"`
	LatencyMS      int64    `json:"latency_ms"`
}

// Source is the connector interface for breach-lookup backends.
type Source interface {
	// Name identifies the implementation ("mock" or "hibp").
	Name() string
	// Pwned asks whether an identifier appears in known breaches.
	Pwned(ctx context.Context, identifier string) (Answer, error)
}
