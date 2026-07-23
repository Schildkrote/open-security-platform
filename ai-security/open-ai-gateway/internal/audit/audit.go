// Package audit writes tamper-evident JSONL audit records for open-ai-gateway.
// The chaining/hashing/serialization engine is shared via platform/audit; this
// package supplies the gateway-specific record type and Log/OpenFile API.
package audit

import (
	"io"
	"os"
	"time"

	platformaudit "github.com/Schildkrote/platform/audit"
)

// Event is a single audited gateway decision.
type Event struct {
	Time       string         `json:"time"`
	APIKey     string         `json:"api_key,omitempty"`
	Model      string         `json:"model,omitempty"`
	Action     string         `json:"action"`
	Rule       string         `json:"rule,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Redactions []string       `json:"redactions,omitempty"`
	Tokens     int64          `json:"tokens,omitempty"`
	Meta       map[string]any `json:"meta,omitempty"`
	PrevHash   string         `json:"prev_hash"`
	Hash       string         `json:"hash"`
}

// Logger appends hash-chained events using the shared chain engine.
type Logger struct {
	chain *platformaudit.Chain
}

// New creates a logger writing to w.
func New(w io.Writer) *Logger {
	return &Logger{chain: platformaudit.New(w)}
}

// OpenFile opens (creating) an append-only audit file.
func OpenFile(path string) (*Logger, *os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return New(f), f, nil
}

// Log chains the event's hash and writes one JSON line.
func (l *Logger) Log(e Event) error {
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return l.chain.Append(&e)
}

// Verify re-walks the chain and reports whether it is intact.
func (l *Logger) Verify() bool {
	return l.chain.Verify()
}
