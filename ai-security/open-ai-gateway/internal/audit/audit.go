// Package audit writes tamper-evident JSONL audit records.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
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

// Logger appends hash-chained events to a writer.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	prevHash string
}

// New creates a logger writing to w.
func New(w io.Writer) *Logger {
	return &Logger{w: w, prevHash: "genesis"}
}

// OpenFile opens (creating) an append-only audit file.
func OpenFile(path string) (*Logger, *os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return New(f), f, nil
}

// Log serializes the event, chains its hash, and writes one JSON line.
func (l *Logger) Log(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	e.PrevHash = l.prevHash
	e.Hash = hashEvent(e)
	l.prevHash = e.Hash
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = l.w.Write(append(b, '\n'))
	return err
}

func hashEvent(e Event) string {
	// Hash over the canonical content excluding the hash field itself.
	tmp := e
	tmp.Hash = ""
	b, _ := json.Marshal(tmp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
