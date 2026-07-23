// Package audit writes a tamper-evident, hash-chained audit trail for
// open-pam-jit. The chaining/hashing/serialization engine is shared via
// platform/audit; this package supplies the PAM-specific record type and an
// ergonomic Log(actor, action, target, detail) API on top of it.
package audit

import (
	"io"
	"sync"
	"time"

	platformaudit "github.com/Schildkrote/platform/audit"
)

// Event is a single PAM/JIT audit record.
type Event struct {
	Time     string `json:"time"`
	Actor    string `json:"actor,omitempty"`
	Action   string `json:"action"`
	Target   string `json:"target,omitempty"`
	Detail   string `json:"detail,omitempty"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Logger appends hash-chained Events using the shared chain engine.
type Logger struct {
	mu      sync.Mutex
	chain   *platformaudit.Chain
	history []Event
}

// New returns a Logger writing JSONL to w (nil discards output).
func New(w io.Writer) *Logger {
	return &Logger{chain: platformaudit.New(w)}
}

// Log records an access event and returns the chained Event.
func (l *Logger) Log(actor, action, target, detail string) Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Event{
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		Actor:  actor,
		Action: action,
		Target: target,
		Detail: detail,
	}
	_ = l.chain.Append(&e) // populates e.PrevHash and e.Hash
	l.history = append(l.history, e)
	return e
}

// Verify re-walks the chain and reports whether it is intact.
func (l *Logger) Verify() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.chain.Verify()
}

// History returns a copy of all recorded events in chain order.
func (l *Logger) History() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.history...)
}
