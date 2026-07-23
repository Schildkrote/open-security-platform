// Package audit writes a tamper-evident, hash-chained audit trail.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Event struct {
	Time     string `json:"time"`
	Actor    string `json:"actor,omitempty"`
	Action   string `json:"action"`
	Target   string `json:"target,omitempty"`
	Detail   string `json:"detail,omitempty"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	prevHash string
	history  []Event
}

func New(w io.Writer) *Logger {
	return &Logger{w: w, prevHash: "genesis"}
}

func (l *Logger) Log(actor, action, target, detail string) Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Event{
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Actor:    actor,
		Action:   action,
		Target:   target,
		Detail:   detail,
		PrevHash: l.prevHash,
	}
	e.Hash = hash(e)
	l.prevHash = e.Hash
	l.history = append(l.history, e)
	if l.w != nil {
		b, _ := json.Marshal(e)
		_, _ = l.w.Write(append(b, '\n'))
	}
	return e
}

// Verify re-walks the in-memory chain.
func (l *Logger) Verify() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := "genesis"
	for _, e := range l.history {
		if e.PrevHash != prev || e.Hash != hash(e) {
			return false
		}
		prev = e.Hash
	}
	return true
}

func (l *Logger) History() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.history...)
}

func hash(e Event) string {
	tmp := e
	tmp.Hash = ""
	b, _ := json.Marshal(tmp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
