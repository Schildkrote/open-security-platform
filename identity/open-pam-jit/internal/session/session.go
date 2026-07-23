// Package session records privileged sessions as a hash-chained transcript.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

type Entry struct {
	Time     string `json:"time"`
	Type     string `json:"type"` // "start" | "command" | "output" | "end"
	Data     string `json:"data"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Session is an in-progress recorded session.
type Session struct {
	mu       sync.Mutex
	ID       string
	User     string
	Target   string
	Entries  []Entry
	prevHash string
	closed   bool
}

func Start(id, user, target string) *Session {
	s := &Session{ID: id, User: user, Target: target, prevHash: "genesis"}
	s.record("start", "session opened")
	return s
}

// Record appends a command/output event to the transcript.
func (s *Session) Record(typ, data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.record(typ, data)
}

func (s *Session) End() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.record("end", "session closed")
	s.closed = true
}

func (s *Session) record(typ, data string) {
	e := Entry{
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Type:     typ,
		Data:     data,
		PrevHash: s.prevHash,
	}
	e.Hash = hashEntry(e)
	s.prevHash = e.Hash
	s.Entries = append(s.Entries, e)
}

// Verify checks the transcript integrity.
func (s *Session) Verify() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := "genesis"
	for _, e := range s.Entries {
		if e.PrevHash != prev || e.Hash != hashEntry(e) {
			return false
		}
		prev = e.Hash
	}
	return true
}

// Transcript renders the session as JSON lines.
func (s *Session) Transcript() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out string
	for _, e := range s.Entries {
		b, _ := json.Marshal(e)
		out += string(b) + "\n"
	}
	return out
}

func hashEntry(e Entry) string {
	tmp := e
	tmp.Hash = ""
	b, _ := json.Marshal(tmp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
