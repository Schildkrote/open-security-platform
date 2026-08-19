// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package audit is a hash-chained, tamper-evident biometric audit log.
// Every face-touching operation writes an Entry carrying the lawful-basis
// decision, retention expiry, and redaction status.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Schildkrote/lawful-basis"
)

// Entry is one audit record.
type Entry struct {
	Seq           uint64         `json:"seq"`
	Timestamp     time.Time      `json:"timestamp"`
	Action        string         `json:"action"`
	SubjectPseudo string         `json:"subject_pseudo"` // hash, never the name
	Component     string         `json:"component"`
	Basis         basis.Decision `json:"basis"`
	RetentionExp  time.Time      `json:"retention_expires"`
	Redacted      bool           `json:"redacted"`
	Detail        string         `json:"detail,omitempty"`
	PrevHash      string         `json:"prev_hash"`
	Hash          string         `json:"hash"`
}

// Store is the audit log interface.
type Store interface {
	Append(e Entry) (Entry, error)
	All() []Entry
	Verify() error
	Len() int
}

// Memory is an in-memory hash-chained store (offline, CI-safe).
type Memory struct {
	mu      sync.Mutex
	entries []Entry
	last    string
}

// NewMemory returns an empty Memory store.
func NewMemory() *Memory { return &Memory{} }

// Append adds e to the chain, filling Seq/Timestamp/PrevHash/Hash.
func (m *Memory) Append(e Entry) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.RetentionExp.IsZero() && e.Basis.RetentionMax > 0 {
		e.RetentionExp = e.Timestamp.Add(time.Duration(e.Basis.RetentionMax) * 24 * time.Hour)
	}
	e.Seq = uint64(len(m.entries) + 1)
	e.PrevHash = m.last
	e.Hash = hashEntry(e)
	m.entries = append(m.entries, e)
	m.last = e.Hash
	return e, nil
}

// All returns a copy of the chain.
func (m *Memory) All() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entry, len(m.entries))
	copy(out, m.entries)
	return out
}

// Len returns the number of entries.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// Verify walks the chain and returns an error on the first break.
func (m *Memory) Verify() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := ""
	for i, e := range m.entries {
		if e.PrevHash != prev {
			return fmt.Errorf("chain break at seq %d: prev_hash mismatch", e.Seq)
		}
		want := hashEntry(e)
		if e.Hash != want {
			return fmt.Errorf("chain break at seq %d: content hash mismatch", e.Seq)
		}
		if uint64(i+1) != e.Seq {
			return fmt.Errorf("chain break at index %d: seq %d expected %d", i, e.Seq, i+1)
		}
		prev = e.Hash
	}
	return nil
}

// Record is a convenience: build an Entry from action + basis and append.
func Record(s Store, component, action, subjectPseudo, detail string, d basis.Decision, redacted bool) (Entry, error) {
	return s.Append(Entry{
		Action:        action,
		SubjectPseudo: subjectPseudo,
		Component:     component,
		Basis:         d,
		Redacted:      redacted,
		Detail:        detail,
	})
}

// Pseudo returns a stable SHA-256 hex of s (used for subject pseudonyms).
func Pseudo(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// hashEntry hashes the entry fields excluding Hash itself.
func hashEntry(e Entry) string {
	payload := struct {
		Seq           uint64         `json:"seq"`
		Timestamp     time.Time      `json:"timestamp"`
		Action        string         `json:"action"`
		SubjectPseudo string         `json:"subject_pseudo"`
		Component     string         `json:"component"`
		Basis         basis.Decision `json:"basis"`
		RetentionExp  time.Time      `json:"retention_expires"`
		Redacted      bool           `json:"redacted"`
		Detail        string         `json:"detail"`
		PrevHash      string         `json:"prev_hash"`
	}{
		Seq: e.Seq, Timestamp: e.Timestamp, Action: e.Action,
		SubjectPseudo: e.SubjectPseudo, Component: e.Component,
		Basis: e.Basis, RetentionExp: e.RetentionExp,
		Redacted: e.Redacted, Detail: e.Detail, PrevHash: e.PrevHash,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
