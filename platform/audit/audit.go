// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package audit provides a hash-chained log of policy decisions and actions.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is one append-only record.
type Entry struct {
	Seq      uint64         `json:"seq"`
	TS       time.Time      `json:"ts"`
	Kind     string         `json:"kind"` // policy|action|read|ingest
	Actor    string         `json:"actor"`
	Purpose  string         `json:"purpose,omitempty"`
	ObjectID string         `json:"object_id,omitempty"`
	Action   string         `json:"action,omitempty"`
	Outcome  string         `json:"outcome,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// Log is an in-memory hash chain.
type Log struct {
	mu      sync.Mutex
	entries []Entry
}

// New returns an empty log.
func New() *Log { return &Log{} }

// Append adds an entry and returns it with hash filled.
func (l *Log) Append(e Entry) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = uint64(len(l.entries) + 1)
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if len(l.entries) > 0 {
		e.PrevHash = l.entries[len(l.entries)-1].Hash
	} else {
		e.PrevHash = "genesis"
	}
	e.Hash = hashEntry(e)
	l.entries = append(l.entries, e)
	return e
}

func hashEntry(e Entry) string {
	// hash without Hash field
	payload := struct {
		Seq      uint64         `json:"seq"`
		TS       time.Time      `json:"ts"`
		Kind     string         `json:"kind"`
		Actor    string         `json:"actor"`
		Purpose  string         `json:"purpose"`
		ObjectID string         `json:"object_id"`
		Action   string         `json:"action"`
		Outcome  string         `json:"outcome"`
		Detail   map[string]any `json:"detail"`
		PrevHash string         `json:"prev_hash"`
	}{e.Seq, e.TS, e.Kind, e.Actor, e.Purpose, e.ObjectID, e.Action, e.Outcome, e.Detail, e.PrevHash}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Verify walks the chain.
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := "genesis"
	for i, e := range l.entries {
		if e.PrevHash != prev {
			return fmt.Errorf("entry %d: prev hash mismatch", i+1)
		}
		if hashEntry(e) != e.Hash {
			return fmt.Errorf("entry %d: content hash mismatch", i+1)
		}
		prev = e.Hash
	}
	return nil
}

// Entries returns a copy.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// SaveJSON writes the chain.
func (l *Log) SaveJSON(path string) error {
	b, err := json.MarshalIndent(l.Entries(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
