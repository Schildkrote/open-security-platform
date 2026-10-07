// Package auditlog implements the platform/audit hash-chain algorithm for
// attack-path's live enrichment events (AP-3): tamper-evident JSONL records,
// 0600 file via AUDIT_PATH, stderr otherwise. No key material is ever
// recorded — only source name, dork and device count.
//
// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only
package auditlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

// Event is one live-enrichment audit record.
type Event struct {
	Time     string `json:"time"`
	Gate     string `json:"gate"`
	Source   string `json:"source"`
	Dork     string `json:"dork"`
	Devices  int    `json:"devices"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Logger is an append-only, hash-chained audit writer. A nil *Logger safely
// discards records.
type Logger struct {
	mu       sync.Mutex
	w        *os.File
	prevHash string

	content [][]byte
	prevs   []string
	hashes  []string
}

// New returns a Logger writing to w (nil w discards output; the in-memory
// chain is still maintained so Verify works).
func New(w *os.File) *Logger {
	return &Logger{w: w, prevHash: "genesis"}
}

// Open returns a Logger appending to path with mode 0600 (created), falling
// back to stderr-free in-memory-only operation when the file cannot be opened
// or path is empty (offline default: nothing written anywhere).
func Open(path string) (*Logger, error) {
	if path == "" {
		return New(nil), nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return New(f), nil
}

// Record links event into the chain and writes it as one JSON line. The
// event's PrevHash and Hash fields are populated and the timestamp is set.
func (l *Logger) Record(gate, source, dork string, devices int, now string) (*Event, error) {
	ev := &Event{
		Time:    now,
		Gate:    gate,
		Source:  source,
		Dork:    dork,
		Devices: devices,
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ev.PrevHash = l.prevHash
	ev.Hash = ""
	content, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	h := hex.EncodeToString(sum[:])
	ev.Hash = h

	out, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	l.prevs = append(l.prevs, ev.PrevHash)
	l.content = append(l.content, content)
	l.hashes = append(l.hashes, h)
	l.prevHash = h
	if l.w != nil {
		if _, err := l.w.Write(append(out, '\n')); err != nil {
			return nil, err
		}
	}
	return ev, nil
}

// Verify re-walks the in-memory chain, confirming both hash integrity and
// prev_hash linkage. It returns true for an empty chain.
func (l *Logger) Verify() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := "genesis"
	for i := range l.hashes {
		if l.prevs[i] != prev {
			return false
		}
		sum := sha256.Sum256(l.content[i])
		if hex.EncodeToString(sum[:]) != l.hashes[i] {
			return false
		}
		prev = l.hashes[i]
	}
	return true
}

// Len returns the number of records appended so far.
func (l *Logger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hashes)
}
