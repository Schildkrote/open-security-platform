// Package auditlog implements the platform/audit hash-chain algorithm for
// attack-path's live enrichment events.
package auditlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordChainsAndWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	first, err := l.Record("active-scanning:ON", "shodan", "port:443", 3, "2026-10-07T00:00:00Z")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	second, err := l.Record("active-scanning:ON", "shodan", "product:nginx", 2, "2026-10-07T00:00:01Z")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if second.PrevHash != first.Hash {
		t.Fatalf("chain broken: second.PrevHash %q != first.Hash %q", second.PrevHash, first.Hash)
	}
	if !l.Verify() {
		t.Fatal("verify failed on intact chain")
	}
	if l.Len() != 2 {
		t.Fatalf("len = %d, want 2", l.Len())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.TrimRight(string(data), "\n")
	if got := strings.Count(lines, "\n") + 1; got != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d", got)
	}
	// No key material ever lands in the log.
	if strings.Contains(lines, "SHODAN") || strings.Contains(lines, "apikey") {
		t.Fatal("key material leaked into audit log")
	}
}

func TestEmptyPathIsInMemoryOnly(t *testing.T) {
	l, err := Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := l.Record("off", "mock", "port:22", 1, "t"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if l.Len() != 1 || !l.Verify() {
		t.Fatal("in-memory chain should record and verify with no sink")
	}
}

func TestTamperDetected(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := l.Record("off", "mock", "d", 1, "t1"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := l.Record("off", "mock", "d", 2, "t2"); err != nil {
		t.Fatalf("record: %v", err)
	}
	l.mu.Lock()
	// Flip a byte of stored content for record 0.
	l.content[0][10] ^= 0xff
	l.mu.Unlock()
	if l.Verify() {
		t.Fatal("verify should fail after tampering")
	}
}

func TestBadPathErrors(t *testing.T) {
	if _, err := Open(filepath.Join(string([]byte{0}), "x")); err == nil {
		// os.OpenFile with a NUL byte fails on most platforms; tolerate success
		// only where the OS allows it.
		t.Skip("platform accepted NUL path")
	}
}
