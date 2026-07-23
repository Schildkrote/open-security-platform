package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rec is a minimal chainable record mirroring the shape components use.
type rec struct {
	Time     string `json:"time"`
	Actor    string `json:"actor,omitempty"`
	Action   string `json:"action"`
	Detail   string `json:"detail,omitempty"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

func TestAppendChainsAndWrites(t *testing.T) {
	var buf bytes.Buffer
	c := New(&buf)

	r1 := rec{Time: "t1", Action: "allow"}
	if err := c.Append(&r1); err != nil {
		t.Fatalf("append r1: %v", err)
	}
	if r1.PrevHash != genesis {
		t.Errorf("first record prev_hash = %q, want %q", r1.PrevHash, genesis)
	}
	if r1.Hash == "" {
		t.Error("first record hash not set")
	}

	r2 := rec{Time: "t2", Action: "deny"}
	if err := c.Append(&r2); err != nil {
		t.Fatalf("append r2: %v", err)
	}
	if r2.PrevHash != r1.Hash {
		t.Errorf("r2 prev_hash = %q, want r1 hash %q", r2.PrevHash, r1.Hash)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d: %q", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], `"action":"allow"`) {
		t.Errorf("line 0 missing action: %s", lines[0])
	}
}

func TestVerifyEmptyAndValid(t *testing.T) {
	c := New(nil)
	if !c.Verify() {
		t.Error("empty chain should verify")
	}
	for i := 0; i < 5; i++ {
		if err := c.Append(&rec{Action: "x"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if !c.Verify() {
		t.Error("intact chain should verify")
	}
	if c.Len() != 5 {
		t.Errorf("Len = %d, want 5", c.Len())
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	c := New(nil)
	for i := 0; i < 3; i++ {
		if err := c.Append(&rec{Action: "x"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if !c.Tamper(1) {
		t.Fatal("Tamper(1) returned false")
	}
	if c.Verify() {
		t.Error("tampered chain must not verify")
	}
}

func TestAppendRejectsBadRecords(t *testing.T) {
	c := New(nil)
	if err := c.Append((*rec)(nil)); err == nil {
		t.Error("nil pointer should error")
	}
	if err := c.Append("not a struct"); err == nil {
		t.Error("non-struct should error")
	}
	// Value (not pointer) is not settable.
	if err := c.Append(rec{Action: "x"}); err == nil {
		t.Error("non-pointer struct should error")
	}
	// Struct without PrevHash/Hash fields.
	type noChain struct{ A string }
	if err := c.Append(&noChain{A: "x"}); err == nil {
		t.Error("struct without chain fields should error")
	}
}

func TestOpenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	c, f, err := OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := c.Append(&rec{Action: "boot"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got rec
	if err := json.Unmarshal(bytes.TrimSpace(b), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Action != "boot" || got.Hash == "" || got.PrevHash != genesis {
		t.Errorf("unexpected persisted record: %+v", got)
	}
}
