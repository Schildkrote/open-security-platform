// Package audit provides a shared tamper-evident, hash-chained audit trail
// used across open-security-platform components.
//
// A Chain links arbitrary JSON-serializable record structs into an append-only
// sequence. Each record must be a struct (passed by pointer) with two string
// fields named "PrevHash" and "Hash". Append sets PrevHash to the previous
// record's hash, computes Hash = sha256 over the record's canonical JSON with
// the Hash field zeroed, and writes one JSON object per line. Verify re-walks
// the in-memory chain to detect any tampering or reordering.
//
// Components keep their own domain-specific record types (and JSON shapes);
// this package supplies only the chaining, hashing, serialization and
// verification engine so that logic is not duplicated per component.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
)

// genesis is the prev_hash seeded into the first record of a chain.
const genesis = "genesis"

// Chain is an append-only, hash-chained audit writer. The zero value is not
// usable; construct with New or OpenFile.
type Chain struct {
	mu       sync.Mutex
	w        io.Writer
	prevHash string

	// Per-record state retained so Verify can re-walk the chain without
	// re-reading the sink. content[i] is the canonical JSON of record i with
	// its Hash field zeroed; prevs[i] is the prev_hash embedded in record i;
	// hashes[i] is record i's computed hash.
	content [][]byte
	prevs   []string
	hashes  []string
}

// New returns a Chain that writes JSONL to w. A nil w discards output; the
// in-memory chain is still maintained so Verify works.
func New(w io.Writer) *Chain {
	return &Chain{w: w, prevHash: genesis}
}

// OpenFile opens (creating) an append-only audit file with mode 0600 and
// returns a Chain writing to it plus the file handle, which the caller closes.
func OpenFile(path string) (*Chain, *os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return New(f), f, nil
}

// Append links record into the chain and writes it as one JSON line. record
// must be a non-nil pointer to a struct with settable string fields PrevHash
// and Hash. On success the record's PrevHash and Hash fields are populated.
func (c *Chain) Append(record any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	v := reflect.ValueOf(record)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return fmt.Errorf("audit: nil record pointer")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("audit: record must be a struct, got %s", v.Kind())
	}
	prevF := v.FieldByName("PrevHash")
	hashF := v.FieldByName("Hash")
	if !prevF.IsValid() || !hashF.IsValid() ||
		prevF.Kind() != reflect.String || hashF.Kind() != reflect.String ||
		!prevF.CanSet() || !hashF.CanSet() {
		return fmt.Errorf("audit: record must have settable string fields PrevHash and Hash")
	}

	prevF.SetString(c.prevHash)
	hashF.SetString("")

	content, err := json.Marshal(v.Interface())
	if err != nil {
		return fmt.Errorf("audit: marshal record: %w", err)
	}
	h := sha256hex(content)
	hashF.SetString(h)

	out, err := json.Marshal(v.Interface())
	if err != nil {
		return fmt.Errorf("audit: marshal record: %w", err)
	}

	c.prevs = append(c.prevs, c.prevHash)
	c.content = append(c.content, content)
	c.hashes = append(c.hashes, h)
	c.prevHash = h

	if c.w != nil {
		if _, err := c.w.Write(append(out, '\n')); err != nil {
			return fmt.Errorf("audit: write: %w", err)
		}
	}
	return nil
}

// Verify re-walks the in-memory chain, confirming both hash integrity and
// prev_hash linkage. It returns true for an empty chain.
func (c *Chain) Verify() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev := genesis
	for i := range c.hashes {
		if c.prevs[i] != prev {
			return false
		}
		if sha256hex(c.content[i]) != c.hashes[i] {
			return false
		}
		prev = c.hashes[i]
	}
	return true
}

// Len returns the number of records appended so far.
func (c *Chain) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hashes)
}

// Tamper corrupts the stored content of the record at index i (for tests and
// tamper-detection demonstrations). It returns false if i is out of range.
func (c *Chain) Tamper(i int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i < 0 || i >= len(c.content) {
		return false
	}
	c.content[i] = append(append([]byte{}, c.content[i]...), 'x')
	return true
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
