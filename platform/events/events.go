// Package events provides a shared cross-component integration-event emitter
// for the Go components of open-security-platform. Events conform to
// platform/schemas/integration_event.schema.json and are hash-chained with the
// same tamper-evident algorithm as platform/audit (sha256 over the canonical
// JSON of the event with its hash field zeroed; prev_hash seeded at "genesis").
//
// Emission is opt-in (no URLs => no-op) and best-effort: a missing or failing
// subscriber never returns an error to the caller, so a down subscriber cannot
// break the producing component.
package events

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

const genesis = "genesis"

// Emitter publishes hash-chained integration events to subscriber webhooks.
type Emitter struct {
	mu     sync.Mutex
	source string
	urls   []string
	prev   string
	client *http.Client
}

// New returns an Emitter for the named source component. An empty urls slice
// disables emission (offline behaviour is unchanged).
func New(source string, urls []string) *Emitter {
	return &Emitter{
		source: source,
		urls:   urls,
		prev:   genesis,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether the emitter has any subscribers.
func (e *Emitter) Enabled() bool { return len(e.urls) > 0 }

// Emit builds, chains and POSTs an integration event to every subscriber, and
// returns the emitted event (nil when there are no subscribers). Errors
// delivering to subscribers are swallowed (best-effort).
func (e *Emitter) Emit(typ, action, subject string, refs, data map[string]any) (map[string]any, error) {
	if !e.Enabled() {
		return nil, nil
	}
	if refs == nil {
		refs = map[string]any{}
	}
	if data == nil {
		data = map[string]any{}
	}
	e.mu.Lock()
	ev := map[string]any{
		"id":        newID(),
		"time":      time.Now().UTC().Format(time.RFC3339Nano),
		"type":      typ,
		"source":    e.source,
		"action":    action,
		"subject":   subject,
		"refs":      refs,
		"data":      data,
		"prev_hash": e.prev,
		"hash":      "",
	}
	ev["hash"] = Digest(ev)
	e.prev, _ = ev["hash"].(string)
	e.mu.Unlock()

	payload, err := marshalCanonical(ev)
	if err != nil {
		return ev, err
	}
	for _, url := range e.urls {
		if resp, err := e.client.Post(url, "application/json", bytes.NewReader(payload)); err == nil {
			_ = resp.Body.Close()
		}
	}
	return ev, nil
}

// Digest computes the event hash: sha256 over the canonical (sorted-key,
// non-HTML-escaped) JSON of the event with its hash field zeroed. This matches
// the Python/Node emitters for ASCII payloads, so chains verify across languages.
func Digest(event map[string]any) string {
	tmp := make(map[string]any, len(event))
	for k, v := range event {
		tmp[k] = v
	}
	tmp["hash"] = ""
	b, _ := marshalCanonical(tmp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// marshalCanonical encodes v as JSON with sorted keys (maps) and no HTML
// escaping, mirroring Python's json.dumps(sort_keys=True).
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
