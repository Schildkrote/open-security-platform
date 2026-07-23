package events

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestEmitChainsAndDelivers(t *testing.T) {
	var mu sync.Mutex
	var received []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev map[string]any
		_ = json.Unmarshal(b, &ev)
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New("open-pam-jit", []string{srv.URL})
	if _, err := e.Emit("access.granted", "approve", "cred-1", map[string]any{"request_id": "r1"}, map[string]any{"approver": "bob"}); err != nil {
		t.Fatalf("emit 1: %v", err)
	}
	if _, err := e.Emit("access.granted", "approve", "cred-2", map[string]any{"request_id": "r2"}, map[string]any{"approver": "bob"}); err != nil {
		t.Fatalf("emit 2: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("expected 2 delivered events, got %d", len(received))
	}
	if received[0]["prev_hash"] != genesis {
		t.Errorf("first prev_hash = %v, want %q", received[0]["prev_hash"], genesis)
	}
	if received[1]["prev_hash"] != received[0]["hash"] {
		t.Errorf("second prev_hash = %v, want first hash %v", received[1]["prev_hash"], received[0]["hash"])
	}
	for i, ev := range received {
		if Digest(ev) != ev["hash"] {
			t.Errorf("event %d: recomputed hash does not match", i)
		}
	}
}

func TestEmitNoopWithoutURLs(t *testing.T) {
	e := New("x", nil)
	if e.Enabled() {
		t.Error("emitter with no URLs should not be enabled")
	}
	ev, err := e.Emit("t", "a", "s", nil, nil)
	if err != nil || ev != nil {
		t.Errorf("expected (nil, nil) with no URLs, got (%v, %v)", ev, err)
	}
}
