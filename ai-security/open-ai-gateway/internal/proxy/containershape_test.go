package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/policy"
)

// ---------------------------------------------------------------------------
// BL-5: the "messages" CONTAINER in a non-array shape used to be forwarded
// upstream verbatim. extractContent failed its []any assertion and reported
// "no content" instead of "content I could not read", so policy matched nothing,
// redaction rewrote nothing, and the request still went out with status 200.
// ---------------------------------------------------------------------------

func TestMessagesContainerObjectFailsClosed(t *testing.T) {
	var received string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, okJSONResponse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	raw, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": map[string]any{"role": "user", "content": "my email is jane.doe@example.com"},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)

	t.Logf("status=%d forwarded=%q", rr.Code, received)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("a non-array messages container must fail closed with 400, got %d", rr.Code)
	}
	if received != "" {
		t.Errorf("BYPASS: uninspected content was forwarded upstream: %s", received)
	}
	if strings.Contains(received, "jane.doe@example.com") {
		t.Errorf("LEAK: PII reached upstream inside a non-array messages container: %s", received)
	}
}

func TestMessagesContainerStringFailsClosed(t *testing.T) {
	var received string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, okJSONResponse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	raw, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": "my email is jane.doe@example.com",
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)

	t.Logf("status=%d forwarded=%q", rr.Code, received)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("a string messages container must fail closed with 400, got %d", rr.Code)
	}
	if received != "" {
		t.Errorf("BYPASS: uninspected content was forwarded upstream: %s", received)
	}
}

func TestMessagesContainerOtherShapesFailClosed(t *testing.T) {
	var received string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, okJSONResponse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	for _, tc := range []struct {
		name string
		val  any
	}{
		{"number", 42},
		{"bool", true},
		{"array of strings", []any{"jane.doe@example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received = ""
			raw, _ := json.Marshal(map[string]any{"model": "m", "messages": tc.val})
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
			req.Header.Set("X-API-Key", "test-key")
			gw.ServeHTTP(rr, req)
			t.Logf("status=%d forwarded=%q", rr.Code, received)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected fail-closed 400, got %d", rr.Code)
			}
			if received != "" {
				t.Errorf("uninspected content was forwarded upstream: %s", received)
			}
		})
	}
}

// The complement: "messages" absent or explicitly null is legitimate (embeddings
// style bodies) and must NOT be refused. Without this the fail-closed rule would
// break clients that post no messages at all.
func TestMessagesAbsentOrNullIsAllowed(t *testing.T) {
	var received string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, okJSONResponse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"absent", map[string]any{"model": "text-embedding-3-small", "input": "hello"}},
		{"explicit null", map[string]any{"model": "m", "messages": nil}},
		{"empty array", map[string]any{"model": "m", "messages": []any{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received = ""
			raw, _ := json.Marshal(tc.body)
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
			req.Header.Set("X-API-Key", "test-key")
			gw.ServeHTTP(rr, req)
			t.Logf("status=%d forwarded=%s", rr.Code, received)
			if rr.Code != http.StatusOK {
				t.Errorf("a body with no messages must be allowed, got %d", rr.Code)
			}
		})
	}
}

// A deny rule must fire against content carried in a multimodal parts array, not
// just in plain string content - otherwise policy is bypassable by request shape.
func TestDenyRuleFiresForMultimodalParts(t *testing.T) {
	var received string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, okJSONResponse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, denyRuleOn("FORBIDDEN"), &buf)
	gw.UpstreamURL = up.URL

	raw, _ := json.Marshal(map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "text", "text": "please say FORBIDDEN"},
			}},
		},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)

	t.Logf("status=%d forwarded=%q", rr.Code, received)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("BYPASS: deny rule did not fire for multimodal parts, got %d", rr.Code)
	}
	if received != "" {
		t.Errorf("denied content was forwarded upstream: %s", received)
	}
}

// denyRuleOn builds a single policy rule that denies any request whose flattened
// content matches pattern.
func denyRuleOn(pattern string) []policy.Rule {
	return []policy.Rule{{
		Name:      "deny-" + pattern,
		ContentRe: pattern,
		Action:    policy.Deny,
		Reason:    "blocked by test rule",
	}}
}
