package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/policy"
)

func mkUp(t *testing.T, received *string) *httptest.Server {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*received = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(up.Close)
	return up
}

func TestVerifyDenyRuleHoldsForMultimodal(t *testing.T) {
	var received string
	up := mkUp(t, &received)
	rules := []policy.Rule{{Name: "no-secret-word", ContentRe: "FORBIDDEN", Action: policy.Deny, Reason: "blocked"}}
	var buf bytes.Buffer
	gw := newTestGateway(t, rules, &buf)
	gw.UpstreamURL = up.URL

	multi, _ := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []any{
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "say FORBIDDEN now"}}},
	}})
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(multi)))
	t.Logf("MULTIMODAL deny-rule status=%d (want 403); forwarded=%q", rr.Code, received)
	if rr.Code != http.StatusForbidden {
		t.Errorf("BYPASS STILL PRESENT: deny rule not enforced for multimodal content, status=%d", rr.Code)
	}
	if received != "" {
		t.Errorf("content was forwarded upstream despite a deny rule: %s", received)
	}
}

func TestVerifyMultimodalPIIIsRedacted(t *testing.T) {
	var received string
	up := mkUp(t, &received)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	multi, _ := json.Marshal(map[string]any{"model": "gpt-4o", "stream": true, "messages": []any{
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "my email is jane.doe@example.com"},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": "http://x/y.png"}},
		}},
	}})
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(multi)))
	t.Logf("status=%d forwarded=%s", rr.Code, received)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if bytes.Contains([]byte(received), []byte("jane.doe@example.com")) {
		t.Errorf("LEAK STILL PRESENT: PII forwarded upstream unredacted: %s", received)
	}
	if !bytes.Contains([]byte(received), []byte("[REDACTED:EMAIL]")) {
		t.Errorf("redaction marker missing from forwarded body: %s", received)
	}
	// The image part and the stream flag must survive in-place redaction.
	if !bytes.Contains([]byte(received), []byte("image_url")) {
		t.Errorf("image part was destroyed by redaction: %s", received)
	}
	if !bytes.Contains([]byte(received), []byte(`"stream":true`)) {
		t.Errorf("stream parameter was dropped: %s", received)
	}
}

func TestVerifyPIIInEarlierMessageAlsoRedacted(t *testing.T) {
	var received string
	up := mkUp(t, &received)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	body, _ := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []any{
		map[string]any{"role": "user", "content": "earlier turn with jane.doe@example.com"},
		map[string]any{"role": "assistant", "content": "ok"},
		map[string]any{"role": "user", "content": "latest turn, no pii"},
	}})
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)))
	t.Logf("status=%d forwarded=%s", rr.Code, received)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if bytes.Contains([]byte(received), []byte("jane.doe@example.com")) {
		t.Errorf("LEAK: PII in an EARLIER message was not redacted (old flatten-into-last-message approach only rewrote one message): %s", received)
	}
	if !bytes.Contains([]byte(received), []byte("latest turn, no pii")) {
		t.Errorf("the later message was clobbered: %s", received)
	}
}

func TestVerifyUnsupportedContentShapeFailsClosed(t *testing.T) {
	var received string
	up := mkUp(t, &received)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	for _, tc := range []struct {
		name string
		body any
	}{
		{"content is a number", map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": 42}}}},
		{"content is an object", map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": map[string]any{"x": 1}}}}},
		{"message is a string", map[string]any{"model": "m", "messages": []any{"just a string"}}},
		{"part text is a number", map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": 7}}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received = ""
			raw, _ := json.Marshal(tc.body)
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw)))
			t.Logf("status=%d forwarded=%q", rr.Code, received)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected fail-closed 400 for an uninspectable content shape, got %d", rr.Code)
			}
			if received != "" {
				t.Errorf("SECURITY: uninspected content was forwarded upstream: %s", received)
			}
		})
	}
}

func TestVerifyNonObjectBodyFailsClosed(t *testing.T) {
	var received string
	up := mkUp(t, &received)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	for name, raw := range map[string]string{
		"null":          "null",
		"array":         `[{"role":"user","content":"jane.doe@example.com"}]`,
		"malformed":     `{"model":`,
		"string scalar": `"hello"`,
	} {
		t.Run(name, func(t *testing.T) {
			received = ""
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(raw))))
			t.Logf("status=%d forwarded=%q", rr.Code, received)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
			if received != "" {
				t.Errorf("SECURITY: non-object body forwarded upstream uninspected: %s", received)
			}
		})
	}
}

func TestVerifyNullContentStillAllowed(t *testing.T) {
	// Tool-call turns legitimately carry content:null; failing closed there
	// would break real clients, so it must be permitted and forwarded.
	var received string
	up := mkUp(t, &received)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	body, _ := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []any{
		map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{
			map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "f", "arguments": "{}"}},
		}},
	}})
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)))
	t.Logf("status=%d forwarded=%s", rr.Code, received)
	if rr.Code != http.StatusOK {
		t.Errorf("content:null (tool-call turn) must be allowed, got %d", rr.Code)
	}
	if !bytes.Contains([]byte(received), []byte("tool_calls")) {
		t.Errorf("tool_calls field was dropped: %s", received)
	}
}
