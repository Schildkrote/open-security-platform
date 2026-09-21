package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// --- Response field preservation --------------------------------------------
//
// Redaction used to unmarshal the upstream response into a narrow struct
// (choices[].message + usage.total_tokens) and re-marshal THAT, silently
// dropping id, object, model, system_fingerprint, choices[].index,
// choices[].finish_reason and the prompt/completion token breakdown.
// RedactResponse defaults to true, so this was the normal path: any OpenAI-
// compatible client lost fields it depends on (finish_reason for truncation
// detection, model for routing/logging) whenever redaction fired.
//
// A redaction must actually trigger for this to be exercised, so the request
// content carries an email address.

func TestRedactionPreservesAllUpstreamResponseFields(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)

	// Triggers response redaction (mock echoes the user content back).
	rr := post(t, gw, "gpt-4o", "contact jane.doe@example.com please")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "[REDACTED:EMAIL]") {
		t.Fatalf("redaction did not fire, so this test would not exercise the rewrite path: %s", rr.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("response body is not valid JSON: %v\nbody=%s", err, rr.Body.String())
	}

	// Every field the mock upstream sends must survive redaction.
	for _, key := range []string{"id", "object", "model", "choices", "usage"} {
		if _, ok := got[key]; !ok {
			t.Errorf("field %q was dropped by redaction; body=%s", key, rr.Body.String())
		}
	}
	if got["id"] != "chatcmpl-mock" {
		t.Errorf("id not preserved: %v", got["id"])
	}
	if got["object"] != "chat.completion" {
		t.Errorf("object not preserved: %v", got["object"])
	}
	if got["model"] != "gpt-4o" {
		t.Errorf("model not preserved: %v", got["model"])
	}

	choices, ok := got["choices"].([]any)
	if !ok || len(choices) == 0 {
		t.Fatalf("choices missing or empty: %v", got["choices"])
	}
	c0, ok := choices[0].(map[string]any)
	if !ok {
		t.Fatalf("choices[0] is not an object: %v", choices[0])
	}
	if c0["index"] == nil {
		t.Errorf("choices[0].index was dropped: %v", c0)
	}
	if c0["finish_reason"] != "stop" {
		t.Errorf("choices[0].finish_reason was dropped (clients use it to detect truncation): %v", c0["finish_reason"])
	}
	// The redacted content must still be in place.
	msg, ok := c0["message"].(map[string]any)
	if !ok {
		t.Fatalf("choices[0].message missing: %v", c0)
	}
	if s, _ := msg["content"].(string); !strings.Contains(s, "[REDACTED:EMAIL]") {
		t.Errorf("redaction was lost while preserving fields: %v", msg["content"])
	}
	if strings.Contains(asString(msg["content"]), "jane.doe@example.com") {
		t.Errorf("PII survived: %v", msg["content"])
	}

	usage, ok := got["usage"].(map[string]any)
	if !ok {
		t.Fatalf("usage missing: %v", got["usage"])
	}
	for _, key := range []string{"prompt_tokens", "completion_tokens", "total_tokens"} {
		if _, present := usage[key]; !present {
			t.Errorf("usage.%s was dropped (billing/observability depends on it): %v", key, usage)
		}
	}
}

// asString renders an any as a string without panicking, for substring checks.
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// --- Content-Length truthfulness --------------------------------------------
//
// The gateway copied the upstream Content-Length header verbatim while writing a
// body that redaction had REWRITTEN to a different length. Clients then aborted
// the transfer as truncated — observed live as curl rc=18 (CURLE_PARTIAL_FILE)
// against a complete JSON body. httptest.ResponseRecorder buffers and never
// enforces the header, so the bug was invisible to every existing test; these
// assert the header directly and also do a real HTTP round-trip.

func TestContentLengthMatchesWrittenBody(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)

	rr := post(t, gw, "gpt-4o", "contact jane.doe@example.com please")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	cl := rr.Header().Get("Content-Length")
	if cl == "" {
		t.Fatal("Content-Length not set on the proxied response")
	}
	declared, err := strconv.Atoi(cl)
	if err != nil {
		t.Fatalf("Content-Length is not an integer: %q", cl)
	}
	actual := rr.Body.Len()
	if declared != actual {
		t.Errorf("SECURITY/CORRECTNESS: Content-Length=%d but body is %d bytes — clients abort this as a truncated transfer (curl rc=18)", declared, actual)
	}
}

func TestRealHTTPRoundTripIsNotTruncated(t *testing.T) {
	// Drive the gateway through a real server + real client so the transport
	// enforces Content-Length, exactly as curl and every SDK do.
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "contact jane.doe@example.com please"}},
	})

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("real POST failed (truncated transfer?): %v", err)
	}
	defer resp.Body.Close()

	// io.ReadAll fails with unexpected EOF if fewer bytes arrive than the
	// Content-Length header promised — the precise live symptom.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body failed, indicating a truncated transfer: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if len(data) == 0 {
		t.Fatal("empty body from a real round-trip")
	}
	// The body must be complete, parseable JSON — truncation would fail here.
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("body is not complete JSON (likely truncated): %v\nbody=%s", err, data)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, _ := strconv.Atoi(cl); n != len(data) {
			t.Errorf("Content-Length=%s but received %d bytes", cl, len(data))
		}
	}
}

// --- Request field preservation ---------------------------------------------
//
// The same narrow-struct bug existed on the request side: RedactRequest also
// defaults to true, and when redaction fired the gateway did
// `body, _ = json.Marshal(req)` from a struct modelling only Model + Messages.
// Every other field the client sent — stream, temperature, top_p, max_tokens,
// tools/tool_choice, response_format, stop, n — was silently dropped before
// forwarding upstream. A streaming client would receive a non-streaming
// response and tool-calling clients would lose their tool schema.

// captureUpstream returns a gateway whose upstream records the exact body it
// received, so we can assert what was actually forwarded.
func captureUpstream(t *testing.T, gw *Gateway) *string {
	t.Helper()
	var received string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL
	return &received
}

func TestRequestRedactionPreservesClientParameters(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	received := captureUpstream(t, gw)

	// A realistic client payload: extra sampling/streaming/tool parameters
	// alongside content that triggers redaction.
	reqBody := map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "email jane.doe@example.com"}},
		"stream":   true,
		// JSON numbers: temperature 0.7, max_tokens 256, top_p 0.9
		"temperature": 0.7,
		"max_tokens":  256,
		"top_p":       0.9,
		"stop":        []string{"\n\n"},
		"n":           1,
		"tools": []map[string]any{{
			"type": "function",
			"function": map[string]any{
				"name":        "lookup",
				"description": "look up a thing",
				"parameters":  map[string]any{"type": "object"},
			},
		}},
		"tool_choice":     "auto",
		"response_format": map[string]any{"type": "json_object"},
	}
	raw, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(*received, "[REDACTED:EMAIL]") {
		t.Fatalf("request redaction did not fire, so the rewrite path was not exercised; upstream got: %s", *received)
	}

	var forwarded map[string]any
	if err := json.Unmarshal([]byte(*received), &forwarded); err != nil {
		t.Fatalf("forwarded body is not valid JSON: %v\nbody=%s", err, *received)
	}

	for _, key := range []string{
		"stream", "temperature", "max_tokens", "top_p", "stop", "n",
		"tools", "tool_choice", "response_format",
	} {
		if _, ok := forwarded[key]; !ok {
			t.Errorf("client parameter %q was silently dropped before forwarding upstream; forwarded=%s", key, *received)
		}
	}
	// stream must still be true, not lost or coerced to false.
	if s, ok := forwarded["stream"].(bool); !ok || !s {
		t.Errorf("stream was lost or changed: %v (a streaming client would get a non-streaming response)", forwarded["stream"])
	}
	// The redacted message content must be in place, and the PII gone.
	msgs, _ := forwarded["messages"].([]any)
	if len(msgs) == 0 {
		t.Fatalf("messages missing after redaction: %s", *received)
	}
	m0, _ := msgs[0].(map[string]any)
	if c, _ := m0["content"].(string); !strings.Contains(c, "[REDACTED:EMAIL]") {
		t.Errorf("redacted content not applied: %v", m0["content"])
	} else if strings.Contains(c, "jane.doe@example.com") {
		t.Errorf("PII was forwarded upstream: %v", c)
	}
}

func TestRequestRedactionTargetsLastUserMessage(t *testing.T) {
	// The map-based rewrite must keep the original selection rule: the LAST
	// message with role "user", not the first message.
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	received := captureUpstream(t, gw)

	raw, _ := json.Marshal(map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "system", "content": "be brief"},
			{"role": "user", "content": "first turn"},
			{"role": "assistant", "content": "ok"},
			{"role": "user", "content": "now email jane.doe@example.com"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var fwd map[string]any
	if err := json.Unmarshal([]byte(*received), &fwd); err != nil {
		t.Fatalf("forwarded body invalid: %v", err)
	}
	msgs, _ := fwd["messages"].([]any)
	if len(msgs) != 4 {
		t.Fatalf("message count changed: %d", len(msgs))
	}
	last, _ := msgs[3].(map[string]any)
	if c, _ := last["content"].(string); !strings.Contains(c, "[REDACTED:EMAIL]") {
		t.Errorf("the last user message was not redacted: %v", last["content"])
	}
	// Earlier messages must be untouched, including the system prompt.
	sys, _ := msgs[0].(map[string]any)
	if sys["content"] != "be brief" {
		t.Errorf("system message was modified: %v", sys["content"])
	}
	first, _ := msgs[1].(map[string]any)
	if first["content"] != "first turn" {
		t.Errorf("an earlier user message was modified: %v", first["content"])
	}
}

// --- Hop-by-hop header hygiene ----------------------------------------------

func TestHopByHopHeadersNotForwarded(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	// An upstream that advertises connection-scoped headers a proxy must not
	// pass through (RFC 9110 §7.6.1).
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("X-Custom-Ok", "keep-me")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"total_tokens":1}}`))
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	// A harmless custom header must survive; hop-by-hop ones must not be copied
	// through by the proxy loop.
	if rr.Header().Get("X-Custom-Ok") != "keep-me" {
		t.Errorf("end-to-end header X-Custom-Ok was wrongly dropped: %v", rr.Header())
	}
	if v := rr.Header().Get("Keep-Alive"); v != "" {
		t.Errorf("hop-by-hop Keep-Alive was forwarded: %q", v)
	}
	// Content-Length must describe OUR body, not the upstream's.
	if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(rr.Body.Len()) {
		t.Errorf("Content-Length=%q does not match body length %d", cl, rr.Body.Len())
	}
}

// --- Malformed upstream response --------------------------------------------

func TestNonJSONUpstreamResponsePassesThrough(t *testing.T) {
	// A gateway must not corrupt or swallow an upstream error page. If the body
	// is not JSON, redaction cannot apply and the original bytes must be served
	// with a truthful Content-Length.
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream exploded"))
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected the upstream 502 to be passed through, got %d", rr.Code)
	}
	if rr.Body.String() != "upstream exploded" {
		t.Errorf("non-JSON body was altered: %q", rr.Body.String())
	}
	if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(rr.Body.Len()) {
		t.Errorf("Content-Length=%q does not match body length %d", cl, rr.Body.Len())
	}
}
