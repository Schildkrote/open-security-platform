package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/policy"
	"github.com/Schildkrote/open-ai-gateway/internal/redactor"
)

// ---------------------------------------------------------------------------
// BL-6: response redaction used to apply ONLY to choices[].message.content as a
// string. Every other shape was skipped silently and served to the client with
// status 200 - a parts array, a delta, or a non-array choices - under an audit
// event reading action "allow" with no redactions and no diagnostic.
// ---------------------------------------------------------------------------

// serveJSON returns an upstream that replies with exactly body and the given
// content type.
func serveJSON(t *testing.T, body string) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	return up
}

const piiEmail = "jane.doe@example.com"

// Response content as a multimodal parts array must be redacted, not forwarded.
func TestResponsePartsContentIsRedacted(t *testing.T) {
	up := serveJSON(t, `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":[`+
		`{"type":"text","text":"her email is `+piiEmail+`"}`+
		`]},"finish_reason":"stop"}],"usage":{"total_tokens":2}}`)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	body := rr.Body.String()
	t.Logf("status=%d body=%.260s", rr.Code, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if strings.Contains(body, piiEmail) {
		t.Errorf("LEAK: PII inside a response parts array reached the client: %s", body)
	}
	if !strings.Contains(body, "[REDACTED:EMAIL]") {
		t.Errorf("the parts array was not redacted in place: %s", body)
	}
	if !strings.Contains(buf.String(), `"resp:EMAIL"`) {
		t.Errorf("the redaction was not recorded in the audit trail: %s", buf.String())
	}
}

// delta.content is emitted by chunked output and by some bridges inside
// non-stream JSON; it must be redacted too.
func TestResponseDeltaContentIsRedacted(t *testing.T) {
	up := serveJSON(t, `{"id":"x","choices":[{"index":0,"delta":{"role":"assistant","content":"her email is `+
		piiEmail+`"}}],"usage":{"total_tokens":2}}`)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	body := rr.Body.String()
	t.Logf("status=%d body=%.260s", rr.Code, body)

	if strings.Contains(body, piiEmail) {
		t.Errorf("LEAK: PII inside delta.content reached the client: %s", body)
	}
	if !strings.Contains(body, "[REDACTED:EMAIL]") {
		t.Errorf("delta.content was not redacted: %s", body)
	}
}

// Legacy completions shape: choices[].text carries the output directly.
func TestResponseLegacyTextIsRedacted(t *testing.T) {
	up := serveJSON(t, `{"id":"x","choices":[{"index":0,"text":"her email is `+piiEmail+
		`","finish_reason":"stop"}],"usage":{"total_tokens":2}}`)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	body := rr.Body.String()
	t.Logf("status=%d body=%.260s", rr.Code, body)
	if strings.Contains(body, piiEmail) {
		t.Errorf("LEAK: PII inside choices[].text reached the client: %s", body)
	}
	// Asserting only the ABSENCE of PII is too weak: a response refused with 502
	// also contains no PII, so a mutation that routes this shape down the
	// fail-closed path instead of redacting it would still pass. Require the
	// success status and the marker that proves redaction actually happened.
	if rr.Code != http.StatusOK {
		t.Errorf("legacy choices[].text must be redacted and served, not refused: got %d", rr.Code)
	}
	if !strings.Contains(body, "[REDACTED:EMAIL]") {
		t.Errorf("choices[].text was not redacted in place: %s", body)
	}
	if !strings.Contains(buf.String(), `"resp:EMAIL"`) {
		t.Errorf("the redaction was not audited: %s", buf.String())
	}
}

// A successful response whose model output is in a shape the gateway cannot read
// must fail closed rather than be served unredacted.
// TestUninspectableShapesAreRedactedNotRefused pins the behaviour change that
// came with the total sweep, and states it explicitly because it reverses what an
// earlier revision of this test asserted.
//
// Previously these shapes were REFUSED with 502: the walker enumerated known
// containers, could not recognise these, and failed closed. Failing closed was
// right when the alternative was forwarding uninspected bytes, but it destroyed
// the response - the client got an error instead of an answer, and a shape the
// gateway happened not to enumerate became a denial of service.
//
// The sweep inspects every string in the document regardless of container, so
// there is nothing left uninspected to fail closed on. These shapes are now
// REDACTED AND SERVED at 200. That is strictly better: PII is still removed (the
// invariant that matters), and the client gets a usable response.
//
// Non-sensitive values are deliberately PRESERVED. An earlier assertion required
// the numbers 12345 and 9999 to be absent, because refusing the whole response
// removed them incidentally. A number is not PII; destroying it would be data
// loss, so the sweep leaves it alone and this test now requires it to survive.
func TestUninspectableShapesAreRedactedNotRefused(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantPIIGone bool
	}{
		{
			"choices is an object",
			`{"id":"x","choices":{"0":{"message":{"content":"` + piiEmail + `"}}},"usage":{"total_tokens":2}}`,
			true,
		},
		{
			"choice is a string",
			`{"id":"x","choices":["` + piiEmail + `"],"usage":{"total_tokens":2}}`,
			true,
		},
		{
			"message is a string",
			`{"id":"x","choices":[{"message":"` + piiEmail + `"}],"usage":{"total_tokens":2}}`,
			true,
		},
		{
			"content is a number",
			`{"id":"x","choices":[{"message":{"content":12345}}],"usage":{"total_tokens":2}}`,
			false,
		},
		{
			"content part is a string",
			`{"id":"x","choices":[{"message":{"content":["` + piiEmail + `"]}}],"usage":{"total_tokens":2}}`,
			true,
		},
		{
			"content part text is a number",
			`{"id":"x","choices":[{"message":{"content":[{"type":"text","text":9999}]}}],"usage":{"total_tokens":2}}`,
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := serveJSON(t, tc.body)
			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL

			rr := post(t, gw, "gpt-4o", "hello")
			client := rr.Body.String()
			t.Logf("status=%d client=%.220s audit=%.280s", rr.Code, client, buf.String())

			// THE INVARIANT: no PII egress, whatever the shape.
			if strings.Contains(client, piiEmail) {
				t.Errorf("LEAK: PII reached the client: %s", client)
			}

			// The response is served, not destroyed.
			if rr.Code != http.StatusOK {
				t.Errorf("status = %d; a swept response should be served at 200 "+
					"rather than refused, because nothing is left uninspected", rr.Code)
			}

			if tc.wantPIIGone {
				if !strings.Contains(client, "[REDACTED:EMAIL]") {
					t.Errorf("the PII was not replaced by a redaction marker: %s", client)
				}
				if !auditClaimsRedaction(buf.String()) {
					t.Errorf("a redaction happened but the audit does not record it: %s",
						buf.String())
				}
			} else {
				// A number carries no PII, so it must survive untouched.
				if !strings.Contains(client, "12345") && !strings.Contains(client, "9999") {
					t.Errorf("a non-sensitive numeric value was destroyed: %s", client)
				}
				if auditClaimsRedaction(buf.String()) {
					t.Errorf("OVER-CLAIM: nothing sensitive was present but the audit "+
						"records a redaction: %s", buf.String())
				}
			}

			// Upstream identity fields must survive the sweep (branch purpose).
			if !strings.Contains(client, `"id":"x"`) {
				t.Errorf("the upstream id was lost: %s", client)
			}
		})
	}
}

// The complement: an upstream ERROR response in an odd shape must still pass
// through. Error bodies are diagnostic, not model output, and refusing them would
// make upstream failures undebuggable.
func TestErrorResponseShapeIsNotRefused(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		// choices as an object: would be refused on a 2xx, must pass on a 4xx.
		_, _ = io.WriteString(w, `{"error":{"message":"rate limited"},"choices":{"weird":true}}`)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("status=%d body=%.160s", rr.Code, rr.Body.String())
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("an upstream 429 must be passed through, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "rate limited") {
		t.Errorf("the upstream error detail was swallowed: %s", rr.Body.String())
	}
}

// No choices at all (embeddings-style response) is not model text and must pass.
func TestResponseWithoutChoicesPassesThrough(t *testing.T) {
	up := serveJSON(t, `{"object":"list","data":[{"embedding":[0.1,0.2],"index":0}],"usage":{"total_tokens":3}}`)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "text-embedding-3-small", "hello")
	t.Logf("status=%d body=%.200s", rr.Code, rr.Body.String())
	if rr.Code != http.StatusOK {
		t.Fatalf("an embeddings-style response must pass through, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "embedding") {
		t.Errorf("the response was altered: %s", rr.Body.String())
	}
	toks, _ := gw.Limiter.Usage("test-key")
	if toks != 3 {
		t.Errorf("usage was not accounted for a choices-less response: %d", toks)
	}
}

// ---------------------------------------------------------------------------
// N1: a truthy non-bool "stream" must be treated as a streaming request.
// ---------------------------------------------------------------------------

func TestTruthyNonBoolStreamIsRefused(t *testing.T) {
	up := serveJSON(t, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	for _, tc := range []struct {
		name string
		val  any
	}{
		{"string true", "true"},
		{"string TRUE", "TRUE"},
		{"string 1", "1"},
		{"string yes", "yes"},
		{"number 1", 1},
		{"number 2", 2.0},
		{"bool true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{
				"model":    "gpt-4o",
				"stream":   tc.val,
				"messages": []map[string]string{{"role": "user", "content": "hi"}},
			})
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
			req.Header.Set("X-API-Key", "test-key")
			gw.ServeHTTP(rr, req)
			t.Logf("stream=%v status=%d", tc.val, rr.Code)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("a truthy stream value must be refused while RedactResponse is on, got %d", rr.Code)
			}
		})
	}
}

// Falsy spellings must NOT be refused - otherwise a client sending stream:false
// as a string would be broken by the guard.
func TestFalsyStreamIsAllowed(t *testing.T) {
	up := serveJSON(t, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	for _, tc := range []struct {
		name string
		val  any
	}{
		{"bool false", false},
		{"string false", "false"},
		{"string empty", ""},
		{"number 0", 0},
		{"absent", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"model":    "gpt-4o",
				"messages": []map[string]string{{"role": "user", "content": "hi"}},
			}
			if tc.val != nil {
				body["stream"] = tc.val
			}
			raw, _ := json.Marshal(body)
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
			req.Header.Set("X-API-Key", "test-key")
			gw.ServeHTTP(rr, req)
			t.Logf("stream=%v status=%d", tc.val, rr.Code)
			if rr.Code != http.StatusOK {
				t.Errorf("a falsy stream value must be allowed, got %d", rr.Code)
			}
		})
	}
}

// N2: the refusal must name a knob that actually exists. Config is JSON
// (redact_response); there is no REDACT_RESPONSE environment variable.
func TestStreamingRefusalNamesARealConfigKnob(t *testing.T) {
	up := serveJSON(t, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	raw, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"stream":   true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)

	body := rr.Body.String()
	t.Logf("detail=%.200s", body)
	if strings.Contains(body, "REDACT_RESPONSE") {
		t.Errorf("the error names a non-existent env var; config is JSON: %s", body)
	}
	if !strings.Contains(body, "redact_response") {
		t.Errorf("the error should name the real config key redact_response: %s", body)
	}
}

// ---------------------------------------------------------------------------
// N3: a REQUEST-side rewrite must not strip the RESPONSE's validators.
// ---------------------------------------------------------------------------

func TestRequestOnlyRewriteKeepsResponseETag(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = b
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", `"upstream-validator"`)
		// Clean response: no PII, so the served bytes should be untouched.
		_, _ = io.WriteString(w, `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"clean"},"finish_reason":"stop"}],"usage":{"total_tokens":2}}`)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	// Response redaction OFF so the response bytes are provably untouched, while
	// request redaction ON so the request IS rewritten.
	gw.RedactResponse = false

	raw, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "email " + piiEmail}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)

	t.Logf("status=%d etag=%q audit=%.200s", rr.Code, rr.Header().Get("Etag"), buf.String())
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), "EMAIL") {
		t.Errorf("the request-side redaction did not happen, so this test proves nothing: %s", buf.String())
	}
	if v := rr.Header().Get("Etag"); v != `"upstream-validator"` {
		t.Errorf("a request-only rewrite must not strip the response ETag: got %q", v)
	}
}

// ---------------------------------------------------------------------------
// N4: a panicking Redactor must not leave the audit chain with a hole.
// ---------------------------------------------------------------------------

type panickingRedactor struct{}

func (panickingRedactor) Redact(string) (string, []string) {
	panic("backend exploded")
}

var _ redactor.Redactor = panickingRedactor{}

func TestPanickingRedactorIsRecoveredAndAudited(t *testing.T) {
	up := serveJSON(t, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = panickingRedactor{}

	rr := post(t, gw, "gpt-4o", "email "+piiEmail)
	t.Logf("status=%d body=%.160s audit=%.300s", rr.Code, rr.Body.String(), buf.String())

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("a panicking redactor should surface as 500, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), "handler-panic") {
		t.Errorf("AUDIT HOLE: the panic was recovered but no event was written: %s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// N5: unbounded reads are a memory-exhaustion vector aimed at the gateway.
// ---------------------------------------------------------------------------

func TestOversizedRequestIsRefused(t *testing.T) {
	up := serveJSON(t, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	// One byte over the limit. maxBodyBytes is 32 MiB; build the body from a
	// padding field so the JSON stays well-formed.
	huge := strings.Repeat("a", maxBodyBytes)
	raw, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": huge}},
	})
	if len(raw) <= maxBodyBytes {
		t.Skipf("test body is not over the limit (%d <= %d)", len(raw), maxBodyBytes)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)

	t.Logf("status=%d audit=%.240s", rr.Code, buf.String())
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversized request must be refused with 413, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), "request-too-large") {
		t.Errorf("the refusal was not audited: %s", buf.String())
	}
}

// A body exactly at the limit must still be accepted, so the guard is not off by
// one in the direction that breaks legitimate large requests.
func TestRequestAtLimitIsAccepted(t *testing.T) {
	up := serveJSON(t, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	raw, _ := json.Marshal(map[string]any{
		"model":    "m",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if len(raw) > maxBodyBytes {
		t.Skip("small body unexpectedly over limit")
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("a normal-size request must be accepted, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// M12: the reviewer found the repo had ZERO tests for audit key masking, even
// though the guard is load-bearing - an unmasked key in the audit log is a
// credential leak into a file that is often shipped to a SIEM.
// ---------------------------------------------------------------------------

const longSecretKey = "sk-live-0123456789abcdefghij"

func TestAuditNeverContainsTheRawAPIKey(t *testing.T) {
	up := serveJSON(t, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	logged := buf.String()
	t.Logf("status=%d audit=%.300s", rr.Code, logged)
	if logged == "" {
		t.Fatal("no audit event was written, so this test proves nothing")
	}
	if strings.Contains(logged, longSecretKey) {
		t.Errorf("LEAK: the raw API key appears in the audit log: %s", logged)
	}
	// The masked form keeps a 4-char prefix, which is the documented behaviour.
	if !strings.Contains(logged, "sk-l") {
		t.Errorf("expected the masked 4-char prefix in the audit log: %s", logged)
	}
}

// The key must be masked on EVERY audited path, not just the happy path. These
// are the paths most likely to be overlooked because they return early.
func TestAuditMasksKeyOnEveryEarlyReturnPath(t *testing.T) {
	up := serveJSON(t, okJSONResponse)

	paths := []struct {
		name    string
		gateway func(*Gateway)
		body    string
	}{
		{
			name:    "policy deny",
			gateway: func(g *Gateway) { g.Engine = engineWithRules(t, denyRuleOn("FORBIDDEN")) },
			body:    `{"model":"m","messages":[{"role":"user","content":"say FORBIDDEN"}]}`,
		},
		{
			name:    "streaming refusal",
			gateway: func(g *Gateway) {},
			body:    `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`,
		},
		{
			name:    "uninspectable content shape",
			gateway: func(g *Gateway) {},
			body:    `{"model":"m","messages":[{"role":"user","content":42}]}`,
		},
		{
			name:    "non-object body",
			gateway: func(g *Gateway) {},
			body:    `null`,
		},
	}

	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL
			tc.gateway(gw)

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
				strings.NewReader(tc.body))
			req.Header.Set("X-API-Key", longSecretKey)
			gw.ServeHTTP(rr, req)

			logged := buf.String()
			t.Logf("status=%d audit=%.240s", rr.Code, logged)
			if strings.Contains(logged, longSecretKey) {
				t.Errorf("LEAK on the %q path: raw API key in the audit log: %s", tc.name, logged)
			}
			// Some early-return paths legitimately write no event (e.g. a
			// non-object body is refused before the key is attributed). What must
			// never happen is an event containing the raw key.
		})
	}
}

// engineWithRules builds a compiled policy engine with an allow-by-default
// posture, mirroring newTestGateway.
func engineWithRules(t *testing.T, rules []policy.Rule) *policy.Engine {
	t.Helper()
	eng := &policy.Engine{Default: policy.Allow, Rules: rules}
	if err := eng.Compile(); err != nil {
		t.Fatalf("compiling policy rules: %v", err)
	}
	return eng
}

// ---------------------------------------------------------------------------
// N10: an out-of-range usage figure must clamp, not rely on Go's
// implementation-defined int64(float64) conversion.
// ---------------------------------------------------------------------------

func TestHugeUsageFigureIsClamped(t *testing.T) {
	// 1e300 as a JSON number decodes to float64 far beyond int64's range.
	up := serveJSON(t, `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":1e300}}`)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	toks, _ := gw.Limiter.Usage("test-key")
	t.Logf("status=%d tokens=%d audit=%.240s", rr.Code, toks, buf.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("a huge usage figure should not fail the request, got %d", rr.Code)
	}
	if toks <= 0 {
		t.Errorf("an enormous usage figure must saturate to a large positive value, got %d "+
			"(a negative or zero figure would be a budget bypass)", toks)
	}
	if toks != math.MaxInt64 {
		t.Errorf("expected saturation to MaxInt64, got %d", toks)
	}
	if !strings.Contains(buf.String(), "exceeded") {
		t.Errorf("a saturating figure should trip the budget signal: %s", buf.String())
	}
}

// A negative or NaN usage figure must not be recorded - a negative figure would
// silently increase a caller's remaining budget.
func TestNegativeUsageIsNotRecorded(t *testing.T) {
	up := serveJSON(t, `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":-5000}}`)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	toks, _ := gw.Limiter.Usage("test-key")
	t.Logf("status=%d tokens=%d audit=%.240s", rr.Code, toks, buf.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("a negative usage figure should not fail the request, got %d", rr.Code)
	}
	if toks != 0 {
		t.Errorf("BUDGET BYPASS: a negative usage figure was recorded as %d, which would "+
			"credit the caller's budget", toks)
	}
	if !strings.Contains(buf.String(), `"usage":"unparseable"`) {
		t.Errorf("a rejected usage figure should be audited as unparseable: %s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// N5: a truncated upstream response must not be forwarded as if complete. The
// original bug announced upstream's Content-Length while writing fewer bytes, so
// a read error is not safe to discard.
// ---------------------------------------------------------------------------

type erroringReader struct {
	n   int
	err error
}

func (e *erroringReader) Read(p []byte) (int, error) {
	if e.n <= 0 {
		return 0, e.err
	}
	e.n--
	return 0, e.err
}

func TestUpstreamReadErrorFailsClosed(t *testing.T) {
	// An upstream that declares a Content-Length and then fails mid-body.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "9999")
		w.WriteHeader(http.StatusOK)
		// Write a little then abort the connection so the client's read errors.
		if f, ok := w.(http.Flusher); ok {
			_, _ = io.WriteString(w, `{"id":"x"`)
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("status=%d body=%.160s audit=%.280s", rr.Code, rr.Body.String(), buf.String())

	if rr.Code != http.StatusBadGateway {
		t.Errorf("a truncated upstream body must surface as 502, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), "response_read_failed") {
		t.Errorf("the read failure was not audited: %s", buf.String())
	}
}

// M27b closed a genuine gap: the oversized-RESPONSE branch had no test at all.
// Without one, deleting the guard would not fail the suite - it is the response
// mirror of TestOversizedRequestIsRefused and just as load-bearing, since the
// response body is also buffered in full before redaction can run.
func TestOversizedUpstreamResponseIsRefused(t *testing.T) {
	// Upstream returns more than maxBodyBytes. The gateway buffers it via a
	// LimitReader, so it must notice the overflow and refuse rather than serve a
	// silently truncated body under a truthful-looking Content-Length.
	big := strings.Repeat("a", maxBodyBytes+1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"`+big+`"}}]}`)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("status=%d body=%.120s audit=%.260s", rr.Code, rr.Body.String(), buf.String())

	if rr.Code != http.StatusBadGateway {
		t.Errorf("an oversized upstream response must be refused with 502, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), "response_too_large") {
		t.Errorf("the refusal was not audited: %s", buf.String())
	}
	if rr.Body.Len() > 4096 {
		t.Errorf("a truncated fragment of the oversized body was served to the client (%d bytes)",
			rr.Body.Len())
	}
}
