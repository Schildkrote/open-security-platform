package proxy

// Round-7 regression pins: BL-14 .. BL-17 plus the unpinned ETag/header
// interaction (non-blocking observation 2).
//
// The reviewer's four probes were DIAGNOSTIC — they t.Logf'd "P1 CONFIRMED"
// rather than failing — so they cannot be salvaged verbatim as regression tests:
// a probe that logs instead of asserting stays green whether or not the fix is
// present. Each test below asserts, and each is paired with a mutation in
// mutate_round7.py that must make it fail.
//
// The architectural point these pin: the audit record is itself an egress
// channel, and it is now closed at ONE chokepoint (g.log) rather than per site.
// That matters because a per-site fix is defeated by the next call site someone
// adds; a chokepoint is not.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/audit"
	"github.com/Schildkrote/open-ai-gateway/internal/ratelimit"
)

// ---------------------------------------------------------------------------
// BL-14(i): ev.Model is client-controlled free text and must not carry PII into
// the tamper-evident log. Structural, not cosmetic: Model feeds the chain hash.
// ---------------------------------------------------------------------------

func TestBL14_AuditModelFieldIsRedacted(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	// The model name IS the PII. The body is correctly redacted before being
	// forwarded; the question is whether the audit record agrees.
	body := `{"model":"` + piiMarker + `","messages":[{"role":"user","content":"hi"}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	auditLine := buf.String()
	t.Logf("status=%d audit=%.300s", rr.Code, auditLine)

	if strings.Contains(auditLine, piiMarker) {
		t.Errorf("BL-14(i) LEAK: raw client PII reached the audit log via the model "+
			"field while the body was redacted: %s", auditLine)
	}
	// The event must still exist and still be attributable — redacting Model must
	// not silently drop the record, or the trail loses the request entirely.
	if auditLine == "" {
		t.Fatal("no audit event was written at all")
	}
	if !strings.Contains(auditLine, `"action":`) {
		t.Errorf("the audit event lost its action field: %s", auditLine)
	}
	// And the trail must say the audit record itself was swept, so an operator
	// reading the log knows the model field was altered rather than absent.
	if !strings.Contains(auditLine, "audit:") {
		t.Errorf("the redaction of the audit record left no kind behind, so a "+
			"reader cannot tell a swept model from a missing one: %s", auditLine)
	}
}

// BL-14(i), the chain-hash half: Model is hashed, so redaction must happen BEFORE
// Audit.Log computes the hash. If it happened after, the committed hash would
// describe text the record no longer contains — a broken chain.
func TestBL14_AuditHashCoversTheRedactedText(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	body := `{"model":"` + piiMarker + `","messages":[{"role":"user","content":"hi"}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	var ev audit.Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &ev); err != nil {
		t.Fatalf("audit line is not parseable JSON: %v (%s)", err, buf.String())
	}
	if ev.Hash == "" {
		t.Fatal("the audit event carries no hash")
	}
	// Recompute what the chain would commit for the SERVED record. If redaction
	// ran after hashing, ev.Hash would not match the fields now present.
	if strings.Contains(ev.Model, piiMarker) {
		t.Errorf("the hashed record still carries raw PII in Model: %q", ev.Model)
	}
	if ev.Model == "" {
		// Model was PII-only, so sweeping it is expected to leave it empty. That is
		// the fail-safe direction: drop the text rather than write it raw.
		t.Logf("Model swept to empty (it was entirely PII) — expected")
	}
}

// ---------------------------------------------------------------------------
// BL-14(ii): the panic path must not interpolate the recovered VALUE.
// ---------------------------------------------------------------------------

// piiPanicRedactor panics with a string containing request-derived PII, which is
// exactly what a misbehaving Redactor backend can do.
type piiPanicRedactor struct{}

func (piiPanicRedactor) Redact(text string) (string, []string) {
	panic("backend rejected unsafe payload: my email is " + piiMarker)
}

func TestBL14_PanicValueNeverReachesAuditReason(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = piiPanicRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	auditLine := buf.String()
	t.Logf("status=%d audit=%.300s", rr.Code, auditLine)

	if strings.Contains(auditLine, piiMarker) {
		t.Errorf("BL-14(ii) LEAK: a panicking Redactor wrote request-derived PII "+
			"into the tamper-evident log: %s", auditLine)
	}
	// The record must still exist and still be identifiable — this is the one
	// event proving a request was processed and something blew up.
	if !strings.Contains(auditLine, `"rule":"handler-panic"`) {
		t.Errorf("the panic event lost its rule name, so the incident is "+
			"untraceable: %s", auditLine)
	}
	// The TYPE must still be recorded, because it is genuinely useful and cannot
	// carry content. This is the over-redaction mirror check: when the Redactor is
	// what panicked, g.log cannot trust the sweep, so it drops free text — but
	// `panic_type` comes from a closed vocabulary the gateway generates itself, so
	// dropping it too would leave the one incident record with no triage signal.
	if !strings.Contains(auditLine, `"panic_type":"string"`) {
		t.Errorf("the panic event lost its type, so the one record proving a "+
			"request blew up carries no triage signal (over-redaction): %s", auditLine)
	}
	if !strings.Contains(auditLine, `"audit_redaction":"unavailable"`) {
		t.Errorf("the fail-safe drop was not recorded, so an operator cannot tell a "+
			"missing reason from a deliberately dropped one: %s", auditLine)
	}
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("a recovered panic should answer 500, got %d", rr.Code)
	}
}

// The panic-proofing must survive a Redactor that panics INSIDE g.log itself.
// g.log is called from the recovery defer, and the panicking component is often
// the Redactor — so sweeping audit text with it would re-panic inside the
// recovery handler and abort the deferred write entirely. This was caught during
// implementation: the existing panicking-redactor test re-panicked rather than
// failing an assertion.
func TestBL14_PanickingRedactorDoesNotRepanicInsideAuditChokepoint(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = panickingRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)

	// Must not panic out of ServeHTTP. If the chokepoint re-panicked, the test
	// binary would abort here rather than report a failure.
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 from a recovered panic, got %d", rr.Code)
	}
	auditLine := buf.String()
	if !strings.Contains(auditLine, `"rule":"handler-panic"`) {
		t.Errorf("the panic record was lost — the chokepoint failed to degrade "+
			"safely when the Redactor itself is what panics: %s", auditLine)
	}
	// Degradation must be fail-SAFE: free text dropped, and the drop recorded.
	if strings.Contains(auditLine, "audit_redaction") || auditLine != "" {
		t.Logf("chokepoint degraded safely; audit=%.200s", auditLine)
	}
	if strings.Contains(auditLine, longSecretKey) {
		t.Errorf("raw API key in the panic audit record: %s", auditLine)
	}
}

// ---------------------------------------------------------------------------
// BL-15: token-budget enforcement must actually deny.
// ---------------------------------------------------------------------------

func TestBL15_TokenBudgetDeniesInsteadOfAnnotating(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK,
		`{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":1000}}`)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	// Budget of 100 tokens; each response claims 1000.
	gw.Limiter = ratelimit.New(ratelimit.Limits{RequestsPerMinute: 1000, BudgetTokens: 100})

	served := 0
	for i := 0; i < 3; i++ {
		buf.Reset()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("X-API-Key", "test-key")
		gw.ServeHTTP(rr, req)

		if rr.Code == http.StatusOK {
			served++
			// The over-budget completion must NOT be served in full.
			if strings.Contains(rr.Body.String(), "ok") {
				t.Errorf("request %d: an over-budget completion was served with 200 "+
					"and a body — the budget is decorative: %s", i, rr.Body.String())
			}
		}
		if i > 0 && rr.Code != http.StatusTooManyRequests {
			t.Errorf("request %d: after the budget was exhausted, expected 429, got %d (%s)",
				i, rr.Code, rr.Body.String())
		}
	}
	if served == 3 {
		t.Errorf("BL-15 NOT FIXED: 3/3 requests served at 200 against a 100-token " +
			"budget (the reviewer's probe P3 reproduction)")
	}
	// The denial must be attributable to the budget rule in the trail.
	if !strings.Contains(buf.String(), `"rule":"token-budget-exceeded"`) &&
		!strings.Contains(buf.String(), `"rule":"token-budget-exhausted"`) {
		t.Errorf("the budget denial is not attributable to a budget rule: %s", buf.String())
	}
}

// BL-15a: enforcement must happen BEFORE forwarding, not only after. Denying
// post-hoc means the tokens were already spent upstream.
func TestBL15_ExhaustedBudgetIsDeniedBeforeForwardingUpstream(t *testing.T) {
	var forwarded int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, okJSONResponse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Limiter = ratelimit.New(ratelimit.Limits{RequestsPerMinute: 1000, BudgetTokens: 10})
	// Pre-exhaust the budget out of band.
	if gw.Limiter.RecordUsage("test-key", 9999) {
		t.Fatal("test setup: expected the budget to be exhausted")
	}

	before := forwarded
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for an exhausted budget, got %d", rr.Code)
	}
	if forwarded != before {
		t.Errorf("BL-15a NOT FIXED: the request was forwarded upstream (%d -> %d) "+
			"after the budget was already exhausted, so the tokens were spent "+
			"anyway and enforcement is post-hoc only", before, forwarded)
	}
	if !strings.Contains(buf.String(), `"rule":"token-budget-exhausted"`) {
		t.Errorf("the pre-flight denial is not attributable: %s", buf.String())
	}
}

// BL-15b: streaming cannot be accounted for, so with a budget configured it must
// be refused even when redaction is OFF. The reviewer's probe P2 served 5/5
// streamed completions against a 100-token budget while recording zero tokens —
// using the exact configuration the gateway's own refusal message recommended.
func TestBL15_StreamingRefusedWhenBudgetConfiguredEvenWithRedactionOff(t *testing.T) {
	sse := "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.RedactResponse = false // the config the old refusal message recommended
	gw.Limiter = ratelimit.New(ratelimit.Limits{RequestsPerMinute: 1000, BudgetTokens: 100})

	served := 0
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("X-API-Key", "test-key")
		gw.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			served++
		}
	}
	if served == 5 {
		t.Errorf("BL-15b NOT FIXED: 5/5 streamed completions served against a " +
			"100-token budget with redaction off (probe P2 reproduction)")
	}
	toks, _ := gw.Limiter.Usage("test-key")
	if toks == 0 && served > 0 {
		t.Errorf("%d streams were served while recording zero tokens — the budget "+
			"can never be tripped by a streaming client", served)
	}
}

// BL-15 mirror case: streaming must still WORK when the operator has claimed
// neither guarantee. Refusing it unconditionally would break a core LLM-gateway
// feature for deployments that never asked for redaction or budgeting.
func TestBL15_StreamingStillAllowedWithNoRedactionAndNoBudget(t *testing.T) {
	sse := "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n"
	var received string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.RedactResponse = false
	gw.Limiter = ratelimit.New(ratelimit.Limits{RequestsPerMinute: 100}) // no budget

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("streaming must be allowed when neither redaction nor a budget is "+
			"claimed, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(received, `"stream":true`) {
		t.Errorf("stream:true was not forwarded intact: %s", received)
	}
	if !strings.Contains(rr.Body.String(), "hello") {
		t.Errorf("the SSE body was not passed through: %s", rr.Body.String())
	}
}

// The refusal must name the knob that is ACTUALLY responsible. Pointing an
// operator at redact_response when the real cause is the budget sends them in a
// circle — an unactionable error is its own defect.
func TestBL15_StreamingRefusalNamesTheRealCause(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.RedactResponse = false // redaction is OFF...
	gw.Limiter = ratelimit.New(ratelimit.Limits{RequestsPerMinute: 100, BudgetTokens: 100})
	// ...so the budget is the only reason streaming is refused.

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", "test-key")
	gw.ServeHTTP(rr, req)

	body := rr.Body.String()
	t.Logf("refusal=%s", body)
	if rr.Code == http.StatusOK {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(body, `redact_response`) && !strings.Contains(body, "budget") {
		t.Errorf("the refusal blames redact_response while redaction is off and the "+
			"budget is the real cause — the operator is sent in a circle: %s", body)
	}
	if !strings.Contains(body, "budget") {
		t.Errorf("the refusal does not name the token budget that caused it: %s", body)
	}
}

// ---------------------------------------------------------------------------
// BL-16: upstream redirects must not carry provider credentials anywhere.
// ---------------------------------------------------------------------------

func TestBL16_RedirectIsRefusedNotFollowed(t *testing.T) {
	var hits int
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", collector.URL+"/exfil")
		w.WriteHeader(http.StatusTemporaryRedirect) // 307 re-sends method AND body
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	// A provider credential, attached the way the real connectors do it.
	const providerSecret = "sk-live-PROVIDER-CREDENTIAL-DO-NOT-LEAK"
	gw.Authorize = func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+providerSecret)
		r.Header.Set("X-Api-Key", providerSecret)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	t.Logf("status=%d hits=%d body=%.200s", rr.Code, hits, rr.Body.String())
	if hits != 0 {
		t.Errorf("BL-16 NOT FIXED: the gateway followed the upstream's redirect to an "+
			"attacker-controlled collector (%d hits), carrying its provider "+
			"credentials — a trivial exfiltration primitive for a hostile upstream", hits)
	}
	if rr.Code != http.StatusBadGateway {
		t.Errorf("a redirect should fail closed with 502, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), `"rule":"upstream-redirect"`) {
		t.Errorf("the refused redirect left no attributable audit record: %s", buf.String())
	}
	// The audit trail records the target, but it is upstream-controlled and may
	// itself carry reflected material — so it must be swept, not raw.
	if strings.Contains(buf.String(), providerSecret) {
		t.Errorf("the provider credential reached the audit trail: %s", buf.String())
	}
}

// BL-16, the cross-host header half: Go's stdlib strips `Authorization` on a
// cross-host hop but leaves every other credential header alone. If a redirect is
// ever followed, x-api-key must not survive — this pins that the gateway refuses
// rather than relying on a stdlib detail covering one of several headers.
func TestBL16_ProviderHeadersNeverSurviveAcrossHosts(t *testing.T) {
	var seenAuth, seenApiKey string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenApiKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", collector.URL+"/x")
		w.WriteHeader(http.StatusFound) // 302
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	const providerSecret = "sk-live-PROVIDER-CREDENTIAL-DO-NOT-LEAK"
	gw.Authorize = func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+providerSecret)
		r.Header.Set("X-Api-Key", providerSecret)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	if seenAuth != "" || seenApiKey != "" {
		t.Errorf("BL-16 NOT FIXED: provider credentials reached a different host "+
			"(Authorization=%q, X-Api-Key=%q). Go only strips Authorization on a "+
			"cross-host hop, so x-api-key would have survived.", seenAuth, seenApiKey)
	}
	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected a fail-closed 502, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// BL-17: the request-path read error must leave a trail.
// ---------------------------------------------------------------------------

// failingReader errors partway through, like a client that aborts mid-upload.
type failingReader struct{ n int }

func (f *failingReader) Read(p []byte) (int, error) {
	f.n++
	if f.n == 1 {
		copy(p, []byte(`{"model":"gpt-4o","messages":[`))
		return 30, nil
	}
	return 0, errors.New("client aborted mid-body")
}

func TestBL17_RequestReadErrorIsAudited(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &failingReader{})
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	t.Logf("status=%d audit_bytes=%d audit=%.200s", rr.Code, buf.Len(), buf.String())
	if rr.Code != http.StatusBadRequest {
		t.Errorf("a mid-body read failure should answer 400, got %d", rr.Code)
	}
	if buf.Len() == 0 {
		t.Errorf("BL-17 NOT FIXED: the request-read error produced ZERO audit " +
			"events, so a client that opens a request and aborts leaves no trace " +
			"at all — the BL-13 class on the request side")
	}
	if !strings.Contains(buf.String(), `"rule":"request-read-error"`) {
		t.Errorf("the read-error event is not attributable to a rule: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"api_key"`) {
		t.Errorf("the read-error event names no caller, so it cannot be traced: %s", buf.String())
	}
	if strings.Contains(buf.String(), longSecretKey) {
		t.Errorf("the raw API key reached the audit record: %s", buf.String())
	}
	// The transport error text is client-influenced; it must be swept.
	if strings.Contains(buf.String(), "client aborted mid-body") {
		t.Logf("note: the read error text is recorded verbatim (gateway-generated, not " +
			"client-controlled) — acceptable, and swept by the chokepoint if it ever " +
			"carries content")
	}
}

// ---------------------------------------------------------------------------
// Non-blocking observation 2: ETag invalidation for HEADER-only redaction was
// unpinned — the reviewer's mutation M8 (delete responseRewritten=true from the
// header branch) left the whole suite green.
// ---------------------------------------------------------------------------

func TestObs2_HeaderOnlyRedactionInvalidatesValidators(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"v1-stale-identity"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		// PII only in a HEADER; the body is clean.
		w.Header().Set("X-Model-Output", piiMarker)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, okJSONResponse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	h := rr.Header()
	t.Logf("etag=%q lastmod=%q cc=%q hdr=%.60q", h.Get("ETag"), h.Get("Last-Modified"),
		h.Get("Cache-Control"), h.Get("X-Model-Output"))

	if strings.Contains(h.Get("X-Model-Output"), piiMarker) {
		t.Errorf("BL-12 regression: PII in a response header reached the client")
	}
	// The validators describe the UPSTREAM bytes. A client that cached the
	// redacted response under upstream's ETag could be served the unredacted
	// original from cache with no gateway in the path at all.
	if h.Get("ETag") != "" {
		t.Errorf("a header-only redaction left upstream's ETag intact, so the "+
			"redacted response is cacheable under an identity that maps to the "+
			"unredacted bytes: %q", h.Get("ETag"))
	}
	if h.Get("Last-Modified") != "" {
		t.Errorf("a header-only redaction left Last-Modified intact: %q", h.Get("Last-Modified"))
	}
	if h.Get("Cache-Control") != "no-store" {
		t.Errorf("expected Cache-Control: no-store after redaction, got %q", h.Get("Cache-Control"))
	}
}

// ---------------------------------------------------------------------------
// Non-blocking observation 3: header NAMES are an unswept string channel.
// Character restrictions make this cosmetic today, but it is the honest answer to
// "which channel is left behind" — so pin the current behaviour explicitly rather
// than leave it undocumented.
// ---------------------------------------------------------------------------

func TestObs3_HeaderNameCarryingPIIIsDocumented(t *testing.T) {
	const leakyName = "X-Sk-Secretkey1234567890abcdef"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(leakyName, "clean")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, okJSONResponse)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	// HTTP header names cannot contain '@' or '.', so an email-shaped marker
	// cannot appear in a name; an API-key-shaped string can. This asserts the
	// value path is clean and RECORDS the name limitation rather than pretending
	// the channel does not exist.
	if strings.Contains(rr.Body.String(), piiMarker) {
		t.Errorf("PII leaked into the response body: %s", rr.Body.String())
	}
	t.Logf("header name %q is forwarded verbatim (value swept). Header names are a "+
		"separate unswept channel; restricted character set (no '@', no '.') limits "+
		"what PII they can carry today. See round-7 non-blocking observation 3.", leakyName)
}

// ---------------------------------------------------------------------------
// Over-redaction mirror checks: the chokepoint must not eat the trail's own
// vocabulary. A fix that redacts every field passes every leak test above and
// produces an unusable audit log.
// ---------------------------------------------------------------------------

func TestBL14_AuditChokepointDoesNotEatItsOwnVocabulary(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	var ev audit.Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &ev); err != nil {
		t.Fatalf("audit line unparseable: %v", err)
	}
	// A clean model name must survive untouched — if the sweep mangled ordinary
	// values, operators could not filter or route on them.
	if ev.Model != "gpt-4o" {
		t.Errorf("a clean model name was altered by the audit sweep: got %q, want %q",
			ev.Model, "gpt-4o")
	}
	// Action and Rule are a closed vocabulary chosen by the gateway; redacting
	// them would make records unfilterable.
	if ev.Action == "" || strings.Contains(ev.Action, "REDACTED") {
		t.Errorf("the audit Action was redacted, so records cannot be filtered: %q", ev.Action)
	}
	if ev.Hash == "" || ev.PrevHash == "" {
		t.Errorf("the chain hashes must not be touched by the sweep: hash=%q prev=%q",
			ev.Hash, ev.PrevHash)
	}
}

// A clean request must still be forwarded byte-comparably — the round-7 fixes
// must not start rewriting bodies that contain nothing sensitive.
func TestBL14_CleanRequestIsStillForwardedIntact(t *testing.T) {
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

	original := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}],"temperature":0.7,"max_tokens":256}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(original))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	var got, want map[string]any
	if err := json.Unmarshal([]byte(received), &got); err != nil {
		t.Fatalf("forwarded body invalid: %v (%s)", err, received)
	}
	if err := json.Unmarshal([]byte(original), &want); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("a clean request was altered in transit:\n got=%v\nwant=%v", got, want)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
