package proxy

// Round-7, part 2: tests for the four mutations that SURVIVED the first battery.
//
// A survivor is a real test gap by definition — the fix may be correct and still
// be unpinned, which means a future change can silently undo it. Diagnosing each
// survivor showed the same root cause in three of four: my tests never
// CONSTRUCTED the condition the defence exists for.
//
//   M2  (Reason left unswept)     — no test ever put PII in ev.Reason.
//   M5  (fail-safe writes raw)    — the panicking-redactor test used a clean
//                                    model name, so there was nothing raw to drop.
//                                    Worse: the panic handler builds a FRESH event
//                                    with no Model at all, so NO panicking-redactor
//                                    test can pin this. The faithful path is a
//                                    policy deny, which logs ev (raw Model) before
//                                    any redaction — see round7failsafe_test.go.
//   M11 (redirect Location raw)   — the redirect test used a clean Location.
//   M3  (panic value interpolated)— genuinely defence-in-depth: with the
//                                    chokepoint sweeping Reason, the interpolation
//                                    is caught by the OTHER layer. Pinned below
//                                    with a secret the redactor cannot match, so
//                                    the type-only construction is the only thing
//                                    standing between the value and the log.
//
// Together these make the chokepoint's guarantees testable field-by-field rather
// than only along the paths that happened to carry PII in round 7's first pass.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/audit"
	"github.com/Schildkrote/open-ai-gateway/internal/ratelimit"
)

// ---------------------------------------------------------------------------
// M2: ev.Reason must be swept by the chokepoint.
//
// g.log is the single point every event passes through, so calling it directly is
// the honest way to pin the field-level guarantee — any indirect test would only
// cover the Reason values that today's call sites happen to produce, and those
// are all gateway-generated constants. Reason is a free-text field; the next call
// site someone adds may populate it from upstream.
// ---------------------------------------------------------------------------

func TestBL14_AuditReasonFieldIsSwept(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)

	// A Reason carrying PII, exactly as a future call site might build it from
	// upstream material.
	gw.log(audit.Event{
		APIKey: maskKey(longSecretKey),
		Action: "denied",
		Rule:   "some-future-rule",
		Reason: "upstream said: " + piiMarker + " is not allowed",
	})

	got := buf.String()
	t.Logf("audit=%.300s", got)
	if strings.Contains(got, piiMarker) {
		t.Errorf("BL-14 LEAK: PII in ev.Reason reached the tamper-evident log "+
			"unswept, so the chokepoint does not actually cover Reason: %s", got)
	}
	if !strings.Contains(got, "audit:") {
		t.Errorf("sweeping Reason left no kind behind, so a reader cannot tell a "+
			"swept reason from a missing one: %s", got)
	}
	// The record itself must survive — dropping the whole event over one dirty
	// field would be worse than the leak it prevents.
	if !strings.Contains(got, `"rule":"some-future-rule"`) {
		t.Errorf("the event lost its Rule (a closed vocabulary that must never be "+
			"swept): %s", got)
	}
	if !strings.Contains(got, "upstream said:") {
		t.Errorf("the non-sensitive part of Reason was destroyed — over-redaction "+
			"makes the trail useless: %s", got)
	}
}

// Meta values are free-form and several sites put upstream-derived text in them,
// so Meta is swept too. Pinned directly for the same reason as Reason.
func TestBL14_AuditMetaValuesAreSwept(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)

	gw.log(audit.Event{
		APIKey: maskKey(longSecretKey),
		Action: "denied",
		Rule:   "some-rule",
		Meta: map[string]any{
			"upstream_detail": "rejected for " + piiMarker,
			"nested":          map[string]any{"deep": piiMarker},
			"count":           float64(7),
		},
	})

	got := buf.String()
	t.Logf("audit=%.400s", got)
	if strings.Contains(got, piiMarker) {
		t.Errorf("BL-14 LEAK: PII nested in ev.Meta reached the audit log unswept: %s", got)
	}
	// Numeric and structural values must survive; a sweep that emptied Meta would
	// pass the leak assertion and destroy the diagnostic.
	if !strings.Contains(got, `"count":7`) {
		t.Errorf("a numeric Meta value was destroyed by the sweep: %s", got)
	}
}

// ---------------------------------------------------------------------------
// M5: when the Redactor cannot be trusted, free text is DROPPED, not written raw.
//
// The condition that triggers the fail-safe is "the Redactor panics", and the
// field that actually carries client content at that moment is ev.Model — which
// is read from the RAW request before any sweep. The first round-7 test used a
// clean model name, so there was nothing raw to drop and the mutation survived.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// M11: a refused redirect's Location is upstream-controlled and may itself carry
// reflected material, so it must be swept before entering the audit record.
// ---------------------------------------------------------------------------

func TestBL16_RedirectLocationIsSweptBeforeAuditing(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A hostile upstream reflects the credential/PII it just received into the
		// redirect target — the same echo capability as the Okta BL-1b class.
		w.Header().Set("Location", "https://collector.example/?q="+piiMarker)
		w.WriteHeader(http.StatusTemporaryRedirect)
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

	got := buf.String()
	t.Logf("status=%d audit=%.300s", rr.Code, got)

	if strings.Contains(got, piiMarker) {
		t.Errorf("BL-16 LEAK: the upstream's redirect target was recorded in the "+
			"audit trail verbatim, so the trail itself became the leak channel: %s", got)
	}
	// The refusal must still be attributable, and the location still recorded in
	// redacted form — an operator needs to know a redirect was attempted.
	if !strings.Contains(got, `"rule":"upstream-redirect"`) {
		t.Errorf("the refused redirect is not attributable: %s", got)
	}
	if !strings.Contains(got, "location") {
		t.Errorf("the redirect target was dropped entirely instead of redacted, so "+
			"the operator cannot see that a redirect was attempted: %s", got)
	}
	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected fail-closed 502, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// M3: the panic VALUE must never be formatted into the record — pinned with a
// secret the redactor cannot recognise.
//
// With the chokepoint sweeping Reason, interpolating the panic value is caught by
// the OTHER layer whenever the value happens to contain something the redactor
// matches. That is defence-in-depth, not a reason to leave the interpolation in:
// a panic value can carry a credential shape no PII regex is configured for, and
// then the type-only construction is the only thing between the value and the
// tamper-evident log. This test uses exactly such a secret.
// ---------------------------------------------------------------------------

// emailOnlyRedactor recognises email addresses and nothing else, modelling a
// deployment whose redactor is scoped to one entity type.
type emailOnlyRedactor struct{}

func (emailOnlyRedactor) Redact(text string) (string, []string) {
	if strings.Contains(text, "@") {
		return "[REDACTED:EMAIL]", []string{"EMAIL"}
	}
	return text, nil
}

// secretShapedPanicValue is NOT email-shaped, so emailOnlyRedactor passes it
// through untouched. If the panic value were interpolated into Reason, this exact
// string would land in the audit log.
const secretShapedPanicValue = "SSWS-abcdef0123456789-cannot-be-recognised"

type secretPanicRedactor struct{}

func (secretPanicRedactor) Redact(text string) (string, []string) {
	panic("backend exploded: " + secretShapedPanicValue)
}

func TestBL14_PanicValueNeverFormattedEvenWhenRedactorCannotMatchIt(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = secretPanicRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	got := buf.String()
	t.Logf("status=%d audit=%.300s", rr.Code, got)

	if strings.Contains(got, secretShapedPanicValue) {
		t.Errorf("BL-14(ii) LEAK: the panic VALUE was formatted into the audit "+
			"record. The redactor cannot match this secret shape, so the chokepoint "+
			"sweep did not catch it and recording only the TYPE was the sole "+
			"defence: %s", got)
	}
	// Even a fragment is a finding: a partial credential at a known position is
	// recoverable, which is the standard this repo applies elsewhere.
	for n := len(secretShapedPanicValue) - 1; n >= 8; n-- {
		if strings.Contains(got, secretShapedPanicValue[:n]) {
			t.Errorf("%d of %d characters of the panic value survived into the "+
				"audit record: %s", n, len(secretShapedPanicValue), got)
			break
		}
	}
	if !strings.Contains(got, `"rule":"handler-panic"`) {
		t.Errorf("the incident record was lost: %s", got)
	}
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// The type must still be recorded — that is the triage signal, and a type name
// comes from a closed vocabulary that cannot carry content.
func TestBL14_PanicTypeIsRecordedForEachValueKind(t *testing.T) {
	cases := map[string]any{
		"string":       "boom",
		"error":        io.ErrUnexpectedEOF,
		"runtime-like": 42,
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			got := panicTypeName(rec)
			if got == "" {
				t.Fatalf("panicTypeName returned empty for %T", rec)
			}
			// The value itself must never appear in the type name.
			switch v := rec.(type) {
			case string:
				if strings.Contains(got, v) {
					t.Errorf("the panic VALUE leaked through panicTypeName: %q", got)
				}
			}
			if strings.Contains(got, "boom") || strings.Contains(got, "42") {
				t.Errorf("panicTypeName formatted the value instead of the type: %q", got)
			}
			t.Logf("%s -> %q", name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Mirror check for the new budget denials: an unlimited configuration must not
// start refusing. Denying when nothing was configured would break every default
// deployment and would be indistinguishable from enforcement in a leak test.
// ---------------------------------------------------------------------------

func TestBL15_NoBudgetConfiguredNeverDenies(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK,
		`{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":1000000}}`)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	// No budget at all — the honest "unthrottled by design" configuration.
	gw.Limiter = ratelimit.New(ratelimit.Limits{RequestsPerMinute: 1000})

	if gw.Limiter.HasBudget() {
		t.Fatal("test setup: HasBudget must be false with no budget configured")
	}
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("X-API-Key", "test-key")
		gw.ServeHTTP(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			t.Errorf("request %d was denied with no budget configured — "+
				"enforcement must not fire when nothing was claimed: %s", i, rr.Body.String())
		}
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, rr.Code)
		}
	}
}
