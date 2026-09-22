package proxy

// Round-7, part 3: faithful pins for the fail-safe path.
//
// The first attempt at pinning BL-14's fail-safe was VACUOUS, and the mutation
// battery is what exposed it. It used a panicking Redactor with a PII model name
// and asserted the log stayed clean — but the panic handler builds a FRESH
// audit.Event{Action:"error", Rule:"handler-panic", ...} that has no Model field
// at all, so there was nothing raw to drop. Removing the fail-safe changed
// nothing, the test still passed, and the mutation survived.
//
// The path that actually carries a raw client-controlled Model into g.log is a
// POLICY DENY: ev is built from the raw request (ev.Model = stringField(parsedReq,
// "model")) and logged at the deny site BEFORE any body redaction runs. With a
// Redactor that panics, that g.log call enters sweepAuditText, the sweep is
// unavailable, and the fail-safe must drop the field rather than write it raw.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/policy"
)

// TestBL14_FailSafeDropsRawModelOnPolicyDeny pins the fail-safe on the one path
// where ev.Model genuinely holds raw client input at the moment the sweep fails.
func TestBL14_FailSafeDropsRawModelOnPolicyDeny(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer

	// A rule that DENIES, so the deny site logs ev — carrying the raw Model — and
	// a Redactor that panics, so sweepAuditText cannot verify the event clean.
	// ContentRe is the only matcher set, so the rule matches any model
	// (ModelPattern empty = unconstrained) and denies on the content.
	rules := []policy.Rule{{
		Name:      "deny-marker",
		ContentRe: "FORBIDDEN",
		Action:    policy.Deny,
		Reason:    "marker content",
	}}
	gw := newTestGateway(t, rules, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = panickingRedactor{}

	// The model name is PII and the content trips the deny rule.
	body := `{"model":"` + piiMarker + `","messages":[{"role":"user","content":"say FORBIDDEN"}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	got := buf.String()
	t.Logf("status=%d audit=%.300s", rr.Code, got)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected the deny rule to fire (403), got %d: %s", rr.Code, rr.Body.String())
	}
	if got == "" {
		t.Fatal("the deny was not audited at all")
	}
	if strings.Contains(got, piiMarker) {
		t.Errorf("BL-14 FAIL-SAFE LEAK: the Redactor panicked so the chokepoint "+
			"could not verify the event clean, and it wrote the raw client PII "+
			"from ev.Model into the tamper-evident log. Degradation must DROP free "+
			"text, not pass it through: %s", got)
	}
	// The deny must still be identifiable — dropping Model must not drop the record.
	// policy.Deny is recorded verbatim as "deny" (ev.Action = string(dec.Action)).
	// Asserting "denied" here would be wrong: that string belongs to the gateway's
	// own refusal sites, not to a policy decision, and a test asserting the wrong
	// vocabulary fails for a reason unrelated to the property under test.
	if !strings.Contains(got, `"action":"deny"`) {
		t.Errorf("the policy denial lost its action, so the record is unfilterable: %s", got)
	}
	if !strings.Contains(got, `"audit_redaction":"unavailable"`) {
		t.Errorf("the fail-safe drop was not recorded, so an operator cannot tell a "+
			"deliberately dropped field from a missing one: %s", got)
	}
	if strings.Contains(got, longSecretKey) {
		t.Errorf("raw API key in the audit record: %s", got)
	}
}

// TestBL14_FailSafeDropsRawReasonOnPolicyDeny is the Reason half of the same
// path: ev.Reason is set from the policy decision, which can quote the matched
// content. A panicking Redactor must not let that through either.
func TestBL14_FailSafeDropsRawReasonOnPolicyDeny(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer

	// ContentRe is the only matcher set, so the rule matches any model
	// (ModelPattern empty = unconstrained) and denies on the content.
	rules := []policy.Rule{{
		Name:      "deny-marker",
		ContentRe: "FORBIDDEN",
		Action:    policy.Deny,
		Reason:    "marker content",
	}}
	gw := newTestGateway(t, rules, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = panickingRedactor{}

	body := `{"model":"m","messages":[{"role":"user","content":"FORBIDDEN ` + piiMarker + `"}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	got := buf.String()
	t.Logf("status=%d audit=%.300s", rr.Code, got)

	if strings.Contains(got, piiMarker) {
		t.Errorf("BL-14 FAIL-SAFE LEAK via ev.Reason: raw content reached the log "+
			"while the sweep was unavailable: %s", got)
	}
	if !strings.Contains(got, `"audit_redaction":"unavailable"`) {
		t.Errorf("the fail-safe drop was not recorded: %s", got)
	}
}
