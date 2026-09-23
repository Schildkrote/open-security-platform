package proxy

// Round-8, BL-20 / BL-21 / BL-22: pins for the three behaviour changes this round
// introduced. A fix that is not pinned is a fix that silently reverts — that is the
// whole lesson of rounds 5 through 8, where the same class came back because the
// guard lived in a reviewer's clone instead of the repo.
//
// These reproduce the reviewer's own observations wherever possible, so a regression
// reproduces the reported symptom rather than merely failing an assertion about an
// internal.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/ratelimit"
	"github.com/Schildkrote/open-ai-gateway/internal/redactor"
)

// ---------------------------------------------------------------------------
// BL-20: omitting `usage` must not make a completion free against the budget.
// ---------------------------------------------------------------------------

// TestBL20_OmittingUsageCannotBypassTheTokenBudget is the reviewer's
// TestR8_VULN_JSONWithoutUsageBypassesBudget, landed in the repo. Their observation:
// with BudgetTokens=100 and a valid JSON completion that simply has no `usage` field,
// 5/5 requests returned 200 with `tokens recorded=0`, so the budget never tripped.
//
// `usage` is entirely upstream-controlled, which makes this a bypass available to a
// hostile provider for free. The fix charges a positive estimate, so the cumulative
// budget advances and eventually denies.
func TestBL20_OmittingUsageCannotBypassTheTokenBudget(t *testing.T) {
	// A valid completion with NO usage field, exactly as the reviewer sent it.
	noUsage := `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`
	up := serveJSON(t, noUsage)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	// A budget that a handful of estimated completions must exhaust.
	gw.Limiter = newBudgetLimiter(100)

	served, denied := 0, 0
	for i := 0; i < 5; i++ {
		rr := post(t, gw, "gpt-4o", "hello")
		if rr.Code == http.StatusOK {
			served++
		} else if rr.Code == http.StatusTooManyRequests {
			denied++
		} else {
			t.Fatalf("request %d got unexpected status %d: %s", i, rr.Code, rr.Body.String())
		}
	}

	toks, _ := gw.Limiter.Usage("test-key")
	t.Logf("served=%d denied=%d tokens-recorded=%d (budget=100)", served, denied, toks)

	if toks == 0 {
		t.Errorf("BL-20 BYPASS: 5 completions were served against a 100-token budget " +
			"and ZERO tokens were recorded. Omitting `usage` makes consumption free, " +
			"and `usage` is upstream-controlled.")
	}
	if denied == 0 {
		t.Errorf("BL-20 BYPASS: the budget never tripped across 5 unaccountable "+
			"completions (served=%d, denied=%d, tokens=%d)", served, denied, toks)
	}
	if served == 0 {
		t.Errorf("over-correction: NO completion was served. The gateway must still " +
			"work for providers that legitimately omit usage; only the cumulative " +
			"budget should eventually deny, not the first request.")
	}
	if !strings.Contains(buf.String(), `"usage":"estimated"`) {
		t.Errorf("the audit trail does not say the figure was an estimate, so an "+
			"operator cannot tell a real provider figure from a gateway guess: %s",
			buf.String())
	}
	// A record must never claim a provider figure it did not receive.
	if strings.Contains(buf.String(), `"usage":"unparseable"`) {
		t.Errorf("BL-20: the completion was still recorded as unaccountable rather "+
			"than charged an estimate: %s", buf.String())
	}
}

// TestBL20_NonJSONBodyCannotBypassBudgetWithRedactionOff is the reviewer's
// TestR8_VULN_NonJSONBodyBypassesBudgetWithRedactionOff. The bypass must not depend
// on the redaction setting: budget and redactor are independent guarantees, and
// gating accounting on `RedactResponse` lets an operator turn one off and silently
// lose the other.
func TestBL20_NonJSONBodyCannotBypassBudgetWithRedactionOff(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// A non-JSON 2xx body: no usage figure is extractable at all.
		_, _ = io.WriteString(w, strings.Repeat("completion text ", 40))
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.RedactResponse = false // the reviewer's configuration
	gw.Limiter = newBudgetLimiter(100)

	for i := 0; i < 3; i++ {
		rr := post(t, gw, "gpt-4o", "hello")
		t.Logf("request %d status=%d", i, rr.Code)
	}
	toks, _ := gw.Limiter.Usage("test-key")
	t.Logf("tokens-recorded=%d with RedactResponse=false", toks)

	if toks == 0 {
		t.Errorf("BL-20 BYPASS: non-JSON completions were served with zero tokens " +
			"recorded while response redaction was OFF. Accounting must not be gated " +
			"on a redaction setting.")
	}
	if !strings.Contains(buf.String(), `"usage":"estimated"`) {
		t.Errorf("the non-JSON path did not record an estimated charge: %s", buf.String())
	}
}

// TestBL20_ErrorResponseIsNotBilledAsACompletion pins the OTHER direction of the
// BL-20 fix, and it was found by review of my own diff rather than by a failing test:
// the first cut charged an estimate at EVERY status, so an upstream 429 or 500 whose
// body happened to be JSON without a usage figure billed the caller for a request that
// failed. None of the 127 tests in the suite caught it, which is precisely why it gets
// a pin.
//
// The pre-BL-20 code stated this invariant outright: "an error response is not a
// billable completion, so zero tokens here is correct rather than a bypass." Closing
// the bypass must not break that. Billing for a failed request makes the budget punish
// clients for upstream errors, which is its own kind of lie — and a hostile upstream
// could burn a caller's budget by returning error pages.
func TestBL20_ErrorResponseIsNotBilledAsACompletion(t *testing.T) {
	// JSON error bodies with no usage figure, at the statuses an upstream actually
	// uses to report a failure.
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			errBody := `{"error":{"message":"upstream is unhappy","type":"server_error"}}`
			up := serveStatusAndBody(t, status, errBody)

			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL
			gw.Limiter = newBudgetLimiter(100)

			rr := post(t, gw, "gpt-4o", "hello")
			toks, _ := gw.Limiter.Usage("test-key")
			t.Logf("status=%d served=%d tokens-recorded=%d audit=%.240s",
				status, rr.Code, toks, buf.String())

			if toks != 0 {
				t.Errorf("BL-20 over-charging: an upstream %d error was billed %d tokens. "+
					"An error response is not a billable completion, so charging it lets "+
					"a hostile upstream burn a caller's budget with error pages.", status, toks)
			}
			// The client must still SEE the upstream error — refusing to serve a
			// diagnostic would be its own regression.
			if rr.Code == http.StatusTooManyRequests && status != http.StatusTooManyRequests {
				t.Errorf("the upstream's %d was replaced by a gateway 429, hiding the "+
					"real failure from the caller", status)
			}
			// And the record must say accounting was unavailable rather than claiming
			// a figure.
			if !strings.Contains(buf.String(), `"usage":"unparseable"`) {
				t.Errorf("an error response with no usage figure was not recorded as "+
					"unparseable: %s", buf.String())
			}
		})
	}
}

// TestBL20_SuccessfulCompletionIsStillBilled is the positive control for the test
// above. Without it, "charge nothing on errors" could pass by charging nothing at
// all — the exact BL-20 bypass — and the pair of tests would be vacuous together.
func TestBL20_SuccessfulCompletionIsStillBilled(t *testing.T) {
	noUsage := `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`
	up := serveJSON(t, noUsage)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Limiter = newBudgetLimiter(100000) // large enough not to deny

	rr := post(t, gw, "gpt-4o", "hello")
	toks, _ := gw.Limiter.Usage("test-key")
	t.Logf("status=%d tokens-recorded=%d", rr.Code, toks)

	if rr.Code != http.StatusOK {
		t.Fatalf("a valid completion should be served, got %d", rr.Code)
	}
	if toks <= 0 {
		t.Errorf("BL-20 BYPASS: a successful completion with no usage figure was "+
			"charged %d tokens; it must be charged a positive estimate or omitting "+
			"usage is free again", toks)
	}
}

// TestBL20_EstimateIsMonotonicAndNeverZero pins the properties the estimate exists to
// have. If it can return zero, the bypass is back; if it is not monotonic in body
// size, a provider can shrink its bill by reformatting.
func TestBL20_EstimateIsMonotonicAndNeverZero(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"one-byte", "x"},
		{"small", `{"a":1}`},
		{"medium", strings.Repeat("y", 400)},
		{"large", strings.Repeat("z", 4000)},
	}
	var prev int64 = -1
	for _, c := range cases {
		got := estimateTokens([]byte(c.body))
		t.Logf("%-8s len=%-5d tokens=%d", c.name, len(c.body), got)
		if got <= 0 {
			t.Errorf("estimateTokens(%s) = %d; an estimate of zero is the BL-20 bypass "+
				"in a different costume — the completion would be free", c.name, got)
		}
		if got < prev {
			t.Errorf("estimateTokens is NOT monotonic: %s (len %d) = %d but a smaller "+
				"body estimated %d; a provider could shrink its bill by reformatting",
				c.name, len(c.body), got, prev)
		}
		prev = got
	}
	// Roughly 4 bytes per token, so a 4000-byte body should land near 1000.
	if got := estimateTokens([]byte(strings.Repeat("z", 4000))); got != 1000 {
		t.Errorf("estimateTokens(4000 bytes) = %d, want 1000 (4 bytes/token)", got)
	}
}

// ---------------------------------------------------------------------------
// BL-21: an injected client must not silently re-open BL-16.
// ---------------------------------------------------------------------------

// TestBL21_InjectedClientDoesNotReopenRedirectExfiltration is the reviewer's
// TestR8_PROBE_CustomClientHeaderArrival, landed in the repo. They reproduced it
// end-to-end: a caller-supplied `&http.Client{}`, Authorize attaching a credential, a
// hostile upstream 307 to a collector — and the collector received BOTH
// `Authorization` and `X-Api-Key` verbatim, because Go strips only Authorization
// cross-host and only since 1.19.
//
// Gateway and Authorize are exported, so this is a live API hazard: the natural thing
// for a Phase 3 connector author to write is `gw.Client = &http.Client{Timeout: t}`,
// which previously disabled the redirect guard with no warning.
func TestBL21_InjectedClientDoesNotReopenRedirectExfiltration(t *testing.T) {
	var hits int
	var gotAuth, gotKey string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", collector.URL+"/exfil")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	providerSecret := detectableKeyShape()
	gw.Authorize = func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+providerSecret)
		r.Header.Set("X-Api-Key", providerSecret)
	}

	// THE POINT OF THE TEST: a natural injected client with no CheckRedirect. This
	// is what a caller writes without thinking about redirects at all.
	gw.Client = &http.Client{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	t.Logf("status=%d collector-hits=%d auth=%q key=%q", rr.Code, hits, gotAuth, gotKey)

	if hits != 0 {
		t.Errorf("BL-21 NOT FIXED: the gateway followed the redirect to an "+
			"attacker-controlled collector (%d hits) using the INJECTED client, "+
			"carrying provider credentials", hits)
	}
	if strings.Contains(gotAuth, providerSecret) || strings.Contains(gotKey, providerSecret) {
		t.Errorf("BL-21 CREDENTIAL EXFIL: the collector received auth=%q key=%q", gotAuth, gotKey)
	}
	if rr.Code != http.StatusBadGateway {
		t.Errorf("a refused redirect should fail closed with 502, got %d", rr.Code)
	}
	if strings.Contains(buf.String(), providerSecret) {
		t.Errorf("the provider credential reached the audit trail: %s", buf.String())
	}
}

// TestBL21_InjectedClientKeepsItsOtherFields proves the wrapping is surgical. If the
// guard were implemented by DISCARDING the caller's client, a connector's Timeout,
// Transport and Jar would silently vanish — a functional regression nobody asked for.
func TestBL21_InjectedClientKeepsItsOtherFields(t *testing.T) {
	calls := 0
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(okJSONResponse)),
			Request:    r,
		}, nil
	})

	gw := newTestGateway(t, nil, &bytes.Buffer{})
	gw.Client = &http.Client{Transport: transport}

	got := gw.client()
	if got == nil {
		t.Fatal("client() returned nil for an injected client")
	}
	if got.CheckRedirect == nil {
		t.Errorf("BL-21 NOT FIXED: the injected client was handed back with no " +
			"redirect policy, so it follows redirects and re-opens BL-16")
	}
	if got.Transport == nil {
		t.Errorf("the caller's Transport was DISCARDED by the wrapping; the guard must " +
			"be surgical and preserve every other field")
	}
	// The preserved transport must actually be used.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okJSONResponse))
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL
	rr := post(t, gw, "gpt-4o", "hello")
	if calls == 0 {
		t.Errorf("the injected Transport was never used (status %d); the client was "+
			"replaced rather than wrapped", rr.Code)
	}
}

// TestBL21_ExplicitCheckRedirectIsRespected pins the deliberate opt-out. A caller who
// genuinely wants redirect handling supplies their own CheckRedirect, and the gateway
// must not override an explicit decision — otherwise the wrapping would be
// indistinguishable from ignoring the caller entirely.
func TestBL21_ExplicitCheckRedirectIsRespected(t *testing.T) {
	var used bool
	gw := newTestGateway(t, nil, &bytes.Buffer{})
	gw.Client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			used = true
			return nil // follow
		},
	}
	got := gw.client()
	if got != gw.Client {
		t.Errorf("a client with an explicit CheckRedirect was re-wrapped; the opt-in " +
			"must be respected")
	}
	if got.CheckRedirect == nil {
		t.Fatal("lost the caller's CheckRedirect")
	}
	// Invoke it to confirm it is the caller's function, not a wrapper around ours.
	_ = got.CheckRedirect(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), nil)
	if !used {
		t.Errorf("the caller's CheckRedirect was replaced rather than preserved")
	}
}

// TestBL21_NilClientStillRefusesRedirects guards the default path against the
// wrapping change. It must stay identical to the pre-BL-21 behaviour: noFollowClient
// refuses, and the returned client is reused rather than rebuilt per call.
func TestBL21_NilClientStillRefusesRedirects(t *testing.T) {
	gw := newTestGateway(t, nil, &bytes.Buffer{})
	gw.Client = nil
	first := gw.client()
	if first.CheckRedirect == nil {
		t.Fatal("the default client lost its redirect refusal")
	}
	if second := gw.client(); second != first {
		t.Errorf("client() rebuilt the default client on each call; it should return " +
			"the shared noFollowClient")
	}
	// And it actually refuses.
	err := first.CheckRedirect(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), nil)
	if err != http.ErrUseLastResponse {
		t.Errorf("default CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

// ---------------------------------------------------------------------------
// BL-22: origin-chosen free text in a STANDARD header must be swept.
// ---------------------------------------------------------------------------

// TestBL22_LocationOnASuccessIsSweptNotServedVerbatim is the reviewer's probe A:
// a hostile upstream answers 200 with a Location carrying a credential, and before
// this round it reached the client byte-for-byte. The same header on a 3xx WAS swept
// by the BL-16 redirect path, so the code already treated the value as dangerous and
// merely disagreed with itself about which status makes it dangerous — a status the
// upstream also controls.
func TestBL22_LocationOnASuccessIsSweptNotServedVerbatim(t *testing.T) {
	// A provider credential in a shape this gateway's REAL detector recognises
	// (OPENAI_KEY: `sk-[A-Za-z0-9]{20,}`). The round-8 reviewer used an
	// "SSWS-..."-shaped canary, but there is no SSWS pattern in internal/redact, so
	// that string is undetectable by construction here and would fail regardless of
	// the code. Using a detectable credential also lets this test run against the
	// DEFAULT redactor — the production path — rather than a mock, which is a
	// stronger guarantee than injecting shapeRedactor.
	// A provider credential in a shape this gateway's REAL detector recognises
	// (OPENAI_KEY: `sk-[A-Za-z0-9]{20,}`), built by detectableKeyShape() rather than
	// written as a literal — see that helper for why a literal here is a trap.
	providerSecret := detectableKeyShape()
	target := "https://attacker.example/collect?tok=" + providerSecret

	// Every status the reviewer noted is upstream-controlled, so none of them can be
	// the thing that decides whether a value is safe.
	for _, status := range []int{http.StatusOK, http.StatusCreated,
		http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Location", target)
				w.Header().Set("X-Model-Output", piiMarker)
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"id":"x","choices":[]}`))
			}))
			t.Cleanup(up.Close)

			var auditBuf bytes.Buffer
			gw := newTestGateway(t, nil, &auditBuf)
			gw.UpstreamURL = up.URL
			// No Redactor injected: the DEFAULT regex detector is the production
			// path and the stronger thing to test.

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
				strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
			req.Header.Set("X-API-Key", longSecretKey)
			gw.ServeHTTP(rr, req)

			got := rr.Header().Get("Location")
			t.Logf("status=%d Location=%q", status, got)
			if got == "" {
				t.Errorf("Location was dropped entirely; sweeping a value is preferable " +
					"to deleting the header, since a client may rely on its presence")
			}
			if strings.Contains(got, providerSecret) {
				t.Errorf("BL-22 LEAK: a hostile upstream's Location reached the client "+
					"carrying a credential verbatim at status %d: %q", status, got)
			}
			if strings.Contains(rr.Header().Get("X-Model-Output"), piiMarker) {
				t.Errorf("control header was not swept either (BL-12 regression)")
			}
			if !strings.Contains(auditBuf.String(), "resp_hdr:") {
				t.Errorf("the header redaction was not recorded in the audit trail: %s",
					auditBuf.String())
			}
		})
	}
}

// TestBL22_OriginChosenFreeTextHeadersAreAllSwept covers the class, not one member.
// BL-22's point is that the spare list's criterion ("part of the HTTP protocol
// vocabulary") was wrong: several standard headers carry origin-chosen free text or
// URIs. Each one is exercised, because fixing only Location is the member-of-class
// patch this round exists to avoid.
func TestBL22_OriginChosenFreeTextHeadersAreAllSwept(t *testing.T) {
	headers := map[string]string{
		"Location":            "https://attacker.example/c?tok=" + piiMarker,
		"Content-Location":    "/files/" + piiMarker,
		"Content-Disposition": `attachment; filename="` + piiMarker + `.txt"`,
		"Warning":             `199 agent "` + piiMarker + `"`,
		"Server":              "nginx/" + piiMarker,
		"Etag":                `"` + piiMarker + `"`,
	}

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"x","choices":[]}`))
	}))
	t.Cleanup(up.Close)

	var auditBuf bytes.Buffer
	gw := newTestGateway(t, nil, &auditBuf)
	gw.UpstreamURL = up.URL
	gw.Redactor = shapeRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	for h := range headers {
		v := rr.Header().Get(h)
		t.Logf("%-20s %q", h, v)
		if strings.Contains(v, piiMarker) {
			t.Errorf("BL-22 LEAK: standard header %s served origin-chosen free text "+
				"carrying PII verbatim: %q", h, v)
		}
		// Etag is the ONE header where absence is not merely acceptable but
		// REQUIRED: it is a validator describing the upstream body, so when the
		// body is rewritten the gateway deletes it (and Last-Modified, and sets
		// no-store) rather than letting a client cache redacted bytes under an
		// identity that maps to the unredacted ones. Sweeping it AND then dropping
		// it are both correct outcomes; only serving it raw is a leak.
		if v == "" && h != "Etag" {
			t.Errorf("header %s was dropped rather than swept; redacting a value is "+
				"preferable to deleting the header, since a client may rely on its "+
				"presence", h)
		}
	}
}

// TestBL22_ProtocolMetadataHeadersAreStillSpared is the over-redaction control. BL-22
// must not turn into "sweep everything": a numeric or closed-vocabulary header the
// client needs to parse the response must survive untouched, or the gateway breaks
// interop for no security gain.
func TestBL22_ProtocolMetadataHeadersAreStillSpared(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Ratelimit-Remaining-Tokens", "12345")
		w.Header().Set("X-Request-Id", "req-abc-123")
		w.Header().Set("Openai-Processing-Ms", "42")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"x","choices":[]}`))
	}))
	t.Cleanup(up.Close)

	gw := newTestGateway(t, nil, &bytes.Buffer{})
	gw.UpstreamURL = up.URL
	gw.Redactor = shapeRedactor{}

	rr := post(t, gw, "gpt-4o", "hello")
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type was rewritten, which breaks the client's ability to "+
			"parse the body: %q", ct)
	}
	for _, h := range []struct{ name, want string }{
		{"X-Ratelimit-Remaining-Tokens", "12345"},
		{"X-Request-Id", "req-abc-123"},
		{"Openai-Processing-Ms", "42"},
	} {
		if got := rr.Header().Get(h.name); got != h.want {
			t.Errorf("BL-22 over-redaction: protocol metadata %s = %q, want %q; "+
				"mangling stack-generated figures breaks tracing and interop",
				h.name, got, h.want)
		}
	}
}

// TestBL22_DetectorCoverageBoundaryIsDocumented records an honest residual
// limitation that BL-22 does NOT fix, so nobody mistakes the header fix for complete
// credential coverage.
//
// BL-22 makes origin-chosen standard headers get SWEPT. Sweeping only removes what
// the configured redactor's patterns recognise. internal/redact has patterns for
// OPENAI_KEY, AWS, GitHub, Slack, JWT and private keys — but NO pattern for an
// Okta SSWS token (`^00[a-zA-Z0-9-_]{40}$`). So a hostile upstream can still put an
// SSWS credential in a Location header and it will be served to the client, because
// the detector does not know that shape.
//
// This is a DETECTOR-COVERAGE gap, not a chokepoint gap: the value is now inspected,
// it just is not recognised. Recording it as a test means the gap is visible and
// falsifiable — adding an SSWS pattern to internal/redact makes this test fail,
// which is the signal to update the documentation rather than a regression.
func TestBL22_DetectorCoverageBoundaryIsDocumented(t *testing.T) {
	const sswsShaped = "SSWS-round8-secret-0123456789abcdef"

	cleaned, kinds := redactor.Regex{}.Redact("tok=" + sswsShaped)
	t.Logf("default redactor on an SSWS-shaped token: cleaned=%q kinds=%v", cleaned, kinds)

	if len(kinds) > 0 && !strings.Contains(cleaned, sswsShaped) {
		t.Errorf("the default redactor NOW recognises an SSWS-shaped token (%v). That is "+
			"an improvement — update this test and the BL-22 documentation to say the "+
			"coverage gap is closed rather than leaving a stale claim.", kinds)
	}
	if strings.Contains(cleaned, sswsShaped) {
		t.Logf("confirmed: an SSWS-shaped credential survives the default detector. " +
			"BL-22 ensures the header is INSPECTED; recognising this credential shape " +
			"requires adding a pattern to internal/redact (or configuring Presidio).")
	}

	// And the contrast: a shape the detector DOES know is removed from the same
	// position, proving the header path works and it is only the pattern that is
	// missing.
	knownShape := detectableKeyShape()
	cleaned2, kinds2 := redactor.Regex{}.Redact("tok=" + knownShape)
	if strings.Contains(cleaned2, knownShape) {
		t.Errorf("control failed: a recognisable OPENAI_KEY shape survived the default "+
			"detector (%q, kinds=%v), so this test cannot distinguish a coverage gap "+
			"from a broken sweep", cleaned2, kinds2)
	}
	t.Logf("control: OPENAI_KEY shape removed, kinds=%v", kinds2)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// detectableKeyShape builds a credential the DEFAULT production redactor actually
// recognises, as `"sk-"` followed by 36 alphanumeric characters, matching
// internal/redact's OPENAI_KEY pattern `sk-[A-Za-z0-9]{20,}`.
//
// It is built from parts rather than written as a literal for a reason that cost
// three failed attempts at this test:
//
//  1. A literal credential-shaped string in source gets ELIDED by display/secret
//     masking layers on the way to disk. Earlier versions of this file contained
//     `sk-liv` + "..." + `7890` — the ellipsis was written into the SOURCE, so the
//     value the redactor saw was 13 characters with dots in it and matched nothing.
//     The test then reported a "leak" that was really an undetectable canary.
//  2. `sk-live-...` also fails: the hyphen after "live" is outside [A-Za-z0-9], so
//     only 4 alnum characters precede it and {20,} never matches.
//  3. An "SSWS-..." shaped token fails too, because internal/redact has no Okta
//     pattern — see TestBL22_DetectorCoverageBoundaryIsDocumented, which records that
//     as an honest coverage gap rather than pretending it is fixed.
//
// Building the value at runtime also keeps credential-shaped literals out of a
// public AGPL repository.
func detectableKeyShape() string {
	return "sk-" + strings.Repeat("9", 36)
}

// roundTripperFunc adapts a function to http.RoundTripper so a test can supply a
// Transport without spinning up a server.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// newBudgetLimiter builds a limiter with an ACTIVE cumulative token budget and
// generous per-minute limits, so only the budget can deny. BudgetTokens defaults to
// 1_000_000 in production config and is not operator-configurable, which is why
// BL-20's fix had to be an estimate rather than a refusal: refusing would break the
// default configuration outright.
func newBudgetLimiter(budget int64) *ratelimit.Limiter {
	return ratelimit.New(ratelimit.Limits{RequestsPerMinute: 100000, BudgetTokens: budget})
}

// TestBL22_SweepIsSurgicalSoInteropSurvives replaces the earlier
// TestBL22_SpareListIsLoadbearing, which pinned a decision round 9 overturned.
//
// THE DECISION THAT WAS REVERSED. This test used to assert that a header on the spare
// list (X-Request-Id, X-Correlation-Id) keeps a detector-recognisable value verbatim,
// on the reasoning that sweeping correlation ids "breaks tracing for no security gain".
// Round 9 showed that reasoning is wrong twice over:
//
//  1. Provenance cannot be inferred from the NAME. Nothing validates the grammar of a
//     request id, so a hostile origin sets those bytes — exactly the fallacy BL-22
//     debunked for the status code. Leaving it spared is an unswept channel.
//  2. The "no security gain" half assumed sweeping costs interop. It does not, because
//     the sweep is SURGICAL: it rewrites a value only when a detector reports a finding.
//     A legitimate request id passes through byte-identical.
//
// So the guarantee worth pinning is the surgical one, in both directions: a CLEAN
// protocol-metadata value must survive untouched (that is what keeps tracing and body
// parsing working), and a value carrying recognised sensitive data must be swept
// regardless of how standard the header name is.
//
// HONEST RESIDUAL COST: if a legitimate correlation id happens to match a detector —
// an id containing an '@', or one that looks like a 40-char SSWS token — it will be
// mangled and that trace link breaks. Accepted deliberately: mangling a suspicious
// identifier is cheaper than handing a hostile origin an unswept text channel, and
// clean ids are unaffected.
func TestBL22_SweepIsSurgicalSoInteropSurvives(t *testing.T) {
	const poisoned = "req-" + piiMarker // matches the EMAIL detector
	const cleanID = "req-7f3a9c2e-1b4d-4e8a"

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", cleanID)                      // must survive byte-identical
		w.Header().Set("X-Correlation-Id", cleanID)                  // must survive byte-identical
		w.Header().Set("X-Ratelimit-Remaining-Tokens", "12345")      // numeric, must survive
		w.Header().Set("X-Poisoned-Trace", poisoned)                 // must be swept
		w.Header().Set("Location", "https://x.example/?r="+poisoned) // must be swept
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(okJSONResponse))
	}))
	t.Cleanup(up.Close)

	gw := newTestGateway(t, nil, &bytes.Buffer{})
	gw.UpstreamURL = up.URL
	gw.Redactor = shapeRedactor{}

	rr := post(t, gw, "gpt-4o", "hello")

	// 1. INTEROP: clean protocol metadata survives byte-for-byte. This is the real
	//    guarantee the spare list used to be argued for, and it holds WITHOUT the
	//    spare list because the sweep only acts on findings.
	for _, h := range []string{"X-Request-Id", "X-Correlation-Id"} {
		if got := rr.Header().Get(h); got != cleanID {
			t.Errorf("over-redaction: clean %s = %q, want %q byte-identical. A surgical "+
				"sweep must not touch values no detector matched, or tracing breaks",
				h, got, cleanID)
		}
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type was rewritten to %q, which breaks the client's ability "+
			"to parse the body", got)
	}
	if got := rr.Header().Get("X-Ratelimit-Remaining-Tokens"); got != "12345" {
		t.Errorf("a numeric provider header was rewritten to %q", got)
	}

	// 2. SECURITY: a recognised sensitive value is swept no matter how standard the
	//    header NAME is.
	for _, h := range []string{"X-Poisoned-Trace", "Location"} {
		got := rr.Header().Get(h)
		if strings.Contains(got, piiMarker) {
			t.Errorf("BL-22 LEAK: %s served origin-chosen text carrying PII verbatim: %q",
				h, got)
		}
		if got == "" {
			t.Errorf("%s was dropped entirely; sweeping the value is preferable to "+
				"deleting the header", h)
		}
	}
}

// TestBL22_ServedHeadersAreStillValidJSON guards a subtle consequence of sweeping more
// headers: the response must remain structurally valid for the client.
func TestBL22_ServedHeadersAreStillValidJSON(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "https://x.example/?a="+piiMarker)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(okJSONResponse))
	}))
	t.Cleanup(up.Close)

	gw := newTestGateway(t, nil, &bytes.Buffer{})
	gw.UpstreamURL = up.URL
	gw.Redactor = shapeRedactor{}

	rr := post(t, gw, "gpt-4o", "hello")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
		t.Errorf("the served body is no longer valid JSON after the header sweep: %v", err)
	}
	if cl := rr.Header().Get("Content-Length"); cl != "" {
		// If a Content-Length is present it must describe the SERVED bytes, not the
		// upstream's. This is the round-6 Content-Length fix; re-pinned here because
		// BL-22 adds more header rewriting.
		if n, _ := strconv.Atoi(cl); n != rr.Body.Len() {
			t.Errorf("Content-Length %d does not match the %d bytes actually served", n, rr.Body.Len())
		}
	}
}
