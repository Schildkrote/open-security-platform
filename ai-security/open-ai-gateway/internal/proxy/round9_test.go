package proxy

// Round-9 pins: NB-1 (negative usage in ANY numeric form credits the budget) plus two
// non-blocking observations the reviewer showed were unpinned (obs 4: the non-JSON
// error-billing gate; obs 9: panic-value interpolation with a HEALTHY redactor).
//
// NB-1 is the same class as BL-20 — an upstream-controlled usage figure defeating the
// token budget — arriving through a different door. Round 9 measured it at
// tokens-recorded=-10000000 across 10 requests against a 10-token budget: because a
// negative figure CREDITS the bucket, a hostile upstream could grant unlimited free
// completions under any budget.
//
// The float64 case already rejected negatives. The string case, added later, did not.
// Fixing only the string case would have left int64, int and json.Number equally
// exposed, so the guard now lives in one function (clampUsage) that every non-float
// numeric path calls, and these tests cover every form an upstream can actually send.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNB1_NegativeUsageInAnyFormIsNeverTrusted covers every representation the JSON
// parser can produce for a usage figure. The string form is the one the reviewer
// reproduced; the others are the same hole one door over, and they are tested because
// "fixed the door that was reported" is precisely how this branch spent rounds 1-5.
func TestNB1_NegativeUsageInAnyFormIsNeverTrusted(t *testing.T) {
	forms := []struct {
		name string
		// The JSON the upstream sends. A negative figure in each shape the parser
		// can yield: string (strconv.ParseInt path) and number (float64 path).
		body string
	}{
		{"string-negative", `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":"-5000"}}`},
		{"string-negative-small", `{"id":"x","choices":[],"usage":{"total_tokens":"-1"}}`},
		{"number-negative", `{"id":"x","choices":[],"usage":{"total_tokens":-5000}}`},
		{"number-negative-float", `{"id":"x","choices":[],"usage":{"total_tokens":-0.5}}`},
		{"string-negative-padded", `{"id":"x","choices":[],"usage":{"total_tokens":"  -5000  "}}`},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			up := serveJSON(t, form.body)
			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL
			gw.Limiter = newBudgetLimiter(10)

			// The reviewer's amplification: repeat the request. If a negative figure
			// is recorded, the budget goes MORE negative each time and nothing is ever
			// denied — unlimited free completions.
			codes := make([]int, 0, 10)
			for i := 0; i < 10; i++ {
				rr := post(t, gw, "gpt-4o", "hello")
				codes = append(codes, rr.Code)
			}
			toks, _ := gw.Limiter.Usage("test-key")
			t.Logf("codes=%v tokens-recorded=%d", codes, toks)

			if toks < 0 {
				t.Errorf("NB-1 BYPASS: a negative usage figure (%s) was trusted and "+
					"CREDITED the bucket to %d. A hostile upstream can grant unlimited "+
					"free completions under any budget this way.", form.name, toks)
			}
			// Denials must eventually happen, or the budget is decorative.
			denied := 0
			for _, c := range codes {
				if c == http.StatusTooManyRequests {
					denied++
				}
			}
			if denied == 0 {
				t.Errorf("NB-1 BYPASS: 10/10 requests served against a 10-token budget "+
					"with tokens-recorded=%d — the budget never tripped", toks)
			}
			// The figure must be recorded as unaccountable, not as a real zero.
			if !strings.Contains(buf.String(), `"usage":"estimated"`) &&
				!strings.Contains(buf.String(), `"usage":"unparseable"`) {
				t.Errorf("a rejected negative usage figure left no accounting "+
					"diagnostic in the audit trail: %s", buf.String())
			}
		})
	}
}

// TestNB1_NegativeUsageIsRejectedNotClamped pins the REJECTION semantics rather than
// clamping to zero. Recording zero would claim the gateway understood a figure that is
// nonsense and would treat a hostile upstream's garbage as a legitimate free request.
// Rejecting routes it to the estimate path, so the traffic is charged instead of
// credited — the difference between a bypass and a bill.
func TestNB1_NegativeUsageIsRejectedNotClamped(t *testing.T) {
	if got, ok := clampUsage(-5000); ok {
		t.Errorf("clampUsage(-5000) = (%d, true); a negative figure must be REJECTED "+
			"(ok=false), not clamped to zero and trusted", got)
	}
	if got, ok := clampUsage(0); !ok || got != 0 {
		t.Errorf("clampUsage(0) = (%d, %v); zero is a legitimate figure and must be "+
			"accepted as zero", got, ok)
	}
	if got, ok := clampUsage(42); !ok || got != 42 {
		t.Errorf("clampUsage(42) = (%d, %v); a positive figure must pass through "+
			"unchanged", got, ok)
	}
	// TotalTokens end-to-end through the parser's string path.
	parsed := map[string]any{"usage": map[string]any{"total_tokens": "-5000"}}
	toks, ok := totalTokens(parsed)
	if ok || toks != 0 {
		t.Errorf("totalTokens on a string negative = (%d, %v), want (0, false)", toks, ok)
	}
}

// TestObs4_NonJSONErrorIsNotBilled closes the reviewer's observation 4: the JSON path's
// error-billing gate was pinned by TestBL20_ErrorResponseIsNotBilledAsACompletion, but
// mutating the NON-JSON path's gate survived the whole suite while billing a
// text/plain 500. Both paths get a pin, because a gate on one and not the other is
// exactly the asymmetry that let NB-1 through.
func TestObs4_NonJSONErrorIsNotBilled(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "upstream is unhappy: "+strings.Repeat("x", 200))
			}))
			t.Cleanup(up.Close)

			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL
			gw.Limiter = newBudgetLimiter(100000)

			rr := post(t, gw, "gpt-4o", "hello")
			toks, _ := gw.Limiter.Usage("test-key")
			t.Logf("status=%d served=%d tokens-recorded=%d", status, rr.Code, toks)

			if toks != 0 {
				t.Errorf("obs-4: a non-JSON upstream %d was billed %d tokens. An error "+
					"is not a billable completion, and a hostile upstream could burn a "+
					"caller's budget with error pages.", status, toks)
			}
			if rr.Code == http.StatusTooManyRequests && status != http.StatusTooManyRequests {
				t.Errorf("the upstream's %d was masked by a gateway 429", status)
			}
		})
	}
}

// TestObs9_PanicValueWithHealthyRedactorNeverReachesAudit closes the reviewer's
// observation 9, which is the sharper of the two. The existing panic pin uses a
// PANICKING redactor, where the fail-safe drops Reason regardless of what the panic
// handler wrote — so it cannot detect a regression in the type-only construction
// (layer 1). With a HEALTHY redactor and a panic value carrying a detector-KNOWN
// secret, interpolating the value (%v) instead of its type (%T) leaks it into the
// tamper-evident log, and the reviewer demonstrated exactly that.
//
// This pins layer 1 directly: the panic Reason must carry only a TYPE NAME.
func TestObs9_PanicValueWithHealthyRedactorNeverReachesAudit(t *testing.T) {
	// With a HEALTHY redactor the sweep (layer 2) would catch a leaked value, so this
	// test asserts the stronger property: the panic value never enters the event at
	// all, so there is nothing for layer 2 to have to catch.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okJSONResponse))
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	// A HEALTHY redactor that recognises everything, so layer 2 is fully functional
	// and the test isolates layer 1.
	gw.Redactor = shapeRedactor{}
	// A transport whose RoundTrip panics with a value containing PII.
	gw.Client = &http.Client{Transport: panickingTransport{msg: "boom " + piiMarker}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	got := buf.String()
	t.Logf("status=%d audit=%.400s", rr.Code, got)

	if got == "" {
		t.Fatal("the panic was not audited at all — the BL-14 gap is back")
	}
	if strings.Contains(got, piiMarker) {
		t.Errorf("obs-9 LEAK: the panic VALUE reached the tamper-evident log. The panic "+
			"path must record only a TYPE NAME via %%T, never %%v, because a hostile "+
			"upstream chooses the panic value: %s", got)
	}
	if !strings.Contains(got, `"panic_type"`) {
		t.Errorf("the panic type was not recorded, so an operator loses the triage "+
			"signal: %s", got)
	}
}

// panickingTransport fails RoundTrip by panicking with an attacker-chosen message,
// which is the shape a hostile upstream can produce (a malformed response that blows
// up inside a decoder, with the offending bytes in the panic value).
type panickingTransport struct{ msg string }

func (p panickingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic(p.msg)
}
