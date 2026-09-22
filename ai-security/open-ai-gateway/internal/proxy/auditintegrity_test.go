package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// BL-7 (regression introduced by the error-response exemption, found by the
// round-3 review): on a non-2xx response with a MIXED shape, the walk redacted
// the first choice, recorded resp:EMAIL on the audit event, then errored on the
// second - and the caller served the ORIGINAL bytes. Result: raw PII to the
// client under an audit line claiming it was redacted. A self-contradicting
// trail is worse than a missing one.
//
// The reviewer's exact reproduction is used here: HTTP 429 with one readable
// message carrying an email and one uninspectable choice.
// ---------------------------------------------------------------------------

const bl7MixedShape = `{"choices":[` +
	`{"message":{"role":"assistant","content":"jane.doe@example.com"}},` +
	`{"text":5}` +
	`]}`

func serveStatusAndBody(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	return up
}

// auditClaimsRedaction reports whether an audit line asserts a redaction.
func auditClaimsRedaction(audit string) bool {
	return strings.Contains(audit, `"redactions":[`) && strings.Contains(audit, "resp:")
}

func TestBL7AuditNeverClaimsARedactionTheServedBodyDisproves(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"429 rate limited", http.StatusTooManyRequests},
		{"500 upstream failure", http.StatusInternalServerError},
		{"400 bad request", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := serveStatusAndBody(t, tc.status, bl7MixedShape)
			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL

			rr := post(t, gw, "gpt-4o", "hello")
			client := rr.Body.String()
			auditLine := buf.String()
			t.Logf("status=%d client=%.220s", rr.Code, client)
			t.Logf("audit=%.400s", auditLine)

			// 1. The upstream status must survive: the diagnostic is the reason
			//    error bodies are passed through at all.
			if rr.Code != tc.status {
				t.Errorf("upstream status %d was replaced by %d, destroying the diagnostic",
					tc.status, rr.Code)
			}

			// 2. THE BL-7 INVARIANT: if the audit claims a redaction, the served
			//    bytes must not contradict it.
			if auditClaimsRedaction(auditLine) && strings.Contains(client, piiEmail) {
				t.Errorf("SELF-CONTRADICTING AUDIT: the trail claims resp:EMAIL was redacted "+
					"but the client received it raw: %s", client)
			}

			// 3. Raw PII must not be served on any status.
			if strings.Contains(client, piiEmail) {
				t.Errorf("LEAK: raw PII served to the client at status %d: %s", rr.Code, client)
			}

			// 4. The readable choice WAS redacted, so the marker should appear.
			if !strings.Contains(client, "[REDACTED:EMAIL]") {
				t.Errorf("the readable part of a mixed error response was not redacted: %s", client)
			}

			// 4b. THE OTHER HALF of the invariant. Asserting only that the audit
			// does not over-claim leaves under-reporting uncaught: a mutation that
			// deleted the kinds from the error path still served redacted bytes
			// and still passed, while the trail silently lost the record that PII
			// was removed. Both directions must hold.
			if strings.Contains(client, "[REDACTED:EMAIL]") && !auditClaimsRedaction(auditLine) {
				t.Errorf("UNDER-REPORTED: the client received redacted output but the audit "+
					"records no redaction, so the trail loses the fact that PII was removed: %s",
					auditLine)
			}

			// 5. The partial skip must still be visible in the trail.
			if !strings.Contains(auditLine, "skipped_uninspectable_error_shape") {
				t.Errorf("the uninspected portion was not audited: %s", auditLine)
			}

			// 6. Content-Length must stay truthful after the re-encode.
			if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(rr.Body.Len()) {
				t.Errorf("Content-Length=%q does not match the %d bytes written", cl, rr.Body.Len())
			}
		})
	}
}

// The error body's diagnostic text must survive the re-encode - preserving the
// status code alone would not be enough if the message were mangled.
func TestBL7ErrorDiagnosticTextSurvives(t *testing.T) {
	body := `{"error":{"message":"rate limited: 42 requests per minute exceeded","type":"rate_limit"},` +
		`"choices":[{"message":{"role":"assistant","content":"jane.doe@example.com"}},{"text":5}]}`
	up := serveStatusAndBody(t, http.StatusTooManyRequests, body)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	client := rr.Body.String()
	t.Logf("status=%d client=%.300s", rr.Code, client)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("status was not preserved: %d", rr.Code)
	}
	if !strings.Contains(client, "rate limited: 42 requests per minute exceeded") {
		t.Errorf("the diagnostic message was lost: %s", client)
	}
	if !strings.Contains(client, "rate_limit") {
		t.Errorf("the error type was lost: %s", client)
	}
	if strings.Contains(client, piiEmail) {
		t.Errorf("LEAK: PII served raw alongside the diagnostic: %s", client)
	}
}

// A fully-uninspectable ERROR response (no readable part at all) keeps its status
// and body: there is nothing to redact, so nothing must be refused either.
func TestBL7FullyUninspectableErrorKeepsStatus(t *testing.T) {
	body := `{"error":{"message":"upstream exploded"},"choices":{"weird":true}}`
	up := serveStatusAndBody(t, http.StatusBadGateway, body)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("status=%d body=%.200s audit=%.300s", rr.Code, rr.Body.String(), buf.String())

	if rr.Code != http.StatusBadGateway {
		t.Errorf("the upstream error status must pass through, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "upstream exploded") {
		t.Errorf("the diagnostic was swallowed: %s", rr.Body.String())
	}
	if auditClaimsRedaction(buf.String()) {
		t.Errorf("a redaction was claimed for a response where nothing was redacted: %s", buf.String())
	}
}

// A MIXED 2xx must still fail closed - the exemption applies to errors only.
// This pins that fixing BL-7 did not reopen BL-6.
func TestBL7MixedShapeStillFailsClosedOn2xx(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, bl7MixedShape)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("status=%d body=%.200s audit=%.300s", rr.Code, rr.Body.String(), buf.String())

	if rr.Code != http.StatusBadGateway {
		t.Errorf("a mixed-shape 2xx must fail closed with 502, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), piiEmail) {
		t.Errorf("LEAK: PII reached the client on a refused 2xx: %s", rr.Body.String())
	}
	if auditClaimsRedaction(buf.String()) {
		t.Errorf("nothing was served, so no redaction may be claimed: %s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// Genuine test gaps the round-3 mutation battery found (M20, M22, M27, M31,
// M04c). Each guard already worked; none was pinned by a test, so deleting it
// would have passed CI.
// ---------------------------------------------------------------------------

// M20: choices[].text as a non-string is an uninspectable shape, not something to
// skip past.
func TestResponseLegacyTextNonStringFailsClosed(t *testing.T) {
	for name, body := range map[string]string{
		"number": `{"choices":[{"index":0,"text":12345}],"usage":{"total_tokens":1}}`,
		"bool":   `{"choices":[{"index":0,"text":true}],"usage":{"total_tokens":1}}`,
		"object": `{"choices":[{"index":0,"text":{"a":"` + piiEmail + `"}}],"usage":{"total_tokens":1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			up := serveStatusAndBody(t, http.StatusOK, body)
			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL

			rr := post(t, gw, "gpt-4o", "hello")
			t.Logf("status=%d body=%.160s", rr.Code, rr.Body.String())
			if rr.Code != http.StatusBadGateway {
				t.Errorf("a non-string choices[].text must fail closed, got %d", rr.Code)
			}
			if strings.Contains(rr.Body.String(), piiEmail) {
				t.Errorf("LEAK: %s", rr.Body.String())
			}
		})
	}
}

// M04c: the BL-5 refusal must write an audit event, and it must say the request
// was REFUSED. An allow-default config previously logged action:"allow" for a
// request that returned 400, which reads as a successful forward.
func TestShapeRefusalIsAuditedAsDenied(t *testing.T) {
	up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL

	raw, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": map[string]any{"role": "user", "content": "hi " + piiEmail},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	auditLine := buf.String()
	t.Logf("status=%d audit=%.300s", rr.Code, auditLine)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected a 400 refusal, got %d", rr.Code)
	}
	if auditLine == "" {
		t.Fatal("AUDIT HOLE: a refused request wrote no event at all")
	}
	if !strings.Contains(auditLine, `"action":"denied"`) {
		t.Errorf("a refused request was audited as something other than denied, "+
			"which reads as a successful forward: %s", auditLine)
	}
	if strings.Contains(auditLine, longSecretKey) {
		t.Errorf("LEAK: raw API key in the audit log: %s", auditLine)
	}
}

// M27: the short-key branch of maskKey. Keys of length <= 4 must not be returned
// raw - a short key is still a credential.
func TestMaskKeyShortKeysAreNotReturnedRaw(t *testing.T) {
	for _, k := range []string{"", "a", "ab", "abc", "abcd"} {
		got := maskKey(k)
		t.Logf("maskKey(%q) = %q", k, got)
		if got == k && k != "" {
			t.Errorf("a short key was returned unmasked: %q", got)
		}
		if strings.Contains(got, k) && k != "" {
			t.Errorf("a short key is recoverable from its mask: %q", got)
		}
	}
	// And the long-key branch keeps its 4-char prefix contract.
	long := maskKey(longSecretKey)
	if !strings.HasPrefix(long, "sk-l") {
		t.Errorf("expected the 4-char prefix to be kept, got %q", long)
	}
	if strings.Contains(long, longSecretKey) {
		t.Errorf("the full key survived masking: %q", long)
	}
}

// M31: key masking must hold on the early-return paths that the earlier test did
// not cover - request-too-large, upstream read error, response-too-large and the
// panic recovery.
func TestAuditMasksKeyOnTheRemainingEarlyReturnPaths(t *testing.T) {
	t.Run("request too large", func(t *testing.T) {
		up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
		var buf bytes.Buffer
		gw := newTestGateway(t, nil, &buf)
		gw.UpstreamURL = up.URL

		raw, _ := json.Marshal(map[string]any{
			"model":    "m",
			"messages": []map[string]string{{"role": "user", "content": strings.Repeat("a", maxBodyBytes)}},
		})
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
		req.Header.Set("X-API-Key", longSecretKey)
		gw.ServeHTTP(rr, req)

		t.Logf("status=%d audit=%.240s", rr.Code, buf.String())
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413, got %d", rr.Code)
		}
		if strings.Contains(buf.String(), longSecretKey) {
			t.Errorf("LEAK: raw key on the 413 path: %s", buf.String())
		}
	})

	t.Run("response too large", func(t *testing.T) {
		big := strings.Repeat("a", maxBodyBytes+1)
		up := serveStatusAndBody(t, http.StatusOK,
			`{"choices":[{"message":{"content":"`+big+`"}}]}`)
		var buf bytes.Buffer
		gw := newTestGateway(t, nil, &buf)
		gw.UpstreamURL = up.URL

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("X-API-Key", longSecretKey)
		gw.ServeHTTP(rr, req)

		t.Logf("status=%d audit=%.240s", rr.Code, buf.String())
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("expected 502, got %d", rr.Code)
		}
		if strings.Contains(buf.String(), longSecretKey) {
			t.Errorf("LEAK: raw key on the response-too-large path: %s", buf.String())
		}
	})

	t.Run("panicking redactor", func(t *testing.T) {
		up := serveStatusAndBody(t, http.StatusOK, okJSONResponse)
		var buf bytes.Buffer
		gw := newTestGateway(t, nil, &buf)
		gw.UpstreamURL = up.URL
		gw.Redactor = panickingRedactor{}

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("X-API-Key", longSecretKey)
		gw.ServeHTTP(rr, req)

		t.Logf("status=%d audit=%.240s", rr.Code, buf.String())
		if strings.Contains(buf.String(), longSecretKey) {
			t.Errorf("LEAK: raw key on the panic path: %s", buf.String())
		}
		// The panic event must be identifiable and attributed. It is the only
		// record that a request was processed and the redactor blew up mid-flight,
		// so dropping either field makes an incident untraceable.
		if !strings.Contains(buf.String(), `"rule":"handler-panic"`) {
			t.Errorf("the panic event lost its rule name: %s", buf.String())
		}
		if !strings.Contains(buf.String(), `"api_key"`) {
			t.Errorf("UNATTRIBUTED: the panic event names no caller, so the one "+
				"record a misbehaving Redactor produces cannot be traced: %s", buf.String())
		}
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("a recovered panic should answer 500, got %d", rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// marshalMap's error path. HONEST CAVEAT, same class as the M7 finding recorded
// earlier on this branch: this branch is UNREACHABLE via ServeHTTP. `parsed`
// comes from json.Unmarshal, so every value in it is one of float64 / string /
// bool / nil / map[string]any / []any, and all of those marshal cleanly. Nothing
// a client or an upstream sends can make json.Marshal fail on that map.
//
// The guard is defensive depth: it exists so that if a future change lets a
// non-marshalable value into parsed (a redactor returning a channel, a NaN from
// arithmetic, a typed nil interface), the failure is loud rather than serving
// unredacted bytes. Pinned at FUNCTION level here so the guard is not silently
// deletable, with the reachability limit stated rather than glossed.
//
// Mutation B5 ("if marshalErr != nil" -> "&& false") SURVIVED the suite, which is
// exactly what an unreachable branch does. This test converts that survivor from
// a blind spot into a documented one.
// ---------------------------------------------------------------------------

func TestMarshalMapFailsLoudlyOnNonMarshalableValue(t *testing.T) {
	// A value json.Unmarshal can never produce, but json.Marshal rejects.
	bad := map[string]any{"choices": []any{math.NaN()}}

	_, err := marshalMap(bad)
	if err == nil {
		t.Fatal("marshalMap swallowed a non-marshalable value; the caller's " +
			"fail-closed guard depends on this error being returned")
	}
	t.Logf("marshalMap correctly failed: %v", err)

	// And the normal path must succeed, so the error is not unconditional.
	good := map[string]any{"choices": []any{map[string]any{"text": "hi"}}}
	out, err := marshalMap(good)
	if err != nil {
		t.Fatalf("marshalMap failed on a plain unmarshal-shaped map: %v", err)
	}
	if !strings.Contains(string(out), `"text":"hi"`) {
		t.Errorf("marshalMap mangled a valid map: %s", out)
	}
}
