package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// BL-8 and N1, both found by the round-4 independent review at 287fc95 and both
// consequences of the same design flaw: redaction was ENUMERATED over a
// hand-maintained list of shapes.
//
// BL-8: the walker returned at the first shape it could not classify, so element
// ORDER decided whether PII was read at all. An uninspectable element placed
// FIRST meant readable PII placed AFTER it was never reached - and because the
// error path re-encoded the map it had only partly redacted, the raw PII was
// served. A fix written against one reproduction ordering stays broken under its
// mirror image.
//
// N1: the walker only visited choices[].message.content and a few siblings. PII in
// error.message - a field no enumerated walker ever looked at - passed through at
// EVERY status including 200.
//
// The total sweep in redactResponse closes both by construction: it recurses over
// all six types encoding/json can produce and redacts every string it finds, so
// there is no ordering to get wrong and no key name that is never visited. These
// tests pin that property rather than the shapes, so a future return to
// enumeration fails here even if it enumerates a different list.
// ---------------------------------------------------------------------------

// BL-8: redaction must not depend on element order.
func TestSweepIsOrderIndependent(t *testing.T) {
	const breaker = `{"text":5}`
	orderings := map[string]string{
		"pii-first":            `{"choices":[{"message":{"content":"` + piiMarker + `"}},` + breaker + `]}`,
		"pii-last":             `{"choices":[` + breaker + `,{"message":{"content":"` + piiMarker + `"}}]}`,
		"pii-between-breakers": `{"choices":[` + breaker + `,{"message":{"content":"` + piiMarker + `"}},` + breaker + `]}`,
		"deeply-nested-pii":    `{"choices":[{"a":{"b":{"c":5}}},{"message":{"content":"` + piiMarker + `"}}]}`,
		"pii-inside-error":     `{"error":{"message":"` + piiMarker + `"},"choices":[` + breaker + `]}`,
	}

	for _, status := range []int{
		http.StatusOK, http.StatusBadRequest, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
	} {
		for name, body := range orderings {
			t.Run(fmt.Sprintf("%s@%d", name, status), func(t *testing.T) {
				up := serveStatusAndBody(t, status, body)
				var buf bytes.Buffer
				gw := newTestGateway(t, nil, &buf)
				gw.UpstreamURL = up.URL
				gw.Redactor = shapeRedactor{}

				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
					strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
				req.Header.Set("X-API-Key", longSecretKey)
				gw.ServeHTTP(rr, req)

				client := rr.Body.String()
				if strings.Contains(client, piiMarker) {
					t.Errorf("BL-8 LEAK: order decided whether PII was read. status=%d "+
						"shape=%s client=%.240s", status, name, client)
				}
				// Every one of these shapes contains PII somewhere, so the trail
				// must record having removed it - unless the response was refused
				// outright, in which case nothing was served to redact.
				refused := rr.Code == http.StatusBadGateway &&
					strings.Contains(client, "could not be redacted")
				if !refused && !auditClaimsRedaction(buf.String()) {
					t.Errorf("UNDER-REPORTED: redacted output was served but the audit "+
						"records no redaction: %.280s", buf.String())
				}
			})
		}
	}
}

// N1: PII in a field no enumerated walker ever visited must still be redacted.
// The reviewer reproduced this at 287fc95 at status 200.
func TestSweepReachesEveryStringFieldNotJustChoices(t *testing.T) {
	bodies := map[string]string{
		"error.message":        `{"error":{"message":"failed for ` + piiMarker + `","type":"server_error"}}`,
		"error.details.reason": `{"error":{"details":{"reason":"` + piiMarker + `"}}}`,
		"top-level message":    `{"message":"` + piiMarker + `","choices":[]}`,
		"model":                `{"model":"` + piiMarker + `","choices":[]}`,
		"usage.detail":         `{"usage":{"detail":"` + piiMarker + `"},"choices":[]}`,
		"id":                   `{"id":"` + piiMarker + `","choices":[]}`,
		"logprobs.token":       `{"choices":[{"logprobs":{"tokens":["` + piiMarker + `"]}}]}`,
		"finish_reason":        `{"choices":[{"finish_reason":"` + piiMarker + `"}]}`,
		"bare string array":    `{"choices":[{"message":{"content":["` + piiMarker + `"]}}]}`,
		"function arguments":   `{"choices":[{"message":{"tool_calls":[{"function":{"arguments":"{\\"email\\":\\"` + piiMarker + `\\"}"}}]}}]}`,
	}

	for _, status := range []int{
		http.StatusOK, http.StatusBadRequest, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
	} {
		for name, body := range bodies {
			t.Run(fmt.Sprintf("%s@%d", name, status), func(t *testing.T) {
				up := serveStatusAndBody(t, status, body)
				var buf bytes.Buffer
				gw := newTestGateway(t, nil, &buf)
				gw.UpstreamURL = up.URL
				gw.Redactor = shapeRedactor{}

				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
					strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
				req.Header.Set("X-API-Key", longSecretKey)
				gw.ServeHTTP(rr, req)

				client := rr.Body.String()
				if strings.Contains(client, piiMarker) {
					t.Errorf("N1 LEAK: PII in %q was served uninspected at status %d: %.240s",
						name, status, client)
				}
			})
		}
	}
}

// Opaque keys are deliberately NOT swept. Pinning that keeps the skip honest: it
// is a documented decision about base64 payloads, not an oversight that lets a
// field be exempted by accident.
func TestSweepSkipsOpaqueBinaryKeys(t *testing.T) {
	// A base64 key whose value happens to contain the canary. Redacting inside
	// base64 would corrupt the payload into something the client cannot decode.
	body := `{"choices":[{"message":{"content":[` +
		`{"type":"image_url","b64_json":"` + piiMarker + `"}]}}]}`
	up := serveStatusAndBody(t, http.StatusOK, body)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = shapeRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	client := rr.Body.String()
	t.Logf("client=%.240s", client)

	if !strings.Contains(client, piiMarker) {
		t.Errorf("the opaque b64_json payload was rewritten, which would corrupt an "+
			"undecodable base64 stream: %s", client)
	}
	if !strings.Contains(client, `"type":"image_url"`) {
		t.Errorf("the surrounding part structure was lost: %s", client)
	}
}

// S5 closed a real gap: the only test of opaqueKeys proved b64_json IS skipped,
// and said nothing about whether OTHER keys were skipped too. A mutation
// widening the check to a "b64" prefix match - so b64_notes or b64anything also
// escaped redaction - passed the suite. The exemption must be exact, not a prefix.
func TestOpaqueKeyExemptionIsExactNotAPrefix(t *testing.T) {
	// Keys that merely LOOK like the exempted one. Every one of these is ordinary
	// text and must be swept.
	for name, key := range map[string]string{
		"b64_notes":      "b64_notes",
		"b64anything":    "b64anything",
		"b64":            "b64",
		"B64_JSON upper": "B64_JSON",
		"b64_json_":      "b64_json_",
		"_b64_json":      "_b64_json",
		"b64_jsonX":      "b64_jsonX",
		"base64":         "base64",
		"image_b64_json": "image_b64_json",
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"choices":[{"message":{"` + key + `":"` + piiMarker + `"}}]}`
			up := serveStatusAndBody(t, http.StatusOK, body)

			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL
			gw.Redactor = shapeRedactor{}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
				strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
			req.Header.Set("X-API-Key", longSecretKey)
			gw.ServeHTTP(rr, req)

			client := rr.Body.String()
			if strings.Contains(client, piiMarker) {
				t.Errorf("LEAK: the key %q was exempted from the sweep, but only the "+
					"exact key b64_json may be: %.240s", key, client)
			}
			if !strings.Contains(client, "[REDACTED:EMAIL]") {
				t.Errorf("the value under key %q was not redacted: %.240s", key, client)
			}
		})
	}
}

// S9 closed a real gap: the binary guard had no test at all. A non-UTF-8 body is
// the one case text redaction cannot serve - a regex pass over image or audio
// bytes neither finds PII nor leaves the payload decodable - so it must fail
// closed. Removing the guard served corrupt bytes and nothing noticed.
func TestNonUTF8ResponseFailsClosed(t *testing.T) {
	// Real binary: a PNG signature followed by invalid UTF-8 continuation bytes.
	binary := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a},
		0xff, 0xfe, 0xc3, 0x28, 0xa0, 0xa1)

	cases := []struct {
		name        string
		status      int
		contentType string
		body        []byte
	}{
		{"png at 200", http.StatusOK, "image/png", binary},
		{"raw invalid utf8 at 500", http.StatusInternalServerError, "text/plain", binary},
		{"lone continuation byte at 429", http.StatusTooManyRequests, "application/octet-stream",
			[]byte{0x80}},
		{"truncated multibyte at 502", http.StatusBadGateway, "", []byte("ok \xe2\x82")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.body)
			}))
			t.Cleanup(up.Close)

			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL
			gw.Redactor = shapeRedactor{}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
				strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
			req.Header.Set("X-API-Key", longSecretKey)
			gw.ServeHTTP(rr, req)

			t.Logf("status=%d body=%.80q audit=%.260s", rr.Code, rr.Body.Bytes(), buf.String())

			// THE PROPERTY: fail closed with the gateway's own refusal rather than
			// passing bytes through. This holds at EVERY status, including non-2xx,
			// because a binary payload is not a diagnostic a caller can act on.
			if rr.Code != http.StatusBadGateway {
				t.Errorf("a non-UTF-8 body must fail closed with 502 at status %d, got %d",
					tc.status, rr.Code)
			}

			// Which refusal reason fires is NOT asserted, deliberately. At 200 the
			// accounting guard runs first - a successful completion with no
			// parseable usage would be served at zero tokens, the BL-2 budget
			// bypass - so it refuses as unparseable_success_response before the
			// UTF-8 check is reached. At non-2xx there is no accounting
			// expectation, so the binary guard fires instead. Both are truthful,
			// both serve no upstream bytes, and asserting one specific string would
			// pin the ORDER of two independent guards rather than the property
			// either of them provides. What is required is that SOME refusal
			// reason was audited.
			audited := buf.String()
			if !strings.Contains(audited, "uninspectable_binary_response") &&
				!strings.Contains(audited, "unparseable_success_response") {
				t.Errorf("the refusal was not audited with a diagnostic reason: %s", audited)
			}
			if strings.Contains(audited, `"action":"allow"`) {
				t.Errorf("a refused response was audited as allowed: %s", audited)
			}
			// Nothing from upstream may reach the client on a refusal.
			if bytes.Contains(rr.Body.Bytes(), tc.body) {
				t.Errorf("the upstream payload was forwarded to the client despite the refusal")
			}
			if strings.Contains(buf.String(), longSecretKey) {
				t.Errorf("INVAR-5 LEAK: raw API key in the audit log: %.200s", buf.String())
			}
		})
	}
}

// A valid-UTF-8 non-JSON body must NOT be refused - that is the diagnostic
// passthrough the binary guard exists to protect. Pinning the boundary stops the
// guard being widened into "refuse everything that is not JSON".
func TestValidUTF8NonJSONErrorIsNotRefused(t *testing.T) {
	body := []byte("upstream said: connection reset by peer")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(body)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = shapeRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	t.Logf("status=%d body=%q", rr.Code, rr.Body.String())
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status was not preserved: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "connection reset by peer") {
		t.Errorf("a valid-UTF-8 diagnostic was refused instead of passed through: %q",
			rr.Body.String())
	}
	if strings.Contains(buf.String(), "uninspectable_binary_response") {
		t.Errorf("valid UTF-8 was misclassified as binary: %s", buf.String())
	}
}
