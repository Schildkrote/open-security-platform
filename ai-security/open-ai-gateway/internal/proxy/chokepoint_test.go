package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// THE CHOKEPOINT INVARIANT.
//
// Four review rounds on this branch each found the same bug class in a
// DIFFERENT half of the shape space:
//
//	round 1  BL-3/4  request content as a parts ARRAY was unread
//	round 2  BL-5    request MESSAGES CONTAINER as an object was unread
//	round 2  BL-6    RESPONSE content as an array / delta / legacy text unread
//	round 3  BL-7    audit claimed a redaction the served bytes disproved
//
// Every fix enumerated the shapes the reviewer happened to name. That converges
// slowly, and each fix is a fresh chance to regress. This file stops enumerating
// and instead asserts ONE property over a mechanically generated shape space, so
// an unenumerated shape is caught by construction rather than by whoever thought
// to test it next.
//
//	INVAR-1 (no raw PII egress): the PII literal must never appear in the bytes
//	  the gateway sends to the client, on ANY status code, for ANY response shape.
//	INVAR-2 (no over-claim): if the audit records a redaction, the served bytes
//	  must not contradict it.
//	INVAR-3 (no omission): if the served bytes contain a redaction marker, the
//	  audit must record it.
//	INVAR-4 (diagnostics survive errors): on a non-2xx the upstream status and
//	  the error message must reach the client, or the response must be a
//	  gateway-generated refusal that carries no upstream bytes at all.
//	INVAR-5 (attribution): every audited path masks the API key.
//
// INVAR-1 is the one that matters: it is the product's entire promise.
// ---------------------------------------------------------------------------

// piiMarker is a distinctive literal. If it survives into the client body the
// redactor never saw it, which is the failure mode all four rounds were about.
const piiMarker = "CHOKEPOINT-CANARY-jane.doe@example.com"

// shapeRedactor redacts anything containing the canary and reports it. Unlike
// findingRedactor (which redacts every non-empty string), this one only fires on
// the canary, so a shape carrying no PII legitimately produces no redaction and
// INVAR-3 stays meaningful.
type shapeRedactor struct{}

func (shapeRedactor) Redact(text string) (string, []string) {
	if strings.Contains(text, piiMarker) {
		return strings.ReplaceAll(text, piiMarker, "[REDACTED:EMAIL]"), []string{"EMAIL"}
	}
	return text, nil
}

// shapeSpace generates response bodies mechanically: a container name, a content
// carrier, a content value kind, and a sibling element that may be readable or
// uninspectable. ORDER IS DELIBERATELY BOTH WAYS - the readable element first and
// second - because a walk that fails partway behaves differently depending on how
// much it had already redacted.
func shapeSpace() []struct {
	name string
	body string
} {
	containers := []string{"message", "delta"}
	carriers := []string{"content", "text"}
	values := []struct {
		name string
		json string
	}{
		{"pii-string", `"` + piiMarker + `"`},
		{"clean-string", `"all clear"`},
		{"parts-array-with-pii", `[{"type":"text","text":"` + piiMarker + `"}]`},
		{"parts-array-clean", `[{"type":"text","text":"all clear"}]`},
		{"parts-array-image-only", `[{"type":"image_url","image_url":{"url":"http://x/y.png"}}]`},
		{"parts-array-string-element", `["` + piiMarker + `"]`},
		{"parts-array-number-text", `[{"type":"text","text":5}]`},
		{"parts-array-part-is-string", `["plain"]`},
		{"number", `42`},
		{"bool", `true`},
		{"object", `{"nested":"` + piiMarker + `"}`},
		{"null", `null`},
	}

	// An element that is definitely uninspectable, used as the walk-breaker.
	const breaker = `{"text":5}`

	var out []struct {
		name string
		body string
	}
	add := func(name, body string) {
		out = append(out, struct {
			name string
			body string
		}{name, body})
	}

	for _, cont := range containers {
		for _, car := range carriers {
			for _, v := range values {
				readable := fmt.Sprintf(`{"%s":{"role":"assistant","%s":%s}}`, cont, car, v.json)

				add(cont+"/"+car+"/"+v.name+"/alone",
					`{"choices":[`+readable+`],"usage":{"total_tokens":3}}`)
				// Readable BEFORE the breaker: the walk redacts, then fails.
				add(cont+"/"+car+"/"+v.name+"/readable-then-breaker",
					`{"choices":[`+readable+`,`+breaker+`],"usage":{"total_tokens":3}}`)
				// Breaker BEFORE readable: the walk fails having redacted NOTHING,
				// so a later element's PII is still live in the parsed map.
				add(cont+"/"+car+"/"+v.name+"/breaker-then-readable",
					`{"choices":[`+breaker+`,`+readable+`],"usage":{"total_tokens":3}}`)
			}
		}
	}

	// Structural oddities around choices itself.
	for _, c := range []struct{ name, body string }{
		{"choices-is-object", `{"choices":{"0":{"message":{"content":"` + piiMarker + `"}}}}`},
		{"choices-is-string", `{"choices":"` + piiMarker + `"` + `}`},
		{"choices-is-number", `{"choices":7}`},
		{"choices-null", `{"choices":null}`},
		{"choices-absent", `{"id":"x","object":"chat.completion"}`},
		{"choices-empty", `{"choices":[]}`},
		{"choice-is-string", `{"choices":["` + piiMarker + `"]}`},
		{"choice-is-number", `{"choices":[7]}`},
		{"choice-is-null", `{"choices":[null]}`},
		{"message-is-string", `{"choices":[{"message":"` + piiMarker + `"}]}`},
		{"message-null-content", `{"choices":[{"message":{"content":null}}]}`},
		{"content-absent", `{"choices":[{"message":{"role":"assistant"}}]}`},
		{"mixed-clean-then-pii", `{"choices":[{"message":{"content":"clean"}},{"message":{"content":"` + piiMarker + `"}}]}`},
		{"mixed-pii-then-clean", `{"choices":[{"message":{"content":"` + piiMarker + `"}},{"message":{"content":"clean"}}]}`},
	} {
		add(c.name, c.body)
	}
	return out
}

var statuses = []int{
	http.StatusOK,
	http.StatusCreated,
	http.StatusNoContent,
	http.StatusBadRequest,
	http.StatusTooManyRequests,
	http.StatusInternalServerError,
	http.StatusBadGateway,
}

func TestChokepointInvariantAcrossTheWholeShapeSpace(t *testing.T) {
	shapes := shapeSpace()
	t.Logf("generated shape space: %d shapes x %d statuses = %d cases",
		len(shapes), len(statuses), len(shapes)*len(statuses))

	var leaks, overClaims, omissions, badCL []string

	for _, sh := range shapes {
		for _, status := range statuses {
			name := fmt.Sprintf("%s@%d", sh.name, status)
			t.Run(name, func(t *testing.T) {
				up := serveStatusAndBody(t, status, sh.body)
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
				auditLine := buf.String()

				gatewayRefusal := rr.Code == http.StatusBadGateway &&
					strings.Contains(client, "could not be redacted")

				// INVAR-1: no raw PII egress, on any status.
				if strings.Contains(client, piiMarker) {
					leaks = append(leaks, name)
					t.Errorf("INVAR-1 LEAK: raw PII served to the client at status %d: %.240s",
						rr.Code, client)
				}

				claims := auditClaimsRedaction(auditLine)
				redacted := strings.Contains(client, "[REDACTED:EMAIL]")

				// INVAR-2: no over-claim.
				if claims && strings.Contains(client, piiMarker) {
					overClaims = append(overClaims, name)
					t.Errorf("INVAR-2 OVER-CLAIM: audit claims resp:EMAIL but the client "+
						"received it raw: %.240s", client)
				}
				// A claimed redaction with neither marker nor refusal is also an
				// over-claim: nothing was served that the claim describes.
				if claims && !redacted && !gatewayRefusal {
					overClaims = append(overClaims, name+"(no-marker)")
					t.Errorf("INVAR-2 OVER-CLAIM: audit claims a redaction but the served "+
						"bytes contain no marker and the response was not refused: %.240s", client)
				}

				// INVAR-3: no omission.
				if redacted && !claims {
					omissions = append(omissions, name)
					t.Errorf("INVAR-3 OMISSION: the client received redacted output but the "+
						"audit records no redaction: %.300s", auditLine)
				}

				// INVAR-4: errors keep their diagnostic, or are a clean refusal.
				if status >= 400 && status != http.StatusBadGateway && !gatewayRefusal {
					if rr.Code != status {
						t.Errorf("INVAR-4: upstream status %d was replaced by %d", status, rr.Code)
					}
					if strings.Contains(sh.body, "all clear") &&
						!strings.Contains(client, "all clear") {
						t.Errorf("INVAR-4: the error diagnostic was lost: %.200s", client)
					}
				}

				// INVAR-5: attribution without disclosure.
				if auditLine != "" {
					if strings.Contains(auditLine, longSecretKey) {
						t.Errorf("INVAR-5 LEAK: raw API key in the audit log: %.200s", auditLine)
					}
					if !strings.Contains(auditLine, `"api_key"`) {
						t.Errorf("INVAR-5: the audit event names no caller: %.200s", auditLine)
					}
				}

				// Content-Length must stay truthful whenever a body was written.
				if cl := rr.Header().Get("Content-Length"); cl != "" {
					want := fmt.Sprintf("%d", rr.Body.Len())
					if cl != want {
						badCL = append(badCL, name)
						t.Errorf("Content-Length=%q but %d bytes were written", cl, rr.Body.Len())
					}
				}
			})
		}
	}

	t.Logf("SUMMARY over %d cases: leaks=%d overClaims=%d omissions=%d badContentLength=%d",
		len(shapes)*len(statuses), len(leaks), len(overClaims), len(omissions), len(badCL))
	for _, l := range leaks {
		t.Logf("  LEAK: %s", l)
	}
	for _, o := range overClaims {
		t.Logf("  OVER-CLAIM: %s", o)
	}
	for _, o := range omissions {
		t.Logf("  OMISSION: %s", o)
	}
}

// The request side gets the same treatment: the messages container and the
// content carrier, in every shape, must either be redacted before forwarding or
// refused. An unredacted forward is the BL-5 class.
func TestChokepointRequestShapeSpaceNeverForwardsRawPII(t *testing.T) {
	containers := []struct {
		name string
		mk   func(content string) string
	}{
		{"array-of-objects", func(c string) string {
			return `[{"role":"user","content":` + c + `}]`
		}},
		{"single-object", func(c string) string {
			return `{"role":"user","content":` + c + `}`
		}},
		{"bare-string", func(c string) string {
			return `"` + c + `"`
		}},
		{"number", func(c string) string { return `7` }},
		{"null", func(c string) string { return `null` }},
		{"absent", func(c string) string { return `__ABSENT__` }},
	}
	contents := []struct{ name, json string }{
		{"pii-string", `"` + piiMarker + `"`},
		{"parts-array-pii", `[{"type":"text","text":"` + piiMarker + `"}]`},
		{"parts-array-nested-deeper", `[{"type":"text","text":{"deep":"` + piiMarker + `"}}]`},
		{"number", `5`},
		{"bool", `true`},
		{"object", `{"a":"` + piiMarker + `"}`},
		{"null", `null`},
	}

	var leaks []string
	for _, cont := range containers {
		for _, cv := range contents {
			name := cont.name + "/" + cv.name
			t.Run(name, func(t *testing.T) {
				msgs := cont.mk(cv.json)
				var raw string
				if strings.Contains(msgs, "__ABSENT__") {
					raw = `{"model":"m"}`
				} else {
					raw = `{"model":"m","messages":` + msgs + `}`
				}
				if !json.Valid([]byte(raw)) {
					t.Skipf("generated request is not valid JSON, skipping: %.80s", raw)
				}

				// Capture what the UPSTREAM actually receives.
				var gotUpstream string
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := io.ReadAll(r.Body)
					gotUpstream = string(b)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(okJSONResponse))
				}))
				t.Cleanup(up.Close)

				var buf bytes.Buffer
				gw := newTestGateway(t, nil, &buf)
				gw.UpstreamURL = up.URL
				gw.Redactor = shapeRedactor{}

				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
					strings.NewReader(raw))
				req.Header.Set("X-API-Key", longSecretKey)
				gw.ServeHTTP(rr, req)

				t.Logf("status=%d upstream-saw=%.200s", rr.Code, gotUpstream)

				// The request went upstream only if the upstream handler ran.
				if gotUpstream != "" && strings.Contains(gotUpstream, piiMarker) {
					leaks = append(leaks, name)
					t.Errorf("INVAR-1 (request) LEAK: raw PII was forwarded upstream at "+
						"status %d: %.240s", rr.Code, gotUpstream)
				}
				if strings.Contains(buf.String(), longSecretKey) {
					t.Errorf("INVAR-5 LEAK: raw API key in the audit log: %.200s", buf.String())
				}
			})
		}
	}
	t.Logf("request-side leaks: %d %v", len(leaks), leaks)
}
