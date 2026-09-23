package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/policy"
)

// ---------------------------------------------------------------------------
// Round-5 blockers BL-10 .. BL-13 and N3.
//
// The round-5 reviewer's finding, verbatim in substance: four prior rounds each
// found "the fix enumerated SHAPES, one behind"; round 5 found that the fix
// enumerated CHANNELS. The response-body value sweep was sound (it could not find
// a fifth value shape that escaped it, and it re-confirmed the S1 mutation kills
// the suite), but the gateway's egress surface is larger than the values in one
// JSON body:
//
//   BL-9  the b64_json exemption was keyed by NAME, never validated      (sweep_test.go)
//   BL-10 object KEYS were never swept                                  (this file)
//   BL-11 the REQUEST side still used the enumerated walker             (this file)
//   BL-12 response HEADERS were copied verbatim                         (this file)
//   BL-13 upstream-unreachable wrote NO audit event                     (this file)
//   N3    the non-JSON text path's ev.Redactions append was unpinned    (this file)
//
// Every test below uses the reviewer's own reproduction shapes, so a regression
// reopens the exact case that was reported rather than a near miss.
// ---------------------------------------------------------------------------

// BL-10: a key is a string in the decoded document and json.Marshal re-emits it
// verbatim, so an upstream that ships PII as a KEY bypassed a values-only sweep.
// Reviewed reproductions: {"jane.doe@example.com":"v"}, {"10.0.0.7":"v"},
// {"sk-<36>":"v"}, and the same nested inside choices[].
func TestBL10_ObjectKeysAreSwept(t *testing.T) {
	shapes := map[string]string{
		"pii_as_top_level_key": `{"choices":[{"message":{"content":"ok"}}],"` + piiMarker + `":"v"}`,
		"pii_nested_key":       `{"choices":[{"` + piiMarker + `":"v","message":{"content":"ok"}}]}`,
		"pii_key_deep":         `{"a":{"b":{"` + piiMarker + `":"v"}},"choices":[]}`,
		"pii_key_in_array_map": `{"choices":[{"message":{"content":[{"` + piiMarker + `":"v"}]}}]}`,
	}
	for _, status := range []int{http.StatusOK, http.StatusTooManyRequests} {
		for name, body := range shapes {
			t.Run(fmt.Sprintf("status_%d/%s", status, name), func(t *testing.T) {
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
				t.Logf("client=%.240s", client)
				if strings.Contains(client, piiMarker) {
					t.Errorf("BL-10 LEAK: PII in an object KEY was served verbatim: %s", client)
				}
				// The audit trail must account for it, not just silently fix it.
				if !strings.Contains(buf.String(), "resp:EMAIL") {
					t.Errorf("the key redaction was not recorded in the audit event: %s", buf.String())
				}
				// Positive control: the body still parsed and served as JSON, so the
				// absence of the canary is because of redaction and not a refusal.
				if !strings.HasPrefix(strings.TrimSpace(client), "{") {
					t.Errorf("response is not a JSON object; was it refused instead of swept? %s", client)
				}
			})
		}
	}
}

// collapsingRedactor maps EVERY key that contains the marker to the SAME string,
// so two distinct PII keys genuinely collide after redaction. shapeRedactor cannot
// express this: it substitutes the marker in place, so "marker" and
// "marker-OTHER" redact to two DIFFERENT strings and the collision path is never
// taken. A collision test that never produces a collision is vacuous - and the
// first version of this test was exactly that, which is how mutation M7
// (delete the collision-avoidance loop) survived the suite.
type collapsingRedactor struct{}

func (collapsingRedactor) Redact(text string) (string, []string) {
	if strings.Contains(text, piiMarker) {
		return "[REDACTED]", []string{"EMAIL"}
	}
	return text, nil
}

// BL-10, the correctness half: sweeping keys must not DROP or CORRUPT data. Two
// distinct keys that redact to the SAME string must both survive, and a map must
// not be mutated while it is being ranged (unsafe in Go, and it can silently skip
// entries). This is the over-redaction mirror question the reviewer asked.
func TestBL10_KeyRenamePreservesBothCollidingEntries(t *testing.T) {
	// Four distinct PII keys, all of which collapse to "[REDACTED]". Without the
	// collision-avoidance suffix loop, three of the four values are silently lost.
	body := `{
		"` + piiMarker + `-alpha":"value-alpha",
		"` + piiMarker + `-beta":"value-beta",
		"` + piiMarker + `-gamma":"value-gamma",
		"` + piiMarker + `-delta":"value-delta",
		"choices":[]
	}`
	up := serveStatusAndBody(t, http.StatusOK, body)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = collapsingRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	client := rr.Body.String()
	t.Logf("client=%s", client)

	if strings.Contains(client, piiMarker) {
		t.Errorf("BL-10 LEAK: a PII key survived: %s", client)
	}
	// ALL FOUR values must survive. Silently overwriting on collision would drop
	// three of them - that is data loss the client cannot detect, because the
	// document still parses and still looks redacted.
	for _, want := range []string{"value-alpha", "value-beta", "value-gamma", "value-delta"} {
		if !strings.Contains(client, want) {
			t.Errorf("a colliding key rename DROPPED %q - silent data loss. client=%s",
				want, client)
		}
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(client), &got); err != nil {
		t.Fatalf("response is not valid JSON after key sweeping: %v (%s)", err, client)
	}
	// Count the redacted keys: there must be four distinct entries holding the
	// four values, not one entry holding whichever won the race.
	redactedKeys := 0
	for k := range got {
		if strings.HasPrefix(k, "[REDACTED]") {
			redactedKeys++
		}
	}
	if redactedKeys != 4 {
		t.Errorf("expected 4 distinct redacted keys (one per original), got %d; "+
			"collisions were not disambiguated. keys=%v", redactedKeys, keysOf(got))
	}
}

// BL-10/M6: renaming during a range over the same map is unsafe in Go and can
// skip entries. With enough colliding keys the skip becomes observable - not every
// key gets swept. This pins the two-pass structure rather than trusting it.
func TestBL10_ManyCollidingKeysAreAllSwept(t *testing.T) {
	parts := make([]string, 0, 24)
	want := make([]string, 0, 24)
	for i := 0; i < 24; i++ {
		parts = append(parts, fmt.Sprintf("%q:%q", piiMarker+fmt.Sprintf("-k%02d", i), fmt.Sprintf("v%02d", i)))
		want = append(want, fmt.Sprintf("v%02d", i))
	}
	body := "{" + strings.Join(parts, ",") + `,"choices":[]}`
	up := serveStatusAndBody(t, http.StatusOK, body)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = collapsingRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	client := rr.Body.String()
	if strings.Contains(client, piiMarker) {
		t.Errorf("BL-10 LEAK with 24 colliding keys: %s", client)
	}
	missing := 0
	for _, w := range want {
		if !strings.Contains(client, w) {
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("%d of 24 values were lost during key sweeping - a range-time map "+
			"mutation skipped entries: %s", missing, client)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// BL-10, degenerate: a key that redacts to an EMPTY string must not produce an
// invalid document or panic.
func TestBL10_EmptyAndOddKeysDoNotCorruptDocument(t *testing.T) {
	for name, body := range map[string]string{
		"empty_key":           `{"":"v","choices":[]}`,
		"key_with_quotes":     `{"a\"b":"v","choices":[]}`,
		"unicode_key":         `{"中文键":"v","choices":[]}`,
		"key_is_marker_only":  `{"` + piiMarker + `":"v","choices":[]}`,
		"many_keys_collision": `{"` + piiMarker + `":"1","x` + piiMarker + `":"2","y` + piiMarker + `":"3","choices":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
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
			var got map[string]any
			if err := json.Unmarshal([]byte(client), &got); err != nil {
				t.Fatalf("document corrupted by key sweeping: %v (%s)", err, client)
			}
			if strings.Contains(client, piiMarker) {
				t.Errorf("BL-10 LEAK in %s: %s", name, client)
			}
			// Content-Length must stay truthful after keys were rewritten.
			if cl := rr.Header().Get("Content-Length"); cl != "" {
				if n := atoiT(t, cl); n != len(rr.Body.Bytes()) {
					t.Errorf("Content-Length %s != actual body %d", cl, len(rr.Body.Bytes()))
				}
			}
		})
	}
}

func atoiT(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatalf("bad Content-Length %q: %v", s, err)
	}
	return n
}

// BL-11: the REQUEST side still used the enumerated walker (messages[].content
// and parts[].text only), so PII in any other field was forwarded to the upstream
// provider verbatim - the direction RedactRequest exists to close. These are the
// reviewer's exact reproductions.
func TestBL11_RequestSidePIIInEveryFieldIsRedacted(t *testing.T) {
	cases := map[string]string{
		"metadata_user_email":   `{"model":"m","messages":[{"role":"user","content":"hi"}],"metadata":{"user_email":"` + piiMarker + `"}}`,
		"prompt_field":          `{"model":"m","prompt":"contact ` + piiMarker + `"}`,
		"tool_description":      `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"function":{"name":"f","description":"email ` + piiMarker + `"}}]}`,
		"top_level_user":        `{"model":"m","messages":[{"role":"user","content":"hi"}],"user":"` + piiMarker + `"}`,
		"image_url_data_uri":    `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:text/plain,` + piiMarker + `"}}]}]}`,
		"stop_sequence":         `{"model":"m","messages":[{"role":"user","content":"hi"}],"stop":["` + piiMarker + `"]}`,
		"nested_response_fmt":   `{"model":"m","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","schema":{"title":"` + piiMarker + `"}}}`,
		"object_key_in_request": `{"model":"m","messages":[{"role":"user","content":"hi"}],"` + piiMarker + `":"v"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			// Capture what the gateway actually forwarded upstream.
			var forwarded []byte
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(r.Body)
				forwarded = buf.Bytes()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(okJSONResponse))
			}))
			t.Cleanup(up.Close)

			var auditBuf bytes.Buffer
			gw := newTestGateway(t, nil, &auditBuf)
			gw.UpstreamURL = up.URL
			gw.Redactor = shapeRedactor{}
			gw.RedactRequest = true

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("X-API-Key", longSecretKey)
			gw.ServeHTTP(rr, req)

			t.Logf("forwarded=%.240s", forwarded)
			if strings.Contains(string(forwarded), piiMarker) {
				t.Errorf("BL-11 LEAK: PII in %s was forwarded to the upstream provider "+
					"verbatim: %s", name, forwarded)
			}
			// Positive control: the request was actually forwarded (not refused),
			// so the absence of the canary is due to redaction.
			if len(forwarded) == 0 {
				t.Fatalf("nothing was forwarded - was the request refused? status=%d body=%s",
					rr.Code, rr.Body.String())
			}
			if !strings.Contains(auditBuf.String(), "req:EMAIL") {
				t.Errorf("the request-side redaction was not recorded with a req: "+
					"prefix, so the trail cannot tell client->upstream from "+
					"upstream->client: %s", auditBuf.String())
			}
		})
	}
}

// BL-11's policy half: a ContentRe deny rule that only saw messages[].content was
// bypassable by field choice. The reviewer reproduced deny rule "FORBIDDEN" with
// body {"model":"m","prompt":"say FORBIDDEN please"} -> 200 allow, audited
// action:"allow". Policy now sees every string in the request.
func TestBL11_PolicyContentRuleCannotBeBypassedByFieldChoice(t *testing.T) {
	forbidden := "FORBIDDEN-PHRASE"
	// A rule that denies any content matching the phrase, wherever it appears.
	// Field names are the real policy.Rule ones: Name, ModelPattern, ContentRe,
	// APIKeys, Action, Reason. The names I first wrote were invented.
	rules := []policy.Rule{{
		Name:         "deny-forbidden",
		ModelPattern: ".*",
		ContentRe:    forbidden,
		Action:       policy.Deny,
		Reason:       "forbidden phrase in request content",
	}}

	cases := map[string]string{
		"in_prompt":          `{"model":"m","prompt":"say ` + forbidden + ` please"}`,
		"in_message_content": `{"model":"m","messages":[{"role":"user","content":"say ` + forbidden + `"}]}`,
		"in_metadata":        `{"model":"m","messages":[{"role":"user","content":"hi"}],"metadata":{"note":"` + forbidden + `"}}`,
		"in_tool_desc":       `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"function":{"description":"` + forbidden + `"}}]}`,
		"in_user_field":      `{"model":"m","messages":[{"role":"user","content":"hi"}],"user":"` + forbidden + `"}`,
		"in_object_key":      `{"model":"m","messages":[{"role":"user","content":"hi"}],"` + forbidden + `":"v"}`,
		"in_stop_array":      `{"model":"m","messages":[{"role":"user","content":"hi"}],"stop":["` + forbidden + `"]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			var forwarded []byte
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(r.Body)
				forwarded = buf.Bytes()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(okJSONResponse))
			}))
			t.Cleanup(up.Close)

			var auditBuf bytes.Buffer
			gw := newTestGateway(t, rules, &auditBuf)
			gw.UpstreamURL = up.URL
			gw.Redactor = shapeRedactor{}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("X-API-Key", longSecretKey)
			gw.ServeHTTP(rr, req)

			audit := auditBuf.String()
			t.Logf("status=%d forwarded=%d audit=%.200s", rr.Code, len(forwarded), audit)

			if rr.Code != http.StatusForbidden {
				t.Errorf("BL-11 POLICY BYPASS: the deny rule did not fire for %s "+
					"(status %d); the forbidden phrase was hidden by field choice", name, rr.Code)
			}
			if len(forwarded) > 0 {
				t.Errorf("BL-11 POLICY BYPASS: a denied request was still forwarded "+
					"upstream (%d bytes): %s", len(forwarded), forwarded)
			}
			// The trail must record a BLOCKING action, not allow. The product's
			// value is "deny" (policy.Deny), not "denied" - the streaming-refusal
			// and shape-guard paths use the literal "denied". Accept either, since
			// both mean the request was blocked, but reject "allow".
			if !strings.Contains(audit, `"action":"deny"`) &&
				!strings.Contains(audit, `"action":"denied"`) {
				t.Errorf("the audit trail records neither deny nor denied for a "+
					"blocked request: %s", audit)
			}
			if strings.Contains(audit, `"action":"allow"`) {
				t.Errorf("the audit trail claims allow for a request that was denied: %s", audit)
			}
		})
	}
}

// BL-11 must not break legitimate traffic: sweeping every request string cannot
// turn into refusing or mangling normal requests. Model, temperature, max_tokens,
// stream-when-permitted, tools schema and response_format must all survive, and a
// clean request must not be rewritten at all.
func TestBL11_SweepPreservesLegitimateRequestFields(t *testing.T) {
	body := `{"model":"gpt-4o","temperature":0.3,"max_tokens":128,"top_p":0.9,` +
		`"stop":["END"],"n":2,"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],` +
		`"tool_choice":"auto","response_format":{"type":"json_object"},` +
		`"messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hello there"}]}`

	var forwarded []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		forwarded = buf.Bytes()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okJSONResponse))
	}))
	t.Cleanup(up.Close)

	var auditBuf bytes.Buffer
	gw := newTestGateway(t, nil, &auditBuf)
	gw.UpstreamURL = up.URL
	gw.Redactor = shapeRedactor{}
	gw.RedactRequest = true

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("a clean request was refused: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(forwarded, &got); err != nil {
		t.Fatalf("forwarded body is not valid JSON: %v (%s)", err, forwarded)
	}
	for _, field := range []string{"model", "temperature", "max_tokens", "top_p",
		"stop", "n", "tools", "tool_choice", "response_format", "messages"} {
		if _, ok := got[field]; !ok {
			t.Errorf("the sweep DROPPED the client's %q field - over-redaction is a "+
				"functional break, not a safety win. forwarded=%s", field, forwarded)
		}
	}
	if got["model"] != "gpt-4o" {
		t.Errorf("model was rewritten: %v", got["model"])
	}
	// Nothing sensitive, so nothing should have been reported as redacted.
	if strings.Contains(auditBuf.String(), "req:EMAIL") {
		t.Errorf("a clean request was reported as redacted: %s", auditBuf.String())
	}
}

// BL-12: response HEADERS are bytes the gateway serves, so "no branch serves
// uninspected bytes" was false while header values passed through verbatim.
// The reviewer's reproduction: X-Model-Output carrying an email, at every status.
func TestBL12_NonStandardResponseHeadersAreRedacted(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadRequest} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Model-Output", piiMarker)
				w.Header().Set("X-User-Email", piiMarker)
				w.Header().Set("X-Custom-Trace", "clean-value")
				w.WriteHeader(status)
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

			for _, h := range []string{"X-Model-Output", "X-User-Email"} {
				v := rr.Header().Get(h)
				t.Logf("%s=%q", h, v)
				if strings.Contains(v, piiMarker) {
					t.Errorf("BL-12 LEAK: header %s served PII verbatim at status %d: %q",
						h, status, v)
				}
				if v == "" {
					t.Errorf("header %s was dropped entirely; redacting is preferable to "+
						"deleting, since the client may rely on its presence", h)
				}
			}
			// Positive control: a clean custom header must still pass through,
			// proving headers are redacted rather than wholesale stripped.
			if v := rr.Header().Get("X-Custom-Trace"); v != "clean-value" {
				t.Errorf("a clean custom header was destroyed: %q", v)
			}
			if !strings.Contains(auditBuf.String(), "resp_hdr:") {
				t.Errorf("the header redaction was not recorded in the audit trail: %s",
					auditBuf.String())
			}
		})
	}
}

// BL-12's scope decision, pinned so it cannot silently widen or narrow: standard
// protocol headers are spared (a PII regex over Date or Cache-Control could break
// content negotiation for no security gain), and an UNKNOWN header falls through
// to being swept - because the spare-list is positive, not a negative list of
// names to redact. A negative list would repeat the enumeration mistake.
func TestBL12_StandardHeadersSparedUnknownHeadersSwept(t *testing.T) {
	standard := []string{"Content-Type", "Date", "Cache-Control", "X-Request-Id"}
	unknown := []string{"X-Something-Nobody-Listed", "X-Provider-Internal-Note", "Totally-Made-Up"}

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for _, h := range unknown {
			w.Header().Set(h, piiMarker)
		}
		// Content-Type must NOT be rewritten even though a regex could match it;
		// breaking it would make the client unable to parse the body.
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

	for _, h := range unknown {
		if v := rr.Header().Get(h); strings.Contains(v, piiMarker) {
			t.Errorf("BL-12: unknown header %s was not swept (a negative spare-list "+
				"would let it through): %q", h, v)
		}
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("a standard protocol header was rewritten, which can break the "+
			"client's ability to parse the body: %q", ct)
	}
	_ = standard
	// isNonStandardHeader is the load-bearing decision; pin it directly too.
	//
	// BL-22 REMOVED "Etag" from this list on purpose, and it used to be asserted here.
	// The criterion the list applied was "is this header part of the HTTP protocol
	// vocabulary", on the assumption that such values are stack-generated. Etag's value
	// is an opaque QUOTED STRING of the origin's choosing — exactly where a hostile
	// upstream can hide a credential — so the assumption is false for it. Same for
	// Location, Content-Location, Content-Disposition (a filename!), Warning and Server.
	// Removing a name from a SPARE list means MORE sweeping, so the change is fail-safe.
	for _, h := range []string{"Content-Type", "Content-Length", "Date", "Cache-Control",
		"Last-Modified", "X-Request-Id", "Strict-Transport-Security"} {
		if isNonStandardHeader(http.CanonicalHeaderKey(h)) {
			t.Errorf("%s was classified non-standard and would be swept; it is protocol "+
				"metadata the client needs", h)
		}
	}
	// And the BL-22 direction: these standard headers carry origin-chosen free text or
	// URIs, so they MUST be swept now. If someone re-adds one to the spare list, this
	// fails and points at the reason.
	for _, h := range []string{"Etag", "Location", "Content-Location",
		"Content-Disposition", "Warning", "Server"} {
		if !isNonStandardHeader(http.CanonicalHeaderKey(h)) {
			t.Errorf("BL-22 regression: %s was re-added to the spare list. Its value is "+
				"origin-chosen free text or a URI, so a hostile upstream can put a "+
				"credential in it — the round-8 reviewer served Location: "+
				"https://attacker.example/collect?tok=<credential> to the client "+
				"byte-for-byte on a 200", h)
		}
	}
	for _, h := range []string{"X-Model-Output", "X-User-Email", "X-Made-Up", "Foo"} {
		if !isNonStandardHeader(http.CanonicalHeaderKey(h)) {
			t.Errorf("%s was classified standard and would be spared; an unknown header "+
				"must default to being swept", h)
		}
	}
}

// BL-13: upstream-unreachable wrote NO audit event. The request had already passed
// policy and rate limiting, so a 502 left an empty trail - a hole in a
// tamper-evident record, the same class the handler-panic fix closed.
func TestBL13_UpstreamUnreachableWritesAuditEvent(t *testing.T) {
	var auditBuf bytes.Buffer
	gw := newTestGateway(t, nil, &auditBuf)
	// A URL nothing listens on: connection refused, deterministically.
	gw.UpstreamURL = "http://127.0.0.1:1/v1/chat/completions"
	gw.Redactor = shapeRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for an unreachable upstream, got %d", rr.Code)
	}
	audit := auditBuf.String()
	t.Logf("audit=%.300s", audit)
	if strings.TrimSpace(audit) == "" {
		t.Errorf("BL-13: an upstream-unreachable request produced NO audit event; the " +
			"trail has a hole for a request that passed policy and rate limiting")
	}
	if !strings.Contains(audit, "upstream_error") {
		t.Errorf("the audit event does not name the failure: %s", audit)
	}
	if !strings.Contains(audit, "upstream-unreachable") {
		t.Errorf("the audit event lacks a rule identifying the cause: %s", audit)
	}
	// The key must be masked, like every other event.
	if strings.Contains(audit, longSecretKey) {
		t.Errorf("BL-13 regression: the raw API key reached the audit log: %s", audit)
	}
	// The load-bearing assertion is the one above (raw key absent). This second one
	// uses the product's own maskKey, so it is mildly circular - it pins that the
	// event is ATTRIBUTABLE to a caller, not that the masking itself is strong.
	if !strings.Contains(audit, maskKey(longSecretKey)) {
		t.Errorf("the masked key form is missing, so the event is not attributable: %s", audit)
	}
}

// BL-13's sibling: the NewRequestWithContext failure has the same shape. It is
// unreachable with a configured URL (the reviewer noted this), so pin it at the
// behaviour level that IS reachable - an invalid upstream URL - and require an
// event rather than a silent 502.
func TestBL13_InvalidUpstreamURLWritesAuditEvent(t *testing.T) {
	var auditBuf bytes.Buffer
	gw := newTestGateway(t, nil, &auditBuf)
	gw.UpstreamURL = "://not-a-valid-url"
	gw.Redactor = shapeRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for an invalid upstream URL, got %d", rr.Code)
	}
	if strings.TrimSpace(auditBuf.String()) == "" {
		t.Errorf("an invalid upstream URL produced NO audit event; the trail has a hole")
	}
}

// N3: the non-JSON TEXT path appends to ev.Redactions, but nothing pinned it -
// the reviewer's mutation deleting that append SURVIVED the whole suite, because
// INVAR-3 was only checked on JSON bodies. Text bodies must be pinned identically.
func TestN3_TextPathRedactionsAreRecordedInAudit(t *testing.T) {
	for _, ct := range []string{"text/plain", "text/html", "application/xml", ""} {
		t.Run("ct="+ct, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ct != "" {
					w.Header().Set("Content-Type", ct)
				}
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("upstream error: contact " + piiMarker + " for help"))
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

			client := rr.Body.String()
			audit := auditBuf.String()
			t.Logf("client=%.200s", client)

			// INVAR-1: no raw PII reaches the client.
			if strings.Contains(client, piiMarker) {
				t.Errorf("LEAK on the text path (content-type %q): %s", ct, client)
			}
			// INVAR-3, the part that was unpinned: the trail must RECORD the
			// redaction it performed. Under-reporting loses the evidence that PII
			// was handled, which is the same two-sided invariant the JSON path has.
			if !strings.Contains(audit, "resp:EMAIL") {
				t.Errorf("N3: the text path redacted PII but recorded NO redaction in "+
					"the audit event (content-type %q): %s", ct, audit)
			}
			// The status must be preserved: an upstream 500 stays a 500.
			if rr.Code != http.StatusInternalServerError {
				t.Errorf("status not preserved on the text path: got %d, want 500", rr.Code)
			}
			// Positive control: the diagnostic text survived, so this was redaction
			// and not a wholesale refusal.
			if !strings.Contains(client, "upstream error") {
				t.Errorf("the diagnostic text was destroyed rather than redacted: %s", client)
			}
		})
	}
}

// BL-9 complement: a genuine base64 payload must still be spared (the exemption's
// legitimate purpose), and the spare must be recorded. Verified separately from
// the non-base64 rejection so neither direction is vacuous.
func TestBL9_GenuineBase64IsSparedAndRecorded(t *testing.T) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		payload := enc.EncodeToString([]byte("some binary bytes that are not text at all"))
		t.Run(fmt.Sprintf("len%d", len(payload)), func(t *testing.T) {
			body := `{"id":"x","b64_json":"` + payload + `","choices":[]}`
			up := serveStatusAndBody(t, http.StatusOK, body)

			var auditBuf bytes.Buffer
			gw := newTestGateway(t, nil, &auditBuf)
			gw.UpstreamURL = up.URL
			gw.Redactor = shapeRedactor{}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
				strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
			req.Header.Set("X-API-Key", longSecretKey)
			gw.ServeHTTP(rr, req)

			if !strings.Contains(rr.Body.String(), payload) {
				t.Errorf("a genuine base64 payload was mangled, which would corrupt "+
					"data the client cannot decode: %s", rr.Body.String())
			}
			audit := auditBuf.String()
			// Both channels, pinned separately - see the M3 note in sweep_test.go.
			// Either string alone is satisfiable while the other is silently
			// missing, which is how mutation M3 survived.
			if !strings.Contains(audit, `"resp:opaque_skipped"`) {
				t.Errorf("the opaque skip left no redaction KIND, so the trail cannot "+
					"account for uninspected bytes: %s", audit)
			}
			if !strings.Contains(audit, `"redaction":"opaque_skipped"`) {
				t.Errorf("the opaque skip left no META diagnostic: %s", audit)
			}
		})
	}
}
