package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/redactor"
)

// findingRedactor reports every non-empty input as sensitive without altering it.
// Used to drive the "PII found but the body could not be rewritten" branch.
type findingRedactor struct{}

func (findingRedactor) Redact(text string) (string, []string) {
	if strings.TrimSpace(text) == "" {
		return text, nil
	}
	return text, []string{"EMAIL"}
}

var _ redactor.Redactor = findingRedactor{}

const okJSONResponse = `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":2}}`

// RC#2 branch: sensitive content was found but json.Marshal of the parsed request
// failed, so the caller must fail closed instead of forwarding the original
// PII-bearing bytes while the audit trail claims a redaction happened.
//
// This exercises redactRequestContent directly. The same branch is not reachable
// through ServeHTTP with a well-formed request: encoding/json only produces
// marshalable values when decoding into map[string]any, so the handler's 422 path
// is defensive. Testing the function is what actually pins the contract.
func TestRedactionMarshalErrorFailsClosed(t *testing.T) {
	// A channel cannot be marshalled, so re-marshalling fails AFTER the redactor
	// reported a finding.
	poisoned := map[string]any{
		"messages": []any{
			map[string]any{
				"role":    "user",
				"content": "jane.doe@example.com",
				"bad":     make(chan int),
			},
		},
	}

	body, kinds, err := redactRequestContent(poisoned, findingRedactor{})
	t.Logf("body=%v kinds=%v err=%v", body, kinds, err)

	if err == nil {
		t.Fatalf("expected a marshal error for an unmarshalable request, got nil (kinds=%v)", kinds)
	}
	if len(kinds) == 0 {
		t.Error("the finding must still be reported even though the rewrite failed, " +
			"otherwise the caller cannot tell 'nothing sensitive' from 'could not redact'")
	}
	if body != nil {
		t.Errorf("a failed rewrite must not return a body to forward: %s", body)
	}
}

// Nothing sensitive -> no rewrite, no error. This is what distinguishes the
// (nil, nil, nil) return from the failure case above; collapsing the two is how
// the original bug forwarded raw PII under a "redacted" audit line.
func TestRedactionNoFindingsIsNotAnError(t *testing.T) {
	clean := map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": ""}},
	}
	body, kinds, err := redactRequestContent(clean, findingRedactor{})
	t.Logf("body=%v kinds=%v err=%v", body, kinds, err)
	if err != nil {
		t.Errorf("nothing sensitive must not be reported as a redaction failure: %v", err)
	}
	if len(kinds) != 0 {
		t.Errorf("no findings expected, got %v", kinds)
	}
	if body != nil {
		t.Errorf("no rewrite should be returned when nothing was redacted: %s", body)
	}
}

// RC#5: headers the upstream names in its Connection header are hop-by-hop for
// this connection specifically (RFC 9110 §7.6.1) and must not be forwarded, even
// though their names are not in the static isHopByHop set. Unrelated headers must
// still pass.
func TestConnectionListedHeadersNotForwarded(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "X-Custom-Hop, X-Another")
		w.Header().Set("X-Custom-Hop", "leak-me")
		w.Header().Set("X-Another", "also-leak")
		w.Header().Set("X-Safe", "keep-me")
		_, _ = io.WriteString(w, okJSONResponse)
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("X-Custom-Hop=%q X-Another=%q X-Safe=%q",
		rr.Header().Get("X-Custom-Hop"), rr.Header().Get("X-Another"), rr.Header().Get("X-Safe"))

	if v := rr.Header().Get("X-Custom-Hop"); v != "" {
		t.Errorf("a Connection-listed header was forwarded: %q", v)
	}
	if v := rr.Header().Get("X-Another"); v != "" {
		t.Errorf("a Connection-listed header was forwarded: %q", v)
	}
	if v := rr.Header().Get("X-Safe"); v != "keep-me" {
		t.Errorf("an unrelated header was wrongly dropped: %q", v)
	}
}

// When the served body differs from the upstream body, validators describing the
// upstream bytes must not be served for it: a client could otherwise cache the
// redacted bytes under an identity that maps to the unredacted ones, and later be
// served them from cache with no gateway in the path at all.
func TestETagDroppedWhenBodyRewritten(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", `"abc123"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		// Response content carries PII, so redaction rewrites the body.
		_, _ = io.WriteString(w, `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"her email is jane.doe@example.com"},"finish_reason":"stop"}],"usage":{"total_tokens":2}}`)
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	body := rr.Body.String()
	t.Logf("status=%d etag=%q last-modified=%q cache-control=%q body=%.160s",
		rr.Code, rr.Header().Get("Etag"), rr.Header().Get("Last-Modified"),
		rr.Header().Get("Cache-Control"), body)

	if strings.Contains(body, "jane.doe@example.com") {
		t.Fatalf("response PII was not redacted: %s", body)
	}
	if v := rr.Header().Get("Etag"); v != "" {
		t.Errorf("ETag describing the unredacted upstream body was served for the redacted one: %q", v)
	}
	if v := rr.Header().Get("Last-Modified"); v != "" {
		t.Errorf("Last-Modified was served for a rewritten body: %q", v)
	}
	if cc := rr.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("a rewritten body should be marked no-store, got %q", cc)
	}
	if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(rr.Body.Len()) {
		t.Errorf("Content-Length=%q does not match the rewritten body length %d", cl, rr.Body.Len())
	}
}

// A SUCCESSFUL non-JSON upstream response cannot be inspected, so with
// RedactResponse enabled it must not reach the client. This is the same
// unredactable-to-client path as streaming, reached by content-type rather than
// by stream:true.
func TestUnparseableSuccessResponseFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "her secret is jane.doe@example.com")
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("status=%d body=%.200s audit=%.300s", rr.Code, rr.Body.String(), buf.String())

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("a successful non-JSON body must fail closed with 502, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "jane.doe@example.com") {
		t.Errorf("LEAK: an unredactable success body reached the client: %s", rr.Body.String())
	}
	if !strings.Contains(buf.String(), "unparseable_success_response") {
		t.Errorf("the fail-closed reason was not audited: %s", buf.String())
	}
}

// The complement: an upstream ERROR page is diagnostic, not model output, and must
// pass through unaltered or upstream failures become undebuggable.
func TestUpstreamErrorPageStillPassesThrough(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream exploded")
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("status=%d body=%q", rr.Code, rr.Body.String())

	if rr.Code != http.StatusBadGateway {
		t.Errorf("the upstream error status was not passed through, got %d", rr.Code)
	}
	if rr.Body.String() != "upstream exploded" {
		t.Errorf("the error body was altered: %q", rr.Body.String())
	}
	if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(rr.Body.Len()) {
		t.Errorf("Content-Length=%q does not match body length %d", cl, rr.Body.Len())
	}
}

// RC#4: usage figures emitted as a JSON string must still be accounted for.
// Refusing to parse them recorded zero tokens and skipped the budget check, which
// is an accounting bypass rather than a formatting quirk.
func TestStringUsageAccounted(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":"100","completion_tokens":"50","total_tokens":"150"}}`)
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	_ = post(t, gw, "gpt-4o", "hello")
	toks, _ := gw.Limiter.Usage("test-key")
	t.Logf("tokens recorded=%d (want 150) audit=%.260s", toks, buf.String())
	if toks != 150 {
		t.Errorf("string total_tokens was not recorded: got %d", toks)
	}
	if strings.Contains(buf.String(), `"usage":"unparseable"`) {
		t.Errorf("a parseable usage figure was reported unparseable: %s", buf.String())
	}
}

// Missing usage must be audited as unparseable rather than silently recording
// zero, so the audit trail shows the accounting gap instead of implying the
// request cost nothing.
func TestMissingUsageAuditedAsUnparseable(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("status=%d audit=%.300s", rr.Code, buf.String())
	if rr.Code != http.StatusOK {
		t.Fatalf("a valid response without usage should still succeed, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), `"usage":"unparseable"`) {
		t.Errorf("missing usage was not recorded in the audit trail: %s", buf.String())
	}
	toks, _ := gw.Limiter.Usage("test-key")
	if toks != 0 {
		t.Errorf("no usage was present, so nothing should have been recorded: %d", toks)
	}
}

// Numeric usage keeps working (the common case), so the string tolerance above did
// not regress ordinary accounting.
func TestNumericUsageStillAccounted(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":42}}`)
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	_ = post(t, gw, "gpt-4o", "hello")
	toks, _ := gw.Limiter.Usage("test-key")
	t.Logf("tokens recorded=%d (want 42)", toks)
	if toks != 42 {
		t.Errorf("numeric total_tokens was not recorded: got %d", toks)
	}
}

// A malformed usage string must not panic or record a bogus figure; it is reported
// unparseable like a missing one.
func TestMalformedUsageStringAudited(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":"not-a-number"}}`)
	}))
	t.Cleanup(up.Close)
	gw.UpstreamURL = up.URL

	rr := post(t, gw, "gpt-4o", "hello")
	t.Logf("status=%d audit=%.300s", rr.Code, buf.String())
	if rr.Code != http.StatusOK {
		t.Fatalf("a malformed usage figure should not fail the request, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), `"usage":"unparseable"`) {
		t.Errorf("a malformed usage figure was not audited as unparseable: %s", buf.String())
	}
}
