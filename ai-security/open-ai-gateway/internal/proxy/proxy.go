// Package proxy is the gateway core: it inspects, filters, rate-limits,
// forwards and audits LLM/agent traffic.
package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Schildkrote/open-ai-gateway/internal/audit"
	"github.com/Schildkrote/open-ai-gateway/internal/policy"
	"github.com/Schildkrote/open-ai-gateway/internal/ratelimit"
	"github.com/Schildkrote/open-ai-gateway/internal/redactor"
)

// Gateway holds the dependencies for request handling.
type Gateway struct {
	UpstreamURL    string
	Engine         *policy.Engine
	Limiter        *ratelimit.Limiter
	Audit          *audit.Logger
	RedactRequest  bool // always redact request bodies (in addition to policy)
	RedactResponse bool
	Client         *http.Client
	Authorize      func(*http.Request) // optional provider auth (Phase 3 LLM connectors)
	Redactor       redactor.Redactor   // optional redaction backend (default: regex)
}

// redactor returns the configured redaction backend, defaulting to regex.
func (g *Gateway) redactor() redactor.Redactor {
	if g.Redactor != nil {
		return g.Redactor
	}
	return redactor.Regex{}
}

func (g *Gateway) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return http.DefaultClient
}

// ServeHTTP implements the gateway decision pipeline.
// maxBodyBytes bounds how much of a request or response body the gateway buffers.
// Both are read fully into memory before any decision can be made, so an unbounded
// read is a memory-exhaustion vector aimed at the gateway itself.
const maxBodyBytes = 32 << 20 // 32 MiB

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Resolved before the recovery handler is registered, because that handler
	// closes over it. A closure cannot capture a variable that is not yet in
	// scope: declaring this after the defer made the panic event the one audit
	// record that could never name its caller - and for a gateway whose selling
	// point is a tamper-evident trail, the event a misbehaving Redactor produces
	// is precisely the one that must be attributable. It also sits above the
	// body-size refusal so that path is attributed too.
	apiKey := extractKey(r)

	// A misbehaving Redactor (e.g. a backend that panics on malformed input) must
	// not escape the handler. net/http recovers per connection so the process
	// survives - but the panic left ZERO audit events for a request that WAS
	// processed, and for a gateway whose selling point is a tamper-evident trail
	// that gap is itself the defect. Recovering keeps the chain complete.
	defer func() {
		if rec := recover(); rec != nil {
			// Attributed: the closure captures by reference, and the key is
			// resolved above, so the panic event can name the caller. Without
			// this the one event a misbehaving Redactor produces is the one that
			// cannot be traced.
			g.log(audit.Event{APIKey: maskKey(apiKey), Action: "error", Rule: "handler-panic",
				Reason: fmt.Sprintf("recovered from panic: %v", rec)})
			http.Error(w, "internal gateway error", http.StatusInternalServerError)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) > maxBodyBytes {
		g.log(audit.Event{APIKey: maskKey(apiKey), Action: "denied", Rule: "request-too-large",
			Reason: "request body exceeds the gateway's buffering limit"})
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error":  "request body too large",
			"detail": fmt.Sprintf("limit is %d bytes", maxBodyBytes),
		})
		return
	}

	// Parse the request as a generic map rather than a narrow struct. The old
	// code did `_ = json.Unmarshal(body, &req)` into a chatRequest whose message
	// content was typed `string`, and DISCARDED the error. OpenAI's multimodal
	// form sends content as an array of parts:
	//
	//	{"role":"user","content":[{"type":"text","text":"..."}]}
	//
	// That unmarshal failed, req.Messages stayed empty, and content came out
	// EMPTY - so policy ContentRe rules could not match and the redactor had
	// nothing to redact. Verified against origin/main before fixing: a deny rule
	// on "FORBIDDEN" returned 403 for plain string content but 200 for the same
	// text in multimodal form, and an email address was forwarded upstream
	// unredacted. That is a bypass-by-request-shape against a gateway whose
	// whole purpose is policy enforcement and PII removal.
	//
	// Failing closed matters here: a body we cannot inspect must not be
	// forwarded uninspected.

	// Set when the bytes the gateway sends to the CLIENT no longer match what
	// upstream returned, so validator headers describing upstream's body cannot be
	// copied verbatim.
	//
	// Only the response side needs a flag. A request-side redaction changes what
	// upstream RECEIVES, not what comes back, so it must not strip the response's
	// ETag/Last-Modified - the earlier single conflated flag did exactly that,
	// dropping validators for a response body that was byte-identical to
	// upstream's. Whether the request was rewritten is already carried by
	// ev.Redactions, so a second flag would be redundant.
	responseRewritten := false

	parsedReq, reqErr := decodeJSONObject(body)
	if reqErr != nil {
		g.log(audit.Event{APIKey: maskKey(apiKey), Action: "denied", Rule: "malformed-request",
			Reason: "request body is not a JSON object; refusing to forward uninspected content"})
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "request body must be a JSON object",
			"detail": reqErr.Error(),
		})
		return
	}
	model := stringField(parsedReq, "model")
	// Only contentOK is used now. extractContent remains the SHAPE guard that
	// fails closed when the message container itself cannot be read; BL-11 moved
	// the policy view to every string in the body (see Evaluate below), so the
	// extracted text is no longer what policy reads.
	_, contentOK := extractContent(parsedReq)

	ev := audit.Event{APIKey: maskKey(apiKey), Model: model}

	// 1. Policy decision.
	//
	// BL-11: policy now evaluates EVERY string in the request body, not just the
	// messages[].content that extractContent could read. A ContentRe deny rule that
	// only saw message content was bypassable by field choice - the reviewer
	// reproduced {"model":"m","prompt":"say FORBIDDEN please"} passing a rule that
	// denied "FORBIDDEN", audited as action:"allow". allRequestStrings covers
	// prompt, metadata, tool descriptions, the user field, data URIs and object
	// keys, in a deterministic order so decisions are reproducible.
	dec := g.Engine.Evaluate(policy.Request{Model: model, Content: allRequestStrings(parsedReq), APIKey: apiKey})
	ev.Action = string(dec.Action)
	ev.Rule = dec.Rule
	ev.Reason = dec.Reason

	// If messages were present but we could not read them as text, we cannot
	// honestly say the content was inspected. Fail closed rather than forward
	// uninspected content past policy and redaction.
	// !contentOK means extractContent saw input it could not read. That is
	// sufficient on its own: it returns ok=true when messages is absent or null
	// (nothing to inspect), and ok=false both for a non-array messages container
	// and for an unreadable element or content shape. Gating this on a second
	// shape check would re-suppress the non-array container case, which is exactly
	// the bypass being closed.
	if !contentOK {
		// Record the refusal as a refusal. ev.Action still holds whatever the
		// policy engine decided - "allow" under an allow-default config - so an
		// event written here reads as a successful forward for a request that was
		// actually rejected with 400. The streaming refusal already set
		// action:"denied"; this path must agree with it or the trail misrepresents
		// its own outcome.
		ev.Action = "denied"
		ev.Rule = "unsupported-content-shape"
		ev.Reason = "message content is not in a shape the gateway can inspect"
		g.log(ev)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "message content is not in a supported shape",
			"detail": "expected a string or an array of {type:text,text:string} parts",
		})
		return
	}

	if dec.Action == policy.Deny {
		g.log(ev)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "denied by policy", "rule": dec.Rule, "reason": dec.Reason})
		return
	}

	// 2. Rate limit.
	if !g.Limiter.AllowRequest(apiKey, nowFn()) {
		ev.Action = "rate_limited"
		g.log(ev)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
		return
	}

	// Streaming is refused while response redaction is enabled.
	//
	// An SSE upstream response is not JSON, so the parse below fails and BOTH
	// response redaction and usage accounting are skipped: the stream is forwarded
	// to the client verbatim (any PII the model emits included) and records zero
	// tokens, which is also a budget bypass. Preserving the client's stream:true
	// field is correct in itself - dropping it silently changed what the client
	// asked for - but it opened that unredactable path. Fail closed instead of
	// silently disabling the gateway's core function; SSE-aware redaction is the
	// follow-up.
	if g.RedactResponse && wantsStreaming(parsedReq) {
		ev.Action = "denied"
		ev.Rule = "streaming-unsupported"
		ev.Reason = "streaming responses cannot be redacted or accounted for; refused"
		g.log(ev)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "streaming is not supported while response redaction is enabled",
			"detail": "re-send the request without stream:true, or set " +
				`"redact_response": false` + " in the gateway config",
		})
		return
	}

	// 3. Request redaction.
	//
	// Redaction rewrites the ORIGINAL body as a generic map rather than
	// re-marshalling a narrow struct. RedactRequest defaults to true, so the old
	// `body, _ = json.Marshal(req)` path silently dropped every field the client
	// sent beyond model+messages: stream, temperature, top_p, max_tokens, stop,
	// n, tools, tool_choice, response_format. A streaming client would receive a
	// non-streaming upstream call and tool-calling clients would lose their tool
	// schema, with no error anywhere.
	//
	// Content is redacted IN PLACE per message/per text part, never by writing
	// one flattened string back into a single message: flattening would destroy a
	// multimodal message's image parts and collapse several messages into one, so
	// what reached upstream would no longer mean what the client sent.
	if g.RedactRequest || dec.Action == policy.Redact {
		rewritten, kinds, err := redactRequestContent(parsedReq, g.redactor())
		switch {
		case err != nil:
			// Sensitive content WAS found but the body could not be rewritten.
			// Forwarding the original would leak PII upstream while the audit
			// trail claims it was redacted, so fail closed instead.
			ev.Action = "redaction_failed"
			ev.Redactions = append(ev.Redactions, kinds...)
			ev.Meta = map[string]any{"redaction": "rewrite_failed"}
			g.log(ev)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error": "request could not be redacted; refusing to forward it",
			})
			return
		case len(kinds) > 0:
			body = rewritten
			ev.Redactions = append(ev.Redactions, kinds...)
		}
	}

	// 4. Forward upstream.
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.UpstreamURL, bytes.NewReader(body))
	if err != nil {
		// BL-13 sibling: same hole as the unreachable-upstream path below. The
		// reviewer judged this unreachable with a configured URL, which is right
		// for a well-formed config - but a malformed g.UpstreamURL reaches it, and
		// a processed-and-failed request that writes no event is a hole in a
		// tamper-evident trail either way. err.Error() can echo the configured
		// URL, so the reason is fixed text and the key is masked.
		ev.Action = "upstream_error"
		ev.Rule = "upstream-request-invalid"
		ev.Reason = "upstream request could not be constructed"
		setMeta(&ev, "upstream", "request_construction_failed")
		g.log(ev)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	if g.Authorize != nil {
		g.Authorize(upReq)
	}
	resp, err := g.client().Do(upReq)
	if err != nil {
		// BL-13: this path wrote NO audit event, so a request that had already
		// passed policy and rate limiting produced a 502 and an empty trail. For a
		// product whose selling point is a tamper-evident record, a
		// processed-and-failed request with zero events is a hole in the trail -
		// the same class the handler-panic fix closed. Mirror the read-error path
		// below. The transport error text can contain the upstream URL and DNS
		// detail, so it is recorded as a fixed reason rather than err.Error(); the
		// key is masked like every other event.
		ev.Action = "upstream_error"
		ev.Rule = "upstream-unreachable"
		ev.Reason = "upstream connection could not be established"
		setMeta(&ev, "upstream", "connect_failed")
		g.log(ev)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	// The read error must not be discarded: a truncated upstream body is not the
	// same as a complete one, and forwarding partial bytes while announcing their
	// length is exactly how the original Content-Length bug presented.
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if readErr != nil {
		ev.Action = "upstream_error"
		setMeta(&ev, "upstream", "response_read_failed")
		g.log(ev)
		http.Error(w, "upstream response could not be read", http.StatusBadGateway)
		return
	}
	if len(respBody) > maxBodyBytes {
		ev.Action = "upstream_error"
		setMeta(&ev, "upstream", "response_too_large")
		g.log(ev)
		http.Error(w, "upstream response too large", http.StatusBadGateway)
		return
	}

	// 5. Response redaction + usage accounting.
	//
	// The response is handled as a generic map rather than a narrow struct on
	// purpose. Redaction used to unmarshal into a narrow struct (choices[].message
	// + usage.total_tokens only) and re-marshal that, which silently DROPPED
	// every other upstream field — id, object, created, model, system_fingerprint,
	// choices[].index and choices[].finish_reason, and the prompt_tokens /
	// completion_tokens breakdown. Clients that read finish_reason to detect
	// truncation, or model for routing/logging, got an OpenAI-incompatible
	// response. RedactResponse defaults to true, so this was the normal path.
	// A map round-trip preserves unknown fields and cannot drift when upstream
	// adds one.
	var parsed map[string]any
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		// A response that is not JSON cannot be swept structurally, so it is swept
		// as TEXT instead.
		//
		// This path used to branch on the status code: a 2xx non-JSON body was
		// refused with 502, while an error body was passed through untouched on the
		// reasoning that an upstream 502 page is diagnostic rather than model
		// output. The reasoning is right about real proxy error pages and wrong
		// about the security property, because it makes the decision to inspect
		// bytes depend on a value the UPSTREAM controls. A compromised or
		// misconfigured upstream only has to answer 500 text/plain - or omit the
		// content type entirely - and its body reaches the client uninspected.
		// Verified: a text/plain 500 carrying an email address was served verbatim
		// through text/html, application/xml and no-content-type variants alike.
		//
		// Redacting the raw text closes that without costing the diagnostic. The
		// redactor operates on text; running it over an error page leaves
		// "502 Bad Gateway / nginx / upstream timed out" intact and removes only
		// what looks like PII. A pinned test asserts a real nginx page survives
		// byte-for-byte.
		//
		// Binary bodies are the one case text redaction cannot serve, so they fail
		// closed at EVERY status rather than at 2xx only. "Not valid UTF-8" is the
		// test: a regex pass over image or audio bytes cannot find PII and would
		// corrupt the payload, so there is nothing honest to do but refuse.
		setMeta(&ev, "response", "unparseable")
		if g.RedactResponse {
			// A 2xx non-JSON body is refused, and the reason is ACCOUNTING, not
			// redaction. A successful completion is a billable, rate-limited
			// action, but no usage figure can be extracted from a body that is not
			// JSON - so serving it would record a success at zero tokens. That is
			// the BL-2 budget-bypass class: completions that escape the token
			// budget. The round-1 fix chose fail-loud accounting over recording
			// zero, and this path has to be consistent with that. The body never
			// reaches the client, so nothing leaks by refusing it.
			if isSuccessfulStatus(resp.StatusCode) {
				ev.Action = "redaction_failed"
				setMeta(&ev, "redaction", "unparseable_success_response")
				g.log(ev)
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error": "upstream returned a successful response that could not be redacted",
				})
				return
			}

			// A non-2xx body is diagnostic, not a billable completion, so there is
			// no accounting expectation and it SHOULD reach the client - an
			// upstream 429/502 page is exactly what the caller needs to debug the
			// failure. But "pass it through" must not mean "pass it through
			// UNREDACTED", which is what this branch did before and is how a
			// compromised upstream could leak model output under a 500 text/plain.
			// Redact the text and serve it with its status intact: a real nginx
			// error page survives byte-for-byte, only PII is removed.
			//
			// Binary is the one case text redaction cannot serve - a regex pass
			// over image or audio bytes neither finds PII nor leaves the payload
			// decodable - so it fails closed at every status. "Not valid UTF-8" is
			// the test.
			if !utf8.Valid(respBody) {
				ev.Action = "redaction_failed"
				setMeta(&ev, "redaction", "uninspectable_binary_response")
				g.log(ev)
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error": "upstream returned a non-UTF-8 response that could not be redacted",
				})
				return
			}
			cleaned, found := g.redactor().Redact(string(respBody))
			for _, k := range found {
				ev.Redactions = append(ev.Redactions, "resp:"+k)
			}
			if cleaned != string(respBody) {
				respBody = []byte(cleaned)
				responseRewritten = true
			}
			// No usage figure is extractable from a non-JSON body, so token
			// accounting stays empty. Recorded rather than silently omitted. An
			// error response is not a billable completion, so zero tokens here is
			// correct rather than a bypass.
			setMeta(&ev, "usage", "unparseable")
		}
	} else {
		if g.RedactResponse {
			// redactResponse re-marshals the parsed map, so the served bytes no
			// longer match what upstream sent even when nothing was redacted.
			// Validator headers describing the upstream body must not be copied.
			before := respBody
			redacted, kinds, opaqueSkipped, err := redactResponse(parsed, g.redactor())
			if opaqueSkipped > 0 {
				// BL-9: an exemption that leaves no diagnostic is indistinguishable
				// from a silent hole. Record that N positions were skipped as
				// verified-opaque binary so the trail accounts for every byte.
				setMeta(&ev, "redaction", "opaque_skipped")
				setMeta(&ev, "opaque_skipped", opaqueSkipped)
			}

			// Record the redactions the sweep applied and serve the re-encoded
			// map. There is no status-code branch here any more, and that is
			// deliberate: the previous version failed closed on 2xx and passed
			// error bodies through, so the gateway trusted an UPSTREAM-CONTROLLED
			// status code for a security decision. A sweep that inspects every
			// string needs no such branch - the only failure left is "could not
			// marshal the result", which fails closed for every status alike.
			//
			// Error diagnostics still survive: the sweep redacts PII out of the
			// error object and leaves its text alone, and resp.StatusCode is
			// written below, so a 429 stays a 429 with its message intact.
			if err != nil {
				ev.Action = "redaction_failed"
				setMeta(&ev, "redaction", "unreencodable_response")
				g.log(ev)
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error": "upstream response could not be redacted",
				})
				return
			}
			respBody = redacted
			ev.Redactions = append(ev.Redactions, kinds...)

			if !bytes.Equal(before, respBody) {
				responseRewritten = true
			}
		}
		tokens, ok := totalTokens(parsed)
		if !ok {
			// No usable usage figure: say so in the audit record instead of
			// recording zero and letting a budget look unconsumed.
			setMeta(&ev, "usage", "unparseable")
		} else {
			ev.Tokens = tokens
			if !g.Limiter.RecordUsage(apiKey, tokens) {
				setMeta(&ev, "budget", "exceeded")
			}
		}
	}

	// Headers listed in the upstream's Connection header are hop-by-hop for this
	// connection specifically (RFC 9110 7.6.1) and must not be forwarded, even
	// though their names are not in the static isHopByHop set.
	connListed := connectionListedHeaders(resp.Header)

	// BL-12: headers are bytes the gateway serves to the client, so the claim
	// "no branch serves uninspected bytes" was false while header VALUES passed
	// through verbatim. The reviewer reproduced an upstream 200 carrying
	// X-Model-Output: <email> reaching the client at every status.
	//
	// The scope is deliberate: only NON-STANDARD headers are redacted, and only
	// when response redaction is enabled. Standard headers are protocol metadata
	// the client needs to interpret the response - running a PII regex over a Date
	// or a Cache-Control could break content negotiation for no security gain, and
	// neither is model output. Custom X-*/provider-specific headers are exactly
	// where an upstream surfaces model or user data, which is what a PII regex is
	// for. isNonStandardHeader is a POSITIVE list of names to spare, so an unknown
	// header falls through to being swept rather than through to being served.
	for k, vs := range resp.Header {
		ck := http.CanonicalHeaderKey(k)
		if isHopByHop(k) || connListed[ck] {
			continue
		}
		for _, v := range vs {
			out := v
			if g.RedactResponse && isNonStandardHeader(ck) {
				cleaned, found := g.redactor().Redact(v)
				if len(found) > 0 {
					out = cleaned
					for _, f := range found {
						ev.Redactions = append(ev.Redactions, "resp_hdr:"+f)
					}
					responseRewritten = true
				}
			}
			w.Header().Add(k, out)
		}
	}
	g.log(ev)

	// Validators describe a specific body. Forwarding upstream's ETag (or
	// Last-Modified) alongside a rewritten body would let a client cache the
	// redacted bytes under an identity that maps to the unredacted ones, and
	// could serve them back from cache with no gateway in the path at all.
	if responseRewritten {
		w.Header().Del("Etag")
		w.Header().Del("Last-Modified")
		w.Header().Set("Cache-Control", "no-store")
	}
	// The body may have been rewritten above, so upstream's Content-Length no
	// longer describes it. Copying it verbatim made the gateway announce more
	// bytes than it wrote, and clients aborted the transfer as truncated
	// (curl CURLE_PARTIAL_FILE / rc=18) despite a complete JSON body. Setting it
	// from the final length keeps the header truthful; net/http would otherwise
	// fall back to chunked encoding.
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// hop-by-hop headers must not be forwarded by a proxy (RFC 9110 §7.6.1), and
// Content-Length is handled explicitly by the caller because the body may be
// rewritten.
func isHopByHop(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length":
		return true
	}
	return false
}

// connectionListedHeaders parses the Connection header and returns the set of
// header names it declares hop-by-hop, canonicalised. A proxy must not forward
// those (RFC 9110 7.6.1); they are connection-scoped rather than
// payload-scoped, so upstream naming them is not an instruction to pass them on.
func connectionListedHeaders(h http.Header) map[string]bool {
	out := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				out[http.CanonicalHeaderKey(name)] = true
			}
		}
	}
	return out
}

// redactResponse redacts model output in place within parsed and returns the
// re-marshalled body, the redaction kinds applied, and an error only if the
// result cannot be marshalled.
//
// It is a TOTAL SWEEP, not a shape-aware walker, and that difference is the
// entire point. Four successive review rounds each found PII leaving the gateway
// through a shape the previous fix had not enumerated: content as a parts array,
// a messages container that was an object, delta.content, legacy choices[].text,
// and message.text. Each fix added the newly-named shapes to a hand-maintained
// list, so the list was always one review behind. An enumerated walker can only
// ever be as complete as its author's imagination.
//
// A sweep needs no imagination. encoding/json decodes into exactly six Go types
// (nil, bool, float64, string, []any, map[string]any), so a switch over those six
// is exhaustive by construction: every string anywhere in the document is
// inspected, regardless of container, nesting depth or key name. No shape can hide
// a value, because no shape is consulted.
//
// A consequence worth stating: the caller no longer needs the upstream STATUS
// CODE to make a security decision. The previous version failed closed on 2xx and
// passed error bodies through, so the gateway trusted an upstream-controlled
// status code for a security decision and a compromised upstream could try to get
// model output served under a non-2xx label. That attack surface is gone, because
// no branch serves uninspected bytes any more.
//
// Keys in opaqueKeys may be skipped, but only when the VALUE verifies as base64
// (see isOpaqueBinary), and every skip is counted and returned so the caller can
// record that content was left uninspected. An exemption is not a hole only if it
// is validated and logged.
func redactResponse(parsed map[string]any, r redactor.Redactor) ([]byte, []string, int, error) {
	c := &sweepCtx{r: r, prefix: "resp"}
	sweepValue(parsed, c)
	body, err := marshalMap(parsed)
	if err != nil {
		return nil, c.kinds, c.opaqueSkipped, err
	}
	return body, c.kinds, c.opaqueSkipped, nil
}

// opaqueKeys name fields whose payload is binary rather than natural language,
// where running a PII regex is both wasteful and liable to mangle data the client
// cannot decode. Membership is a HINT, not a grant: see isOpaqueBinary.
var opaqueKeys = map[string]bool{
	"b64_json": true,
}

// isOpaqueBinary decides whether a value under an opaqueKeys name may skip the
// sweep, and it decides by CONTENT rather than by key name.
//
// BL-9: the exemption used to fire on the key alone, at any depth, for any value
// type. That made {"b64_json":"jane.doe@example.com"} - and the same PII under
// b64_json as an object, an array, or a deep subtree - be served verbatim, with
// nothing recorded in the audit event. It was a one-entry hand-maintained list of
// uninspectable positions, i.e. enumeration reintroduced inside the fix for
// enumeration, which is the exact defect this branch exists to remove.
//
// So the skip requires the value to be a string that actually IS base64: it must
// decode and re-encode to itself. A non-string under b64_json cannot be a binary
// payload at all, and a string that does not round-trip is not opaque data -
// either way it gets swept like everything else. All four standard encodings are
// tried so a genuine image or audio payload using URL-safe or unpadded base64 is
// not corrupted by over-redaction.
func isOpaqueBinary(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" {
		return false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		raw, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if enc.EncodeToString(raw) == s {
			return true // round-trips: genuinely opaque binary
		}
	}
	return false
}

// sweepCtx carries what a total sweep accumulates, so the SAME traversal serves
// both directions and neither can drift from the other.
//
// prefix records which way the bytes were flowing: "resp" for upstream->client
// and "req" for client->upstream. The audit trail has to be able to tell them
// apart, because a redaction that never reached the client is not evidence the
// client was protected, and vice versa.
type sweepCtx struct {
	r             redactor.Redactor
	kinds         []string
	opaqueSkipped int
	prefix        string
}

func (c *sweepCtx) found(kind string) {
	c.kinds = append(c.kinds, c.prefix+":"+kind)
}

// sweepValue redacts every string in a JSON-decoded value, in place, and returns
// the (possibly replaced) value. Strings are immutable in Go, so containers
// reassign their children.
//
// BL-10: object KEYS are swept, not just values. A key is a string in the decoded
// document and json.Marshal re-emits it verbatim, so a compromised upstream could
// ship PII as a key ({"jane.doe@example.com":"v"}) and the client would receive it
// raw. "Every string anywhere in the document" is false for keys unless keys are
// swept.
//
// Renaming happens in a second pass: adding or deleting map entries while ranging
// over that same map is not safe in Go, so renames are collected and applied after
// the range completes. Two distinct keys can redact to the SAME string, which
// would silently drop one entry, so collisions get a numeric suffix and both are
// preserved.
//
// The default branch is a deliberate no-op rather than an error: encoding/json
// cannot produce a seventh type when decoding into any, so reaching it would mean
// a future change to how the body is decoded. json.Number is handled explicitly
// for that reason - it is a string type and a numeric literal cannot carry PII,
// but letting it fall through to default would leave the assumption unstated.
func sweepValue(v any, c *sweepCtx) any {
	switch tv := v.(type) {
	case nil, bool, float64:
		return v
	case json.Number:
		// A numeric literal. Not natural language, cannot carry PII.
		return v
	case string:
		cleaned, found := c.r.Redact(tv)
		for _, k := range found {
			c.found(k)
		}
		return cleaned
	case []any:
		for idx, el := range tv {
			tv[idx] = sweepValue(el, c)
		}
		return tv
	case map[string]any:
		// Pass 1: sweep values, collect key renames without mutating the map.
		type rename struct{ from, to string }
		var renames []rename
		for k, val := range tv {
			if opaqueKeys[k] && isOpaqueBinary(val) {
				// Genuinely opaque binary, verified by CONTENT. Record the skip so
				// the trail shows something was left uninspected and where - an
				// exemption that leaves no diagnostic is indistinguishable from a
				// silent hole (the BL-8/N1 class).
				c.opaqueSkipped++
				c.found("opaque_skipped")
				continue
			}
			tv[k] = sweepValue(val, c)
			if ck, found := c.r.Redact(k); len(found) > 0 && ck != k {
				// Record the kinds for the KEY redaction too. Discarding them here
				// would make the audit trail claim nothing was redacted while PII
				// was in fact removed from a key - the reviewer's N1 finding
				// ("string case discards found kinds") reborn one level up. It is
				// worse than a telemetry bug: redactRequestContent returns
				// (nil,nil,nil) when kinds is empty, so a request whose ONLY PII
				// sat in a key would not be rewritten at all and would be forwarded
				// to the upstream provider verbatim.
				for _, f := range found {
					c.found(f)
				}
				renames = append(renames, rename{k, ck})
			}
		}
		// Pass 2: apply renames now that ranging is finished.
		for _, rn := range renames {
			val, exists := tv[rn.from]
			if !exists {
				continue
			}
			to := rn.to
			// Preserve both entries if two keys redacted to the same string;
			// silently overwriting would drop data the client asked for.
			for n := 2; ; n++ {
				if _, clash := tv[to]; !clash {
					break
				}
				to = rn.to + "_" + strconv.Itoa(n)
			}
			delete(tv, rn.from)
			tv[to] = val
		}
		return tv
	default:
		return v
	}
}

// collectStrings gathers every string in a JSON-decoded value, keys included, in
// document order. It exists for the policy engine (BL-11): a ContentRe deny rule
// that only saw messages[].content could be bypassed by putting the forbidden text
// in ANY other field - prompt, metadata.user_email, tools[].function.description,
// the top-level user field, an image_url data URI, or an object key. Feeding
// policy the concatenation of every string means the rule cannot be dodged by
// field choice, which is the request-side analogue of the response sweep.
//
// Keys are included because a key is attacker-chosen text that reaches upstream.
func collectStrings(v any, out *[]string) {
	switch tv := v.(type) {
	case string:
		*out = append(*out, tv)
	case []any:
		for _, el := range tv {
			collectStrings(el, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(tv))
		for k := range tv {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic: map iteration order is randomised
		for _, k := range keys {
			*out = append(*out, k)
			collectStrings(tv[k], out)
		}
	}
}

// allRequestStrings returns every string in a request body, joined for policy
// evaluation. Deterministic ordering matters: policy decisions must be
// reproducible, and Go randomises map iteration.
func allRequestStrings(parsed map[string]any) string {
	var parts []string
	collectStrings(parsed, &parts)
	return strings.Join(parts, "\n")
}

// isNonStandardHeader reports whether a canonical header name is NOT part of the
// HTTP protocol vocabulary or a well-known provider interop header. BL-12 redacts
// the values of everything this returns true for.
//
// The list is a POSITIVE list of names to SPARE. A negative list of names to
// redact would be the enumeration mistake this branch exists to remove: any header
// nobody thought of would fall through unswept. Sparing protocol vocabulary is
// safe because those values are generated by the HTTP stack, not by a model.
func isNonStandardHeader(canonical string) bool {
	switch canonical {
	case "Content-Type", "Content-Length", "Content-Encoding", "Content-Language",
		"Content-Range", "Content-Disposition", "Content-Location",
		"Date", "Server", "Cache-Control", "Pragma", "Expires", "Age",
		"Vary", "Via", "Warning", "Allow", "Location",
		"Accept-Ranges", "Retry-After", "Trailer", "Transfer-Encoding",
		"Last-Modified", "Etag", "If-None-Match", "If-Modified-Since",
		"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
		"Access-Control-Allow-Headers", "Access-Control-Allow-Methods",
		"Access-Control-Expose-Headers", "Access-Control-Max-Age",
		"Strict-Transport-Security", "X-Content-Type-Options",
		"X-Frame-Options", "X-Xss-Protection", "Referrer-Policy",
		"X-Request-Id", "X-Correlation-Id", "Request-Id",
		"X-Amzn-Requestid", "X-Amzn-Trace-Id",
		"Openai-Organization", "Openai-Processing-Ms", "Openai-Version",
		"X-Ratelimit-Limit-Requests", "X-Ratelimit-Limit-Tokens",
		"X-Ratelimit-Remaining-Requests", "X-Ratelimit-Remaining-Tokens",
		"X-Ratelimit-Reset-Requests", "X-Ratelimit-Reset-Tokens",
		"Anthropic-Ratelimit-Requests-Limit",
		"Anthropic-Ratelimit-Requests-Remaining",
		"Anthropic-Ratelimit-Requests-Reset",
		"Cf-Ray", "Cf-Cache-Status":
		return false
	}
	return true
}

// isSuccessfulStatus reports whether a status code denotes success.
//
// It is used for exactly ONE decision, and it is important to be precise about
// which: whether a non-JSON 2xx body may be served at all. It is NOT used to
// decide whether to redact - redaction now happens at every status, so no
// security property depends on a value the upstream controls. That distinction is
// the whole difference between this and the round-3 bug, where the status code
// chose whether bytes were inspected at all.
func isSuccessfulStatus(code int) bool {
	return code >= 200 && code < 300
}

// marshalMap re-marshals a decoded response. Failure is returned rather than
// papered over with the original bytes.
func marshalMap(parsed map[string]any) ([]byte, error) {
	out, err := json.Marshal(parsed)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func setMeta(ev *audit.Event, key string, value any) {
	if ev.Meta == nil {
		ev.Meta = map[string]any{}
	}
	ev.Meta[key] = value
}

// totalTokens extracts usage.total_tokens, tolerating the integer types encoding/
// json produces (float64 for a generic decode).
func totalTokens(parsed map[string]any) (int64, bool) {
	usage, ok := parsed["usage"].(map[string]any)
	if !ok {
		return 0, false
	}
	switch v := usage["total_tokens"].(type) {
	case float64:
		// Clamp rather than rely on int64(float64) conversion, whose result Go
		// leaves implementation-defined for out-of-range values. On amd64/arm64
		// it saturates to MaxInt64, which happens to be safe (budget exceeded),
		// but a hostile or buggy upstream should not depend on that.
		if v != v { // NaN
			return 0, false
		}
		if v > math.MaxInt64 {
			return math.MaxInt64, true
		}
		if v < 0 {
			return 0, false
		}
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case string:
		// Some upstreams emit usage figures as JSON strings. Refusing to parse
		// them silently recorded zero tokens and skipped the budget check, which
		// is an accounting bypass rather than a formatting quirk.
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func (g *Gateway) log(e audit.Event) {
	if g.Audit == nil {
		return
	}
	// A failed append breaks the hash chain, so it must not be silent. Failing the
	// request would be worse - an audit backend hiccup would take down inference -
	// but the operator has to see it.
	if err := g.Audit.Log(e); err != nil {
		log.Printf("open-ai-gateway: audit append FAILED (chain may be incomplete): %v", err)
	}
}

// errNotJSONObject is returned for a body that is valid JSON but not an object
// (e.g. "null"), which would otherwise decode to a nil map and look parseable.
var errNotJSONObject = errors.New("body is not a JSON object")

// decodeJSONObject parses a request body as a JSON object. Anything else
// (array, scalar, malformed JSON) is an error: the gateway must not forward a
// body it cannot inspect.
func decodeJSONObject(body []byte) (map[string]any, error) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, errNotJSONObject
	}
	return parsed, nil
}

// stringField reads a string member, returning "" when absent or non-string.
func stringField(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// wantsStreaming reports whether the client asked for a streaming response.
//
// It accepts the non-boolean truthy forms clients actually emit - "stream":
// "true" as a string, "stream": 1 as a number - not just a JSON boolean. A
// bool-only check was bypassable by those two forms: the request went upstream as
// a streaming call, the gateway could not redact the SSE it got back, and the
// refusal that existed to prevent exactly that never fired. (The response-side
// non-JSON 2xx guard still caught it, so nothing leaked, but the client received
// a misleading error and the request had already transited upstream.)
func wantsStreaming(m map[string]any) bool {
	switch v := m["stream"].(type) {
	case bool:
		return v
	case string:
		// Match the truthy spellings used by OpenAI-compatible SDKs and shell
		// templates that interpolate the value as a string.
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true
		}
		return false
	case float64:
		return v != 0
	case json.Number:
		n, err := v.Int64()
		return err == nil && n != 0
	default:
		return false
	}
}

// messagesShapeInspectable reports whether the request's "messages" member is in a
// shape this gateway can inspect.
//
// This exists because "key absent" and "key present but unreadable" must NOT be
// treated the same way:
//
//   - absent (or explicitly null) -> true. An embeddings-style or completions
//     body legitimately carries no messages, and there is nothing to inspect.
//   - present as an array          -> true. Each element is then classified by
//     extractContent, which fails closed on anything it cannot read.
//   - present as ANY other shape   -> false. An object, a string, a number or a
//     bool here means model input the gateway cannot read, so it must be refused
//     rather than forwarded.
//
// The third case was a live bypass: {"messages":{"role":"user","content":"my
// email is jane.doe@example.com"}} forwarded VERBATIM upstream with status 200.
// extractContent failed its []any type assertion on the container and reported
// "no content" instead of "content I could not read", and the handler's guard was
// additionally gated on hasMessages, which failed the same assertion - so the
// guard could never fire for precisely the shape that needed it. Policy matched
// nothing and redaction rewrote nothing, while the request still went out. That is
// the same bypass-by-shape class the content-shape work closed, one level up.
//
// hasMessages is gone for that reason: a second, differently-failing shape check
// on the same field is how the guard became unreachable. extractContent returning
// ok=false is now the single source of truth for "input I could not inspect".
func messagesShapeInspectable(m map[string]any) bool {
	v, present := m["messages"]
	if !present {
		return true
	}
	switch v.(type) {
	case nil:
		// "messages": null carries no input.
		return true
	case []any:
		// Per-element shapes are classified by extractContent.
		return true
	default:
		return false
	}
}

// extractContent flattens every message's TEXT into one string for policy
// matching and redaction, and reports whether every shape it saw was understood.
//
// It handles the three content shapes OpenAI-compatible clients actually send:
//   - "content": "text"                              (plain string)
//   - "content": [{"type":"text","text":"..."}, ...] (multimodal parts)
//   - "content": null                                (tool-call turns)
//
// Returning ok=false for an unrecognised shape is load-bearing: the caller fails
// closed rather than forwarding content that policy and redaction never saw.
// The previous implementation typed content as a plain string and discarded the
// unmarshal error, so multimodal requests produced EMPTY content and silently
// bypassed both.
func extractContent(m map[string]any) (string, bool) {
	// A "messages" member that is present but not an array is content the gateway
	// cannot read, not absent content - see messagesShapeInspectable. Report it as
	// unclassified so the caller fails closed.
	if !messagesShapeInspectable(m) {
		return "", false
	}
	msgs, ok := m["messages"].([]any)
	if !ok {
		// No messages array (absent or null): nothing textual to inspect. Not an
		// error - this can be an embeddings-style body.
		return "", true
	}
	parts := make([]string, 0, len(msgs))
	for _, raw := range msgs {
		msg, ok := raw.(map[string]any)
		if !ok {
			return "", false
		}
		switch c := msg["content"].(type) {
		case nil:
			// Tool-call / assistant turns legitimately carry no content.
			continue
		case string:
			parts = append(parts, c)
		case []any:
			// Multimodal parts: inspect every text part. Image and other
			// non-text parts are skipped, but their presence is not an error.
			for _, pt := range c {
				part, ok := pt.(map[string]any)
				if !ok {
					return "", false
				}
				if v, present := part["text"]; present {
					s, ok := v.(string)
					if !ok {
						return "", false
					}
					parts = append(parts, s)
				}
			}
		default:
			// Number, bool, object: content we cannot read as text.
			return "", false
		}
	}
	return strings.Join(parts, "\n"), true
}

// redactRequestContent redacts sensitive text throughout the request's messages
// IN PLACE, preserving every other field and the original content shape.
//
// It rewrites string content, and each {type:text,text:...} part of a multimodal
// content array (image and other non-text parts are left untouched).
//
// It returns:
//   - (body, kinds, nil) when something was redacted and the body re-marshalled
//   - (nil, nil, nil)    when nothing sensitive was found (no rewrite needed)
//   - (nil, kinds, err)  when sensitive content WAS found but the body could not
//     be re-marshalled
//
// That third case is why this returns an error rather than a bool: collapsing it
// into ok=false made the caller keep the ORIGINAL bytes, forwarding raw PII
// upstream while the audit trail still recorded a redaction. The caller fails
// closed on it. Unrecognised content shapes never reach here - extractContent has
// already failed closed on them.
// redactRequestContent redacts a client request body before it is forwarded
// upstream, in place, preserving every field the client sent.
//
// BL-11: this used to be an ENUMERATED walker - messages[].content strings and
// parts[].text only - which is precisely the design four review rounds proved
// insufficient on the response side. The response half was converted to a total
// sweep and this half was not, so PII in metadata.user_email, prompt,
// tools[].function.description, the top-level user field, or an image_url data URI
// was forwarded to the provider verbatim. That leaks in the direction
// RedactRequest exists to close (client -> upstream), and it also let a ContentRe
// deny rule be bypassed by field choice.
//
// It now runs the same sweepValue traversal as the response path, so the two
// directions cannot drift apart, and object keys are swept too. Non-string fields
// are untouched, which is what keeps the request semantically intact: model,
// stream, temperature, max_tokens, top_p, stop, n, tools, tool_choice and
// response_format all survive, because the redactor only rewrites strings that
// match a PII pattern.
//
// The (nil, nil, nil) return means "nothing sensitive found" and is deliberately
// distinct from an error: collapsing the two is how the original bug forwarded raw
// PII under an audit line claiming it had been redacted.
func redactRequestContent(parsed map[string]any, r redactor.Redactor) ([]byte, []string, error) {
	c := &sweepCtx{r: r, prefix: "req"}
	sweepValue(parsed, c)
	if len(c.kinds) == 0 {
		return nil, nil, nil
	}
	out, err := marshalMap(parsed)
	if err != nil {
		return nil, c.kinds, err
	}
	return out, c.kinds, nil
}

func extractKey(r *http.Request) string {
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	auth := r.Header.Get("Authorization")
	return strings.TrimPrefix(auth, "Bearer ")
}

func maskKey(k string) string {
	if len(k) <= 4 {
		return "****"
	}
	return k[:4] + "…"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
