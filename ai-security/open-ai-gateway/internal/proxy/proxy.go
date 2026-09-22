// Package proxy is the gateway core: it inspects, filters, rate-limits,
// forwards and audits LLM/agent traffic.
package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"

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
	// A misbehaving Redactor (e.g. a backend that panics on malformed input) must
	// not escape the handler. net/http recovers per connection so the process
	// survives - but the panic left ZERO audit events for a request that WAS
	// processed, and for a gateway whose selling point is a tamper-evident trail
	// that gap is itself the defect. Recovering keeps the chain complete.
	defer func() {
		if rec := recover(); rec != nil {
			g.log(audit.Event{Action: "error", Rule: "handler-panic",
				Reason: fmt.Sprintf("recovered from panic: %v", rec)})
			http.Error(w, "internal gateway error", http.StatusInternalServerError)
		}
	}()

	// Resolved before anything is audited so every event, including the
	// body-size refusal below, can be attributed to a caller.
	apiKey := extractKey(r)

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
	content, contentOK := extractContent(parsedReq)

	ev := audit.Event{APIKey: maskKey(apiKey), Model: model}

	// 1. Policy decision.
	dec := g.Engine.Evaluate(policy.Request{Model: model, Content: content, APIKey: apiKey})
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
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	if g.Authorize != nil {
		g.Authorize(upReq)
	}
	resp, err := g.client().Do(upReq)
	if err != nil {
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
		// A response that is not JSON cannot be redacted or accounted for.
		//
		// Error bodies are deliberately passed through: an upstream 502 page is
		// diagnostic information the caller needs, it is not model output, and
		// swallowing it would make upstream failures undebuggable.
		//
		// A SUCCESSFUL non-JSON body is different. That is model output the
		// gateway cannot inspect, so with RedactResponse on it must not reach the
		// client - it is the same unredactable-to-client path as the streaming
		// case, just reached by content-type instead of by stream:true.
		setMeta(&ev, "response", "unparseable")
		if g.RedactResponse && isSuccessfulStatus(resp.StatusCode) {
			ev.Action = "redaction_failed"
			setMeta(&ev, "redaction", "unparseable_success_response")
			g.log(ev)
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error": "upstream returned a successful response that could not be redacted",
			})
			return
		}
		setMeta(&ev, "redaction", "skipped_unparseable_response")
	} else {
		if g.RedactResponse {
			// redactResponse re-marshals the parsed map, so the served bytes no
			// longer match what upstream sent even when nothing was redacted.
			// Validator headers describing the upstream body must not be copied.
			before := respBody
			redacted, err := redactResponse(parsed, g.redactor(), &ev)
			if err != nil && isSuccessfulStatus(resp.StatusCode) {
				// A SUCCESSFUL response carrying model output the gateway cannot
				// read must not be served unredacted. Same fail-closed contract as
				// the non-JSON 2xx case above.
				ev.Action = "redaction_failed"
				setMeta(&ev, "redaction", "unparseable_response_shape")
				g.log(ev)
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error": "upstream returned a successful response that could not be redacted",
				})
				return
			}
			if err != nil {
				// An ERROR response in an odd shape is passed through. It is
				// diagnostic rather than model output, and replacing an upstream
				// 429 with a generic 502 would destroy the very information the
				// caller needs to debug the failure. The skip is still audited so
				// the trail shows the body left uninspected.
				setMeta(&ev, "redaction", "skipped_uninspectable_error_shape")
			} else {
				respBody = redacted
			}
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

	g.log(ev)

	// Headers listed in the upstream's Connection header are hop-by-hop for this
	// connection specifically (RFC 9110 7.6.1) and must not be forwarded, even
	// though their names are not in the static isHopByHop set.
	connListed := connectionListedHeaders(resp.Header)

	for k, vs := range resp.Header {
		if isHopByHop(k) || connListed[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
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

// redactResponse redacts model output in place and returns the re-marshalled
// response, preserving every other upstream field.
//
// It covers the output shapes OpenAI-compatible upstreams actually emit:
//   - choices[].message.content as a string           (standard completion)
//   - choices[].message.content as an array of parts   (multimodal / vLLM)
//   - choices[].delta.content                          (chunked output, and some
//     bridges emit delta inside non-stream JSON)
//   - choices[].text                                   (legacy completions API)
//
// It returns an error for any shape it cannot inspect - a non-array choices, a
// non-object choice/message/delta, or content that is neither a string, a parts
// array, null nor absent. The caller fails closed on that error.
//
// This mirrors the request-side contract (extractContent). Without it the
// response path silently skipped redaction for anything outside the narrow
// choices[].message.content-as-string whitelist: a parts array, a delta, or a
// choices object were served to the client verbatim with status 200, PII intact,
// under an audit event reading action "allow" with no redactions and no
// diagnostic. That is the same unredactable-to-client class as the streaming and
// non-JSON cases, reached by response shape instead of by content-type.
//
// A marshal failure is also an error rather than a fallback to the original
// bytes: returning originalBody after a finding would forward unredacted output
// while the audit trail had already recorded a redaction.
func redactResponse(parsed map[string]any, r redactor.Redactor, ev *audit.Event) ([]byte, error) {
	raw, present := parsed["choices"]
	if !present {
		// No choices: nothing model-generated to inspect (e.g. an embeddings
		// response). Not an error.
		return marshalMap(parsed)
	}
	choices, ok := raw.([]any)
	if !ok {
		return nil, errUninspectableResponseShape
	}
	for _, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			return nil, errUninspectableResponseShape
		}
		// Each of these containers may hold model output; every one must be
		// either absent or an object we can walk.
		for _, key := range []string{"message", "delta"} {
			if v, p := choice[key]; p {
				container, ok := v.(map[string]any)
				if !ok && v != nil {
					return nil, errUninspectableResponseShape
				}
				if ok {
					if err := redactContentField(container, r, ev); err != nil {
						return nil, err
					}
				}
			}
		}
		// Legacy completions shape: choices[].text is the output directly.
		if v, p := choice["text"]; p {
			if s, ok := v.(string); ok {
				cleaned, kinds := r.Redact(s)
				choice["text"] = cleaned
				for _, k := range kinds {
					ev.Redactions = append(ev.Redactions, "resp:"+k)
				}
			} else if v != nil {
				return nil, errUninspectableResponseShape
			}
		}
	}
	return marshalMap(parsed)
}

// redactContentField redacts a message-or-delta container's "content" member in
// place. Absent or null content is legitimate (tool-call turns, role-only
// deltas); a string and a parts array are redacted; anything else is an
// uninspectable shape.
func redactContentField(container map[string]any, r redactor.Redactor, ev *audit.Event) error {
	v, present := container["content"]
	if !present || v == nil {
		return nil
	}
	switch c := v.(type) {
	case string:
		cleaned, kinds := r.Redact(c)
		container["content"] = cleaned
		for _, k := range kinds {
			ev.Redactions = append(ev.Redactions, "resp:"+k)
		}
		return nil
	case []any:
		for _, pt := range c {
			part, ok := pt.(map[string]any)
			if !ok {
				return errUninspectableResponseShape
			}
			s, present := part["text"]
			if !present || s == nil {
				// Image/audio parts carry no text to redact.
				continue
			}
			text, ok := s.(string)
			if !ok {
				return errUninspectableResponseShape
			}
			cleaned, kinds := r.Redact(text)
			part["text"] = cleaned
			for _, k := range kinds {
				ev.Redactions = append(ev.Redactions, "resp:"+k)
			}
		}
		return nil
	default:
		return errUninspectableResponseShape
	}
}

// isSuccessfulStatus reports whether an upstream status code indicates a
// successful response. The distinction is load-bearing in two places: a
// SUCCESSFUL body the gateway cannot inspect must be refused, while an ERROR body
// must be passed through because it is diagnostic rather than model output.
func isSuccessfulStatus(code int) bool {
	return code >= 200 && code < 300
}

// errUninspectableResponseShape reports a successful response whose model output
// the gateway cannot read, which must not be served to the client.
var errUninspectableResponseShape = errors.New("response contains model output in a shape the gateway cannot redact")

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
func redactRequestContent(parsed map[string]any, r redactor.Redactor) ([]byte, []string, error) {
	msgs, ok := parsed["messages"].([]any)
	if !ok {
		return nil, nil, nil
	}
	var kinds []string
	for _, raw := range msgs {
		msg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		switch c := msg["content"].(type) {
		case string:
			cleaned, found := r.Redact(c)
			if len(found) > 0 {
				msg["content"] = cleaned
				kinds = append(kinds, found...)
			}
		case []any:
			for _, pt := range c {
				part, ok := pt.(map[string]any)
				if !ok {
					continue
				}
				s, ok := part["text"].(string)
				if !ok {
					continue
				}
				cleaned, found := r.Redact(s)
				if len(found) > 0 {
					part["text"] = cleaned
					kinds = append(kinds, found...)
				}
			}
		}
	}
	if len(kinds) == 0 {
		return nil, nil, nil
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		return nil, kinds, err
	}
	return out, kinds, nil
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
