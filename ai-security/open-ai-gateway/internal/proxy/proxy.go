// Package proxy is the gateway core: it inspects, filters, rate-limits,
// forwards and audits LLM/agent traffic.
package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
	apiKey := extractKey(r)

	// Set whenever the bytes forwarded or served no longer match upstream's, so
	// length-dependent and validator headers cannot be copied verbatim.
	bodyRewritten := false

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
	if !contentOK && hasMessages(parsedReq) {
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
	if g.RedactResponse && boolField(parsedReq, "stream") {
		ev.Action = "denied"
		ev.Rule = "streaming-unsupported"
		ev.Reason = "streaming responses cannot be redacted or accounted for; refused"
		g.log(ev)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "streaming is not supported while response redaction is enabled",
			"detail": "re-send the request without stream:true, or disable REDACT_RESPONSE",
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
			bodyRewritten = true
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
	respBody, _ := io.ReadAll(resp.Body)

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
		if g.RedactResponse && resp.StatusCode >= 200 && resp.StatusCode < 300 {
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
			// redactChoices re-marshals the parsed map, so the served bytes no
			// longer match what upstream sent even when nothing was redacted.
			// Validator headers describing the upstream body must not be copied.
			before := respBody
			respBody = redactChoices(parsed, g.redactor(), &ev, respBody)
			if !bytes.Equal(before, respBody) {
				bodyRewritten = true
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
	if bodyRewritten {
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

// redactChoices redacts each choices[].message.content in place and returns the
// re-marshalled response, preserving all other fields. If re-marshalling somehow
// fails it returns originalBody so the caller still serves a complete, truthful
// response rather than an empty one.
func redactChoices(parsed map[string]any, r redactor.Redactor, ev *audit.Event, originalBody []byte) []byte {
	choices, ok := parsed["choices"].([]any)
	if !ok {
		return marshalOr(parsed, originalBody)
	}
	for _, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		msg, ok := choice["message"].(map[string]any)
		if !ok {
			continue
		}
		content, ok := msg["content"].(string)
		if !ok {
			continue
		}
		cleaned, kinds := r.Redact(content)
		msg["content"] = cleaned
		for _, k := range kinds {
			ev.Redactions = append(ev.Redactions, "resp:"+k)
		}
	}
	return marshalOr(parsed, originalBody)
}

// setMeta records a diagnostic on the audit event, preserving any value already
// set (the budget-exceeded path and the unparseable-response path can both fire).
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

// marshalOr re-marshals a value that was successfully unmarshalled from JSON, so
// failure is not reachable in practice; if it somehow happens, fall back to the
// caller's original bytes rather than serving an empty body.
func marshalOr(v map[string]any, fallback []byte) []byte {
	out, err := json.Marshal(v)
	if err != nil {
		return fallback
	}
	return out
}

func (g *Gateway) log(e audit.Event) {
	if g.Audit != nil {
		_ = g.Audit.Log(e)
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

// boolField reads a boolean member, returning false when absent or non-boolean.
func boolField(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// hasMessages reports whether the request carried a non-empty messages array.
func hasMessages(m map[string]any) bool {
	msgs, ok := m["messages"].([]any)
	return ok && len(msgs) > 0
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
	msgs, ok := m["messages"].([]any)
	if !ok {
		// No messages array: nothing textual to inspect. Not an error (this can
		// be an embeddings-style body), just no content.
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
