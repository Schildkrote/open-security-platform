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
		if rewritten, kinds, ok := redactRequestContent(parsedReq, g.redactor()); ok {
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
	if json.Unmarshal(respBody, &parsed) == nil {
		if g.RedactResponse {
			respBody = redactChoices(parsed, g.redactor(), &ev, respBody)
		}
		if tokens, ok := totalTokens(parsed); ok {
			ev.Tokens = tokens
			if !g.Limiter.RecordUsage(apiKey, tokens) {
				ev.Meta = map[string]any{"budget": "exceeded"}
			}
		}
	}

	g.log(ev)

	for k, vs := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
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
// It returns ok=false only when nothing sensitive was found or the body cannot
// be re-marshalled, in which case the caller keeps the ORIGINAL bytes. That is
// safe because extractContent has already run and failed closed on any shape
// this function does not understand, so an unrecognised shape cannot reach here
// and be forwarded unredacted.
func redactRequestContent(parsed map[string]any, r redactor.Redactor) ([]byte, []string, bool) {
	msgs, ok := parsed["messages"].([]any)
	if !ok {
		return nil, nil, false
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
		return nil, nil, false
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		return nil, nil, false
	}
	return out, kinds, true
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
