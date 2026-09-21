// Package proxy is the gateway core: it inspects, filters, rate-limits,
// forwards and audits LLM/agent traffic.
package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Schildkrote/open-ai-gateway/internal/audit"
	"github.com/Schildkrote/open-ai-gateway/internal/policy"
	"github.com/Schildkrote/open-ai-gateway/internal/ratelimit"
	"github.com/Schildkrote/open-ai-gateway/internal/redactor"
)

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
}

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

	var req chatRequest
	_ = json.Unmarshal(body, &req)
	content := flatten(req.Messages)
	apiKey := extractKey(r)

	ev := audit.Event{APIKey: maskKey(apiKey), Model: req.Model}

	// 1. Policy decision.
	dec := g.Engine.Evaluate(policy.Request{Model: req.Model, Content: content, APIKey: apiKey})
	ev.Action = string(dec.Action)
	ev.Rule = dec.Rule
	ev.Reason = dec.Reason

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
	// This rewrites the ORIGINAL body as a generic map, not via the narrow
	// chatRequest struct. RedactRequest defaults to true, so whenever anything
	// was redacted the old code did `body, _ = json.Marshal(req)` — and req only
	// models Model + Messages, which silently dropped every other field the
	// client sent: stream, temperature, top_p, max_tokens, tools/tool_choice,
	// response_format, stop, n. A streaming client would get a non-streaming
	// upstream call back and tool-calling clients would lose their tool schema.
	// A map round-trip preserves unknown fields and cannot drift when upstream
	// adds one.
	if g.RedactRequest || dec.Action == policy.Redact {
		redacted, kinds := g.redactor().Redact(content)
		if len(kinds) > 0 {
			if rewritten, ok := redactRequestBody(body, redacted); ok {
				body = rewritten
			}
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

func flatten(msgs []message) string {
	parts := make([]string, 0, len(msgs))
	for _, m := range msgs {
		parts = append(parts, m.Content)
	}
	return strings.Join(parts, "\n")
}

// redactRequestBody rewrites the original request body as a generic map so that
// every field the client sent survives so every field the client sent
// survives (stream, temperature, max_tokens, tools, ...). It reports ok=false
// when the body is not a JSON object or has no rewritable messages, in which
// case the caller keeps the original bytes rather than sending a mangled body.
func redactRequestBody(body []byte, redacted string) ([]byte, bool) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, false
	}
	msgs, ok := parsed["messages"].([]any)
	if !ok || len(msgs) == 0 {
		return nil, false
	}

	// Selection rule: the last message with role "user", else the final
	// message. This is deliberately unchanged from the pre-map implementation.
	target := -1
	for i := len(msgs) - 1; i >= 0; i-- {
		m, ok := msgs[i].(map[string]any)
		if !ok {
			continue
		}
		if role, _ := m["role"].(string); role == "user" {
			target = i
			break
		}
	}
	if target < 0 {
		target = len(msgs) - 1
	}
	tm, ok := msgs[target].(map[string]any)
	if !ok {
		return nil, false
	}
	tm["content"] = redacted

	out, err := json.Marshal(parsed)
	if err != nil {
		return nil, false
	}
	return out, true
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
