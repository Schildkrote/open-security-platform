// Package proxy is the gateway core: it inspects, filters, rate-limits,
// forwards and audits LLM/agent traffic.
package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Schildkrote/open-ai-gateway/internal/audit"
	"github.com/Schildkrote/open-ai-gateway/internal/policy"
	"github.com/Schildkrote/open-ai-gateway/internal/ratelimit"
	"github.com/Schildkrote/open-ai-gateway/internal/redact"
)

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
}

type chatResponse struct {
	Choices []struct {
		Message message `json:"message"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int64 `json:"total_tokens"`
	} `json:"usage"`
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
	if g.RedactRequest || dec.Action == policy.Redact {
		redacted, findings := redact.Redact(content)
		if len(findings) > 0 {
			applyRedaction(&req, redacted)
			body, _ = json.Marshal(req)
			for _, f := range findings {
				ev.Redactions = append(ev.Redactions, f.Kind)
			}
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
	var cr chatResponse
	if json.Unmarshal(respBody, &cr) == nil {
		if g.RedactResponse {
			for i := range cr.Choices {
				cleaned, findings := redact.Redact(cr.Choices[i].Message.Content)
				cr.Choices[i].Message.Content = cleaned
				for _, f := range findings {
					ev.Redactions = append(ev.Redactions, "resp:"+f.Kind)
				}
			}
			respBody, _ = json.Marshal(cr)
		}
		ev.Tokens = cr.Usage.TotalTokens
		if !g.Limiter.RecordUsage(apiKey, cr.Usage.TotalTokens) {
			ev.Meta = map[string]any{"budget": "exceeded"}
		}
	}

	g.log(ev)

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
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

// applyRedaction writes the redacted flattened content back into the last
// user message (simple, deterministic mapping for the MVP).
func applyRedaction(req *chatRequest, redacted string) {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			req.Messages[i].Content = redacted
			return
		}
	}
	if len(req.Messages) > 0 {
		req.Messages[len(req.Messages)-1].Content = redacted
	}
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
