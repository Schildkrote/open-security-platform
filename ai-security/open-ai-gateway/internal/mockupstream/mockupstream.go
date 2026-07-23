// Package mockupstream is an offline stand-in for a real LLM provider so the
// gateway can be exercised end-to-end without network access.
package mockupstream

import (
	"encoding/json"
	"net/http"
	"strings"
)

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

// Handler returns an http.Handler that mimics /v1/chat/completions. It echoes
// the last user message back (so response-side redaction is observable) and
// reports a rough token usage.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		last := ""
		for i := len(req.Messages) - 1; i >= 0; i-- {
			if req.Messages[i].Role == "user" {
				last = req.Messages[i].Content
				break
			}
		}
		reply := "echo: " + last
		tokens := int64(strings.Count(reply, " ") + 1)

		resp := map[string]any{
			"id":      "chatcmpl-mock",
			"object":  "chat.completion",
			"model":   req.Model,
			"choices": []map[string]any{{"index": 0, "message": chatMessage{Role: "assistant", Content: reply}, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": tokens, "completion_tokens": tokens, "total_tokens": tokens * 2},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}
