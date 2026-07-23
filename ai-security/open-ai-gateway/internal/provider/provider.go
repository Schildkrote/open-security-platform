// Package provider defines the LLM-provider connector interface for
// open-ai-gateway (Phase 3). Each provider knows its upstream endpoint and how
// to authorize a request. The Mock provider is the offline default; the Real
// providers (OpenAI, Anthropic, Ollama) call the public APIs with user-supplied
// credentials. Selecting a provider never breaks the offline model: with none
// configured the gateway uses its mock upstream.
package provider

import (
	"net/http"
	"os"
	"strings"
)

// Provider is an LLM backend the gateway can proxy to.
type Provider interface {
	Name() string
	Endpoint() string
	Authorize(req *http.Request)
}

func baseOrDefault(base, def string) string {
	if strings.TrimSpace(base) == "" {
		return def
	}
	return strings.TrimRight(base, "/")
}

// Mock is the offline default. The endpoint is the gateway's mock upstream; no
// authorization is applied.
type Mock struct{ URL string }

func (m Mock) Name() string            { return "mock" }
func (m Mock) Endpoint() string        { return m.URL }
func (m Mock) Authorize(*http.Request) {}

// OpenAI calls the OpenAI chat-completions API.
type OpenAI struct {
	APIKey  string
	BaseURL string
}

func (p OpenAI) Name() string { return "openai" }
func (p OpenAI) Endpoint() string {
	return baseOrDefault(p.BaseURL, "https://api.openai.com/v1") + "/chat/completions"
}
func (p OpenAI) Authorize(req *http.Request) {
	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
}

// Anthropic calls the Anthropic messages API.
type Anthropic struct {
	APIKey  string
	BaseURL string
	Version string
}

func (p Anthropic) Name() string { return "anthropic" }
func (p Anthropic) Endpoint() string {
	return baseOrDefault(p.BaseURL, "https://api.anthropic.com/v1") + "/messages"
}
func (p Anthropic) Authorize(req *http.Request) {
	if p.APIKey != "" {
		req.Header.Set("x-api-key", p.APIKey)
	}
	version := p.Version
	if version == "" {
		version = "2023-06-01"
	}
	req.Header.Set("anthropic-version", version)
}

// Ollama calls a local Ollama instance (OpenAI-compatible endpoint). No auth.
type Ollama struct{ BaseURL string }

func (p Ollama) Name() string { return "ollama" }
func (p Ollama) Endpoint() string {
	return baseOrDefault(p.BaseURL, "http://localhost:11434") + "/v1/chat/completions"
}
func (p Ollama) Authorize(*http.Request) {}

// FromEnv builds a provider by name, reading credentials from the environment:
// OPENAI_API_KEY / OPENAI_BASE_URL, ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL,
// OLLAMA_BASE_URL. Unknown names fall back to the Mock provider (mockURL).
func FromEnv(name, mockURL string) Provider {
	switch strings.ToLower(name) {
	case "openai":
		return OpenAI{APIKey: os.Getenv("OPENAI_API_KEY"), BaseURL: os.Getenv("OPENAI_BASE_URL")}
	case "anthropic":
		return Anthropic{APIKey: os.Getenv("ANTHROPIC_API_KEY"), BaseURL: os.Getenv("ANTHROPIC_BASE_URL")}
	case "ollama":
		return Ollama{BaseURL: os.Getenv("OLLAMA_BASE_URL")}
	default:
		return Mock{URL: mockURL}
	}
}
