package provider

import (
	"net/http/httptest"
	"testing"
)

func TestEndpoints(t *testing.T) {
	cases := []struct {
		name string
		p    Provider
		want string
	}{
		{"openai default", OpenAI{}, "https://api.openai.com/v1/chat/completions"},
		{"openai custom", OpenAI{BaseURL: "https://gw.example/v1/"}, "https://gw.example/v1/chat/completions"},
		{"anthropic default", Anthropic{}, "https://api.anthropic.com/v1/messages"},
		{"ollama default", Ollama{}, "http://localhost:11434/v1/chat/completions"},
		{"ollama custom", Ollama{BaseURL: "http://10.0.0.5:11434"}, "http://10.0.0.5:11434/v1/chat/completions"},
		{"mock", Mock{URL: "http://127.0.0.1:9999"}, "http://127.0.0.1:9999"},
	}
	for _, c := range cases {
		if got := c.p.Endpoint(); got != c.want {
			t.Errorf("%s: Endpoint() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestOpenAIAuthorize(t *testing.T) {
	req := httptest.NewRequest("POST", "/x", nil)
	OpenAI{APIKey: "sk-test"}.Authorize(req)
	if got := req.Header.Get("Authorization"); got != "Bearer sk-test" {
		t.Errorf("Authorization = %q, want Bearer sk-test", got)
	}
}

func TestAnthropicAuthorize(t *testing.T) {
	req := httptest.NewRequest("POST", "/x", nil)
	Anthropic{APIKey: "sk-ant"}.Authorize(req)
	if got := req.Header.Get("x-api-key"); got != "sk-ant" {
		t.Errorf("x-api-key = %q, want sk-ant", got)
	}
	if got := req.Header.Get("anthropic-version"); got != "2023-06-01" {
		t.Errorf("anthropic-version = %q, want 2023-06-01", got)
	}
}

func TestMockAndOllamaNoAuth(t *testing.T) {
	for _, p := range []Provider{Mock{URL: "u"}, Ollama{}} {
		req := httptest.NewRequest("POST", "/x", nil)
		p.Authorize(req)
		if req.Header.Get("Authorization") != "" || req.Header.Get("x-api-key") != "" {
			t.Errorf("%s should not set auth headers", p.Name())
		}
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-x")
	if _, ok := FromEnv("openai", "mock").(OpenAI); !ok {
		t.Error("FromEnv(openai) should return OpenAI")
	}
	if _, ok := FromEnv("anthropic", "mock").(Anthropic); !ok {
		t.Error("FromEnv(anthropic) should return Anthropic")
	}
	if _, ok := FromEnv("ollama", "mock").(Ollama); !ok {
		t.Error("FromEnv(ollama) should return Ollama")
	}
	if _, ok := FromEnv("unknown", "mock").(Mock); !ok {
		t.Error("FromEnv(unknown) should fall back to Mock")
	}
}
