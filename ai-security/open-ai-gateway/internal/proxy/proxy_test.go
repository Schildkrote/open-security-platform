package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/example/open-ai-gateway/internal/audit"
	"github.com/example/open-ai-gateway/internal/mockupstream"
	"github.com/example/open-ai-gateway/internal/policy"
	"github.com/example/open-ai-gateway/internal/ratelimit"
)

func newTestGateway(t *testing.T, rules []policy.Rule, buf *bytes.Buffer) *Gateway {
	t.Helper()
	up := httptest.NewServer(mockupstream.Handler())
	t.Cleanup(up.Close)
	eng := &policy.Engine{Default: policy.Allow, Rules: rules}
	if err := eng.Compile(); err != nil {
		t.Fatal(err)
	}
	return &Gateway{
		UpstreamURL:    up.URL,
		Engine:         eng,
		Limiter:        ratelimit.New(ratelimit.Limits{RequestsPerMinute: 100, BudgetTokens: 1_000_000}),
		Audit:          audit.New(buf),
		RedactRequest:  true,
		RedactResponse: true,
	}
}

func post(t *testing.T, gw *Gateway, model, content string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)
	return rr
}

func TestEndToEndRedaction(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)

	rr := post(t, gw, "gpt-4o", "my email is jane.doe@example.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "jane.doe@example.com") {
		t.Errorf("PII leaked in response: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "[REDACTED:EMAIL]") {
		t.Errorf("expected redaction marker in response: %s", rr.Body.String())
	}
	if !strings.Contains(buf.String(), `"action":"allow"`) {
		t.Errorf("expected audit allow event, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "EMAIL") {
		t.Errorf("expected redaction recorded in audit: %s", buf.String())
	}
}

func TestEndToEndDeny(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, []policy.Rule{
		{Name: "no-legacy", ModelPattern: "^gpt-3", Action: policy.Deny, Reason: "deprecated"},
	}, &buf)

	rr := post(t, gw, "gpt-3.5-turbo", "hello")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), `"action":"deny"`) {
		t.Errorf("expected audit deny event: %s", buf.String())
	}
}

func TestEndToEndRateLimit(t *testing.T) {
	up := httptest.NewServer(mockupstream.Handler())
	t.Cleanup(up.Close)
	eng := &policy.Engine{Default: policy.Allow}
	_ = eng.Compile()
	var buf bytes.Buffer
	gw := &Gateway{
		UpstreamURL: up.URL,
		Engine:      eng,
		Limiter:     ratelimit.New(ratelimit.Limits{RequestsPerMinute: 1}),
		Audit:       audit.New(&buf),
	}
	if rr := post(t, gw, "m", "a"); rr.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rr.Code)
	}
	if rr := post(t, gw, "m", "b"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request should be rate limited, got %d", rr.Code)
	}
}
