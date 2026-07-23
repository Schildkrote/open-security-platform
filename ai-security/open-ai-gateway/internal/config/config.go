// Package config loads gateway configuration from JSON.
package config

import (
	"encoding/json"
	"os"

	"github.com/Schildkrote/open-ai-gateway/internal/policy"
	"github.com/Schildkrote/open-ai-gateway/internal/ratelimit"
	"github.com/Schildkrote/open-ai-gateway/internal/registry"
)

type Config struct {
	Listen          string           `json:"listen"`
	UpstreamURL     string           `json:"upstream_url"`
	UseMockUpstream bool             `json:"use_mock_upstream"`
	RedactRequest   bool             `json:"redact_request"`
	RedactResponse  bool             `json:"redact_response"`
	AuditFile       string           `json:"audit_file"`
	DefaultAction   policy.Action    `json:"default_action"`
	Rules           []policy.Rule    `json:"rules"`
	Limits          ratelimit.Limits `json:"limits"`
	Tools           []registry.Tool  `json:"tools"`
}

func Default() Config {
	return Config{
		Listen:          ":8080",
		UseMockUpstream: true,
		RedactRequest:   true,
		RedactResponse:  true,
		AuditFile:       "audit.jsonl",
		DefaultAction:   policy.Allow,
		Limits:          ratelimit.Limits{RequestsPerMinute: 60, BudgetTokens: 1_000_000, PricePer1KTokens: 0.01},
	}
}

// Load reads a JSON config file, falling back to defaults for missing fields.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
