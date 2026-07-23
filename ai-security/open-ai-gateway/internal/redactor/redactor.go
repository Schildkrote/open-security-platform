// Package redactor defines the PII/secret redaction connector interface for
// open-ai-gateway (Phase 3). The Regex backend wraps the built-in regex
// detectors (offline default); the Presidio backend calls Microsoft Presidio's
// anonymizer API for NER-based redaction. Selecting a backend never breaks the
// offline model: with none configured the gateway uses Regex.
package redactor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Schildkrote/open-ai-gateway/internal/redact"
)

// Redactor redacts sensitive content, returning the cleaned text and the kinds
// of entities found (e.g. "EMAIL", "OPENAI_KEY").
type Redactor interface {
	Redact(text string) (cleaned string, kinds []string)
}

// Regex wraps the built-in regex detectors (offline default).
type Regex struct{}

// Redact implements Redactor using the regex detectors.
func (Regex) Redact(text string) (string, []string) {
	cleaned, findings := redact.Redact(text)
	kinds := make([]string, 0, len(findings))
	for _, f := range findings {
		kinds = append(kinds, f.Kind)
	}
	return cleaned, kinds
}

// Presidio calls a Presidio anonymizer service (Real backend).
type Presidio struct {
	BaseURL string
	client  *http.Client
}

// NewPresidio targets a Presidio anonymizer base URL (e.g. http://localhost:5001).
func NewPresidio(baseURL string) *Presidio {
	return &Presidio{BaseURL: baseURL, client: &http.Client{Timeout: 10 * time.Second}}
}

// Redact calls Presidio's /anonymize endpoint. On any error it fails open
// (returns the original text) so a down Presidio never blocks the gateway.
func (p *Presidio) Redact(text string) (string, []string) {
	body, _ := json.Marshal(map[string]any{"text": text})
	req, err := http.NewRequest(http.MethodPost, p.BaseURL+"/anonymize", bytes.NewReader(body))
	if err != nil {
		return text, nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return text, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return text, nil
	}
	var out struct {
		Text  string `json:"text"`
		Items []struct {
			EntityType string `json:"entity_type"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return text, nil
	}
	kinds := make([]string, 0, len(out.Items))
	for _, item := range out.Items {
		kinds = append(kinds, item.EntityType)
	}
	return out.Text, kinds
}
