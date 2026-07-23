package redactor

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegexRedactor(t *testing.T) {
	cleaned, kinds := Regex{}.Redact("contact jane.doe@example.com now")
	if len(kinds) == 0 {
		t.Fatal("expected at least one finding kind")
	}
	found := false
	for _, k := range kinds {
		if k == "EMAIL" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected EMAIL kind, got %v", kinds)
	}
	if cleaned == "contact jane.doe@example.com now" {
		t.Error("expected the email to be redacted")
	}
}

func TestPresidioRedactor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/anonymize" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"contact <EMAIL> now","items":[{"entity_type":"EMAIL_ADDRESS"}]}`))
	}))
	defer srv.Close()

	cleaned, kinds := NewPresidio(srv.URL).Redact("contact jane.doe@example.com now")
	if cleaned != "contact <EMAIL> now" {
		t.Errorf("cleaned = %q", cleaned)
	}
	if len(kinds) != 1 || kinds[0] != "EMAIL_ADDRESS" {
		t.Errorf("kinds = %v, want [EMAIL_ADDRESS]", kinds)
	}
}

func TestPresidioFailsOpen(t *testing.T) {
	// Unreachable service -> returns original text, no kinds.
	cleaned, kinds := NewPresidio("http://127.0.0.1:1").Redact("secret text")
	if cleaned != "secret text" || len(kinds) != 0 {
		t.Errorf("expected fail-open, got %q, %v", cleaned, kinds)
	}
}
