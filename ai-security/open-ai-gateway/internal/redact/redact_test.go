package redact

import (
	"strings"
	"testing"
)

func TestRedactPII(t *testing.T) {
	in := "Contact jane.doe@example.com or call 415-555-1234, SSN 123-45-6789."
	out, findings := Redact(in)
	for _, kind := range []string{"EMAIL", "PHONE", "SSN"} {
		if !hasKind(findings, kind) {
			t.Errorf("expected finding %s, got %+v", kind, findings)
		}
	}
	if strings.Contains(out, "jane.doe@example.com") {
		t.Errorf("email not redacted: %s", out)
	}
	if !strings.Contains(out, "[REDACTED:EMAIL]") {
		t.Errorf("missing redaction marker: %s", out)
	}
}

func TestRedactSecrets(t *testing.T) {
	in := "key=sk-abcdefghij0123456789ABCDEF and aws AKIAABCDEFGHIJKLMNOP"
	out, findings := Redact(in)
	if !hasKind(findings, "OPENAI_KEY") || !hasKind(findings, "AWS_ACCESS_KEY") {
		t.Fatalf("expected secret findings, got %+v", findings)
	}
	if strings.Contains(out, "sk-") || strings.Contains(out, "AKIA") {
		t.Errorf("secret leaked: %s", out)
	}
}

func TestRedactClean(t *testing.T) {
	out, findings := Redact("hello world, nothing sensitive here")
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
	if out != "hello world, nothing sensitive here" {
		t.Errorf("content changed unexpectedly: %s", out)
	}
}

func hasKind(fs []Finding, kind string) bool {
	for _, f := range fs {
		if f.Kind == kind {
			return true
		}
	}
	return false
}
