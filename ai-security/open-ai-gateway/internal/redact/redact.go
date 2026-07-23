// Package redact detects and redacts PII and secrets from text.
package redact

import "regexp"

type Detector struct {
	Name string
	Re   *regexp.Regexp
}

// Mask is the replacement token. The detector name is preserved so audits
// can show what kind of value was removed without revealing the value.
func mask(kind string) string { return "[REDACTED:" + kind + "]" }

var defaultDetectors = []Detector{
	{"EMAIL", regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)},
	{"SSN", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{"CREDIT_CARD", regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`)},
	{"PHONE", regexp.MustCompile(`\b(?:\+?\d{1,3}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b`)},
	{"OPENAI_KEY", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	{"AWS_ACCESS_KEY", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GITHUB_TOKEN", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"SLACK_TOKEN", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"PRIVATE_KEY", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)},
	{"IPV4", regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
}

type Finding struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// Redact replaces every detected PII/secret value in s and returns the
// redacted string plus a summary of what was found.
func Redact(s string) (string, []Finding) {
	return RedactWith(s, defaultDetectors)
}

// RedactWith allows callers (tests, custom policy) to supply detectors.
func RedactWith(s string, detectors []Detector) (string, []Finding) {
	var findings []Finding
	for _, d := range detectors {
		n := len(d.Re.FindAllString(s, -1))
		if n == 0 {
			continue
		}
		s = d.Re.ReplaceAllString(s, mask(d.Name))
		findings = append(findings, Finding{Kind: d.Name, Count: n})
	}
	return s, findings
}
