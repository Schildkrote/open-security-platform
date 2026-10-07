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
	// OPENAI_KEY matches the classic shape. NOTE the hyphen trap: `sk-live-...`
	// and `sk-ant-...` do NOT match, because [A-Za-z0-9] excludes '-', so only 4
	// alnum characters precede the second hyphen and {20,} fails. Two separate
	// detectors cover the prefixed shapes below rather than loosening this one,
	// which would start matching arbitrary sk- prose.
	{"OPENAI_KEY", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	// NB-2 (round 9): the detector was blind to the credential shapes this gateway
	// itself transmits. provider.go arms Anthropic requests with ANTHROPIC_API_KEY as
	// `x-api-key`, and that shape is `sk-ant-...` with hyphens — so a hostile upstream
	// reflecting the gateway's OWN Anthropic key back through any swept channel passed
	// every layer, because the body sweep, the header sweep, the redirect sweep and the
	// audit chokepoint all consult this same list. A chokepoint is only as good as its
	// detector, and the last mile failed exactly where the product's own credentials
	// live. Added the two shapes this ecosystem actually uses: Anthropic and Okta SSWS.
	{"ANTHROPIC_KEY", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	// Okta System Log tokens: `SSWS ` followed by a 40-character secret, or the
	// `00<40 chars from [a-zA-Z0-9-_]>` form. Both are used by the oiaf Okta adapter,
	// whose PR landed in the sibling repo, so this shape is live in the same product
	// family. Matching the prefixed form is safe and unambiguous.
	{"OKTA_TOKEN", regexp.MustCompile(`\bSSWS [A-Za-z0-9_\-]{20,}`)},
	{"OKTA_SSWS", regexp.MustCompile(`\b00[A-Za-z0-9_\-]{40}\b`)},
	// The other common provider/secret shapes, so the boundary is not limited to what
	// this gateway happens to transmit.
	{"GOOGLE_API_KEY", regexp.MustCompile(`\bAIza[A-Za-z0-9_\-]{35}\b`)},
	{"STRIPE_KEY", regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`)},
	{"SENDGRID_KEY", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b`)},
	{"TWILIO_KEY", regexp.MustCompile(`\bSK[a-f0-9]{32}\b`)},
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
