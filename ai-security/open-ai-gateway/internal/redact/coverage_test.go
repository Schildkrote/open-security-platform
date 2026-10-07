package redact

// Detector coverage boundary — the test NB-2 asked for.
//
// A chokepoint is only as good as its detector. Round 9 found that the gateway's own
// sweeps (body, headers, redirect Location, audit record) all consult this pattern
// list, and that the list did not recognise the credential shape the gateway itself
// transmits to Anthropic. Every layer passed while the secret went through untouched.
//
// This file enumerates the shapes the detector must recognise, so the boundary is
// explicit and a missing pattern fails a test rather than silently shipping.
//
// Samples are BUILT from strings.Repeat, never written as literals. Credential-shaped
// literals get elided by display/secret masking on the way to disk, which produced
// three undetectable canaries earlier in this branch — a test asserting "no canary"
// against a canary that cannot be matched passes for the wrong reason.

import (
	"strings"
	"testing"
)

// TestDetectorsCoverTheKnownCredentialShapes is the positive half: every shape this
// product family handles must be detected and actually removed.
func TestDetectorsCoverTheKnownCredentialShapes(t *testing.T) {
	alnum := strings.Repeat("aB1c", 9) // 36 chars, alphanumeric only
	cases := []struct {
		kind   string
		sample string
		why    string
	}{
		// The classic OpenAI shape. Note the hyphen trap documented in redact.go:
		// `sk-ant-...` and `sk-live-...` do NOT match this pattern, because
		// [A-Za-z0-9] excludes '-', so {20,} can never be satisfied past a hyphen.
		{"OPENAI_KEY", "sk-" + strings.Repeat("9", 36),
			"the baseline shape every other key detector was modelled on"},
		// NB-2: the shape provider.go arms requests with (ANTHROPIC_API_KEY -> x-api-key).
		// This was the most consequential gap, because it is the gateway's OWN credential.
		{"ANTHROPIC_KEY", "sk-ant-api03-" + alnum,
			"the credential this gateway itself transmits to a supported provider"},
		// Okta System Log tokens, used by the sibling oiaf Okta adapter.
		{"OKTA_TOKEN", "SSWS 00" + alnum,
			"Okta Authorization: SSWS <token> header form"},
		{"OKTA_SSWS", "00" + strings.Repeat("z", 40),
			"Okta SSWS token body form (^00[a-zA-Z0-9-_]{40}$)"},
		{"GOOGLE_API_KEY", "AIza" + strings.Repeat("Sy1bC2dE3fG4hI5j", 3)[:35],
			"Google AIza-prefixed API key"},
		{"STRIPE_KEY", "sk_live_" + strings.Repeat("9", 24),
			"Stripe live secret key"},
		{"STRIPE_KEY", "sk_test_" + strings.Repeat("9", 24),
			"Stripe test secret key (same detector)"},
		{"SENDGRID_KEY", "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43),
			"SendGrid two-part API key"},
		{"TWILIO_KEY", "SK" + strings.Repeat("a1b2c3d4", 4),
			"Twilio 32-hex secret key"},
	}

	for _, c := range cases {
		name := c.kind + "/" + c.why
		t.Run(name, func(t *testing.T) {
			cleaned, kinds := Redact("prefix " + c.sample + " suffix")

			found := false
			for _, k := range kinds {
				if k.Kind == c.kind {
					found = true
					if k.Count != 1 {
						t.Errorf("%s: Count=%d, want 1", c.kind, k.Count)
					}
				}
			}
			if !found {
				t.Errorf("NO DETECTOR for %s (sample %d chars). %s. A chokepoint that "+
					"inspects this text cannot redact what it cannot recognise, so the "+
					"value would pass through every layer — body sweep, header sweep, "+
					"redirect sweep and audit chokepoint alike.",
					c.kind, len(c.sample), c.why)
			}
			if strings.Contains(cleaned, c.sample) {
				t.Errorf("%s was reported but the value SURVIVED: %q", c.kind, cleaned)
			}
			if !strings.Contains(cleaned, "prefix ") || !strings.Contains(cleaned, " suffix") {
				t.Errorf("%s redaction damaged the surrounding text: %q", c.kind, cleaned)
			}
			if !strings.Contains(cleaned, "[REDACTED:") {
				t.Errorf("%s produced no mask marker: %q", c.kind, cleaned)
			}
		})
	}
}

// TestDetectorsDoNotOverRedactOrdinaryText is the negative half. A detector broad
// enough to catch every key shape would also eat ordinary prose, and a sweep that
// mangles legitimate content is a functional regression, not a security win.
func TestDetectorsDoNotOverRedactOrdinaryText(t *testing.T) {
	benign := []string{
		"the model said sk is a variable name",
		"00 is just a number",
		"SG is a country code",
		"AIza is not a key by itself",
		"SSWS without a token after it is prose",
		"sk-ant- alone is not a credential",
		"a short SK1a2b is not a Twilio key",
		"the completion discussed JSON schema validation",
		"usage: 42 tokens, model gpt-4o",
	}
	for _, b := range benign {
		_, kinds := Redact(b)
		if len(kinds) != 0 {
			t.Errorf("OVER-REDACTION: benign text %q produced findings %v", b, kinds)
		}
	}
}

// TestDetectorRedactionIsIdempotent guards against marker recursion. A mask contains
// letters and brackets, so a second pass could match inside its own output — the same
// class of bug that produced [red[redacted]cted] in the oiaf Okta matcher.
func TestDetectorRedactionIsIdempotent(t *testing.T) {
	once, _ := Redact("key=sk-" + strings.Repeat("9", 36))
	twice, kinds := Redact(once)
	if once != twice {
		t.Errorf("redaction is NOT idempotent:\n  once  = %q\n  twice = %q", once, twice)
	}
	if len(kinds) != 0 {
		t.Errorf("a second pass found something in already-redacted text: %v (marker recursion)", kinds)
	}
	if strings.Contains(once, "[REDACTED:[REDACTED:") {
		t.Errorf("nested mask markers indicate recursion: %q", once)
	}
}
