// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// PII redaction for live-recon results. The safety model requires that full
// names, emails, and phone numbers are hashed or masked before they reach the
// audit log or stdout (without -verbose).
package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+`)
	phoneRe = regexp.MustCompile(`\+?\d[\d\- ]{7,}\d`)
)

// HashPII returns a short (first 12 hex chars) SHA-256 of the value, suitable
// for the audit log. The full value is never stored.
func HashPII(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])[:12]
}

// MaskEmail keeps the first char of the local part and the full domain,
// masking the rest of the local part with 4 stars:
// "jane.doe@example.com" -> "j****@example.com".
func MaskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 1 {
		return "***"
	}
	local, domain := email[:at], email[at:]
	if len(local) <= 2 {
		return local[0:1] + "***" + domain
	}
	return local[0:1] + "****" + domain
}

// MaskPhone keeps the last 2 digits, masking the rest:
// "555-123-4567" -> "********67". Numbers shorter than 4 digits are fully
// masked (revealing them would leak too much).
func MaskPhone(phone string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
	if len(digits) < 4 {
		return strings.Repeat("*", len(digits))
	}
	return strings.Repeat("*", len(digits)-2) + digits[len(digits)-2:]
}

// RedactString scans s for emails and phone numbers and masks them.
// Names are not masked here (the caller hashes them via HashPII).
func RedactString(s string) string {
	s = emailRe.ReplaceAllStringFunc(s, MaskEmail)
	s = phoneRe.ReplaceAllStringFunc(s, MaskPhone)
	return s
}

// RedactEvidence walks a map and masks any email/phone values found.
func RedactEvidence(e map[string]any) map[string]any {
	out := make(map[string]any, len(e))
	for k, v := range e {
		switch val := v.(type) {
		case string:
			out[k] = RedactString(val)
		default:
			out[k] = v
		}
	}
	return out
}
