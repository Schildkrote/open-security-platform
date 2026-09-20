// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package source

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// hibpBaseURL is the HIBP k-anonymity API root.
const hibpBaseURL = "https://api.pwnedpasswords.com"

// HIBP is the real Source: the PwnedPasswords k-anonymity API. Only the
// first 5 hex chars of the SHA-1 of the input are sent (range request); the
// full hash never leaves the machine. This keeps PII exposure minimal and
// fits the repo safety model (read-only GETs, user-supplied API key for
// rate-limit headroom, optional).
type HIBP struct {
	BaseURL string
	Client  *http.Client
	APIKey  string // optional; empty = anonymous rate limit
	Timeout time.Duration
}

// NewHIBP returns a HIBP source with defaults.
func NewHIBP() *HIBP {
	return &HIBP{
		BaseURL: hibpBaseURL,
		Client:  &http.Client{},
		Timeout: 10 * time.Second,
	}
}

// Name implements Source.
func (h *HIBP) Name() string { return "hibp" }

// Pwned performs a k-anonymity range lookup for the identifier. For email
// lookups this uses the Pwned Emails endpoint (range on SHA-1(email)); the
// count returned is k-anonymized (0 means "fewer than 1000").
func (h *HIBP) Pwned(ctx context.Context, identifier string) (Answer, error) {
	id := strings.ToLower(strings.TrimSpace(identifier))
	if id == "" {
		return Answer{}, fmt.Errorf("empty identifier")
	}
	if h.Client == nil {
		h.Client = &http.Client{}
	}
	if h.Timeout <= 0 {
		h.Timeout = 10 * time.Second
	}
	if h.BaseURL == "" {
		h.BaseURL = hibpBaseURL
	}
	start := time.Now()
	full := sha1Hex(id)
	prefix := full[:5]
	suffix := full[5:]

	u, err := url.Parse(h.BaseURL + "/range/" + prefix)
	if err != nil {
		return Answer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Answer{}, err
	}
	req.Header.Set("User-Agent", "credential-intel/0.1 (+https://github.com/Schildkrote/open-security-platform)")
	if h.APIKey != "" {
		req.Header.Set("hibp-api-key", h.APIKey)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return Answer{IdentifierHash: full, Source: "hibp", Uncertain: true,
			LatencyMS: time.Since(start).Milliseconds()}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return Answer{IdentifierHash: full, Source: "hibp", Uncertain: true,
			LatencyMS: time.Since(start).Milliseconds()}, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return Answer{IdentifierHash: full, Source: "hibp", Uncertain: true,
				LatencyMS: time.Since(start).Milliseconds()},
			fmt.Errorf("rate limited (429); set -api-key for higher limits")
	}
	if resp.StatusCode != http.StatusOK {
		return Answer{IdentifierHash: full, Source: "hibp", Uncertain: true,
				LatencyMS: time.Since(start).Milliseconds()},
			fmt.Errorf("hibp status %d", resp.StatusCode)
	}

	count := 0
	found := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), strings.ToUpper(suffix)) {
			found = true
			// Format: "SUFFIX:count"
			if idx := strings.Index(line, ":"); idx >= 0 {
				if n, err := strconv.Atoi(line[idx+1:]); err == nil {
					count = n
				}
			}
			break
		}
	}
	return Answer{
		IdentifierHash: full,
		Source:         "hibp",
		Pwned:          found,
		Count:          count,
		Uncertain:      false,
		LatencyMS:      time.Since(start).Milliseconds(),
	}, nil
}

// sha1Hex returns the lowercase hex SHA-1 of s.
func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Breaches fetches the breach list for an identifier from the HIBP
// /range/{prefix}/{email}?unmask=email endpoint.
func (h *HIBP) Breaches(ctx context.Context, identifier string) ([]Breach, error) {
	id := strings.ToLower(strings.TrimSpace(identifier))
	if id == "" {
		return nil, fmt.Errorf("empty identifier")
	}
	full := sha1Hex(id)
	u := h.BaseURL + "/range/" + full[:5] + "/" + url.QueryEscape(id) + "?unmask=email"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "credential-intel/0.1 (+https://github.com/Schildkrote/open-security-platform)")
	if h.APIKey != "" {
		req.Header.Set("hibp-api-key", h.APIKey)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hibp breaches status %d", resp.StatusCode)
	}
	return h.ParseBreachList(body)
}

// ParseBreachList parses the JSON array of breach objects returned by the
// HIBP /range/{prefix}/{email}?unmask=email endpoint.
func (h *HIBP) ParseBreachList(data []byte) ([]Breach, error) {
	var raw []struct {
		Title     string `json:"Title"`
		Name      string `json:"Name"`
		Year      int    `json:"Year"`
		DataClass string `json:"DataClasses"`
		Logo      string `json:"Logo"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make([]Breach, 0, len(raw))
	for _, r := range raw {
		out = append(out, Breach{
			Title: r.Title, Name: r.Name, Year: r.Year,
			DataType: r.DataClass, Logo: r.Logo,
		})
	}
	return out, nil
}
