// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package source

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout bounds a single real probe.
const DefaultTimeout = 8 * time.Second

// HTTP is a real Source that probes service URLs with read-only GET requests.
// It uses response-code differentials: a service reports "found" when the
// account URL returns 200 and the not-found URL returns a 4xx. Services with
// no differential return Uncertain. Only read-only probes are made (no
// credentials, no POSTs), consistent with the repo safety model.
type HTTP struct {
	Client  *http.Client
	Timeout time.Duration
}

// NewHTTP returns an HTTP source with sane defaults.
func NewHTTP() *HTTP {
	return &HTTP{Client: &http.Client{}, Timeout: DefaultTimeout}
}

// Name implements Source.
func (h *HTTP) Name() string { return "http" }

// Probe performs a read-only GET on the account URL and compares it against
// the not-found URL. The not-found URL is derived by replacing the username
// placeholder with a high-entropy non-colliding token.
func (h *HTTP) Probe(ctx context.Context, service, accountURL, username string) (Result, error) {
	if h.Timeout <= 0 {
		h.Timeout = DefaultTimeout
	}
	if h.Client == nil {
		h.Client = &http.Client{}
	}
	accountURL = strings.ReplaceAll(accountURL, "{username}", username)
	notFoundURL := strings.ReplaceAll(accountURL, username, nonExistentToken(username))

	start := time.Now()
	codeA, err := h.get(ctx, accountURL)
	if err != nil {
		return Result{Service: service, URL: accountURL, Uncertain: true, LatencyMS: time.Since(start).Milliseconds()}, err
	}
	codeB, errB := h.get(ctx, notFoundURL)
	if errB != nil {
		return Result{Service: service, URL: accountURL, Uncertain: true, LatencyMS: time.Since(start).Milliseconds()}, errB
	}
	latency := time.Since(start).Milliseconds()

	found := codeA == http.StatusOK && codeB >= 400 && codeB < 500
	if codeA >= 400 && codeA < 500 {
		// Service 404s everything: only "found" if the not-found URL differs.
		found = codeA != codeB
	}
	uncertain := !found && codeA == codeB // no usable differential
	return Result{
		Service:   service,
		URL:       accountURL,
		Found:     found,
		Uncertain: uncertain,
		LatencyMS: latency,
	}, nil
}

// get issues one read-only GET and returns the status code.
func (h *HTTP) get(ctx context.Context, rawURL string) (int, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", rawURL, err)
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return 0, fmt.Errorf("scheme %q not allowed (http/https only)", u.Scheme)
	}
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "username-enum/0.1 (+https://github.com/Schildkrote/open-security-platform)")
	resp, err := h.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return resp.StatusCode, nil
}

// nonExistentToken builds a token that is effectively guaranteed not to be
// a real username (username + high-entropy suffix).
func nonExistentToken(username string) string {
	return username + "-nouser-" + fmt.Sprintf("%x", 0x9e3779b9^len(username))
}
