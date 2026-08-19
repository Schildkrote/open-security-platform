// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// ExternalScan runs a read-only nmap service-version probe (and an optional
// nuclei template scan) against one host:port target. It is the "aggressive"
// sub-gate of active-scanning: it invokes external binaries that are NOT
// part of the OSS core (nmap, nuclei). Both are optional — if a binary is
// missing, that probe is skipped and reported as "unavailable" (the scan
// never fails because of a missing binary).
//
// Safety:
//   - nmap: -sV (service version) + -Pn (no ping, read-only) + -p <port>
//     (single port, no sweep). No -sC/-sC+/-A (no script/exploit templates).
//   - nuclei: -t <template> with only read-only templates (the caller picks
//     the template; the default http-tech-detect is read-only).
type ExternalScan struct {
	Nmap    string // path to nmap ("" = use PATH)
	Nuclei  string // path to nuclei ("" = use PATH)
	Timeout time.Duration
}

func NewExternalScan() *ExternalScan {
	return &ExternalScan{Timeout: 30 * time.Second}
}

// nmapResult is the subset of nmap -oJSON we care about.
type nmapResult struct {
	Hosts []struct {
		Addresses []struct {
			Addr     string `json:"addr"`
			AddrType string `json:"addrtype"`
		} `json:"addresses"`
		Ports []struct {
			PortID  int    `json:"portid"`
			Service string `json:"service"`
			Version string `json:"product"`
			State   string `json:"state"`
		} `json:"ports"`
	} `json:"hosts"`
}

// RunNmap issues one read-only nmap -sV probe against host:port.
func (e *ExternalScan) RunNmap(ctx context.Context, host, port string) (map[string]any, error) {
	bin := e.Nmap
	if bin == "" {
		bin = "nmap"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return map[string]any{"status": "unavailable", "reason": "nmap not found in PATH"}, nil
	}
	if e.Timeout <= 0 {
		e.Timeout = 30 * time.Second
	}
	hctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	args := []string{"-sV", "-Pn", "-p", port, "-oJSON", "-", host}
	cmd := exec.CommandContext(hctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		if hctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("nmap timed out after %s", e.Timeout)
		}
		return nil, fmt.Errorf("nmap: %w", err)
	}
	var nr nmapResult
	if err := json.Unmarshal(out, &nr); err != nil {
		return map[string]any{"status": "parse-error", "reason": err.Error()}, nil
	}
	ev := map[string]any{"status": "ok"}
	if len(nr.Hosts) > 0 {
		h := nr.Hosts[0]
		ev["host"] = host
		if len(h.Addresses) > 0 {
			ev["addr"] = h.Addresses[0].Addr
		}
		for _, p := range h.Ports {
			ev["service"] = p.Service
			ev["state"] = p.State
			if p.Version != "" {
				ev["version"] = p.Version
			}
			break // single port
		}
	}
	return ev, nil
}

// RunNuclei issues one read-only nuclei template scan against host:port.
func (e *ExternalScan) RunNuclei(ctx context.Context, host, port, template string) (map[string]any, error) {
	bin := e.Nuclei
	if bin == "" {
		bin = "nuclei"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return map[string]any{"status": "unavailable", "reason": "nuclei not found in PATH"}, nil
	}
	if e.Timeout <= 0 {
		e.Timeout = 30 * time.Second
	}
	if template == "" {
		template = "http/technologies/" // read-only tech-detect templates
	}
	scheme := "http"
	if port == "443" {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%s/", scheme, host, port)
	hctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	args := []string{"-t", template, "-oJSON", "-", "-silent", url}
	cmd := exec.CommandContext(hctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		if hctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("nuclei timed out after %s", e.Timeout)
		}
		// nuclei exits non-zero when it finds findings; that's not an error.
		if len(out) == 0 {
			return map[string]any{"status": "ok", "findings": 0}, nil
		}
	}
	findings := 0
	var lines []map[string]any
	for _, line := range splitLines(string(out)) {
		var f map[string]any
		if json.Unmarshal([]byte(line), &f) == nil {
			lines = append(lines, f)
			findings++
		}
	}
	return map[string]any{
		"status":   "ok",
		"findings": findings,
		"details":  lines,
	}, nil
}

// splitLines splits s on newlines, dropping empty lines.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// whichBinary reports the resolved path or "not-found".
func whichBinary(bin string) string {
	p, err := exec.LookPath(bin)
	if err != nil {
		return "not-found"
	}
	return p
}

// Ensure os import is used (for future env-based binary overrides).
var _ = os.Getenv
