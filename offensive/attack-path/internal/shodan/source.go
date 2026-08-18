// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package shodan adds the Source connector for dork resolution: the mock
// source returns a deterministic offline device set, the API source queries
// the Shodan API (live-gated).
package shodan

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"encoding/json"
	"fmt"
)

// Device is one exposed device from a dork result.
type Device struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Transport string `json:"transport"`
}

// Source resolves a dork to a set of devices.
type Source interface {
	Name() string
	// Query resolves dork. The mock implementation filters a fixed sample
	// set by the dork's constraints; the API implementation sends the dork
	// to Shodan.
	Query(ctx context.Context, dork string) ([]Device, error)
}

// Mock is an offline Source with a small deterministic device set.
type Mock struct{}

// NewMock returns a Mock source.
func NewMock() *Mock { return &Mock{} }

// Name implements Source.
func (m *Mock) Name() string { return "mock" }

// Query implements Source with a fixed sample device set, filtered by the
// dork's port and product constraints when present.
func (m *Mock) Query(_ context.Context, dork string) ([]Device, error) {
	all := sampleDevices()
	q, err := Parse(dork)
	if err != nil {
		return nil, err
	}
	ports := q.Ports()
	product := q.Value("product")
	var out []Device
	for _, d := range all {
		if len(ports) > 0 && !containsInt(ports, d.Port) {
			continue
		}
		if product != "" && !strings.EqualFold(product, d.Product) {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}

// Value returns the value the query constrains key to (first match), or "".
func (q *Query) Value(key string) string {
	for _, group := range q.Groups {
		for _, t := range group {
			if strings.EqualFold(t.Key, key) {
				return t.Value
			}
		}
	}
	return ""
}

func sampleDevices() []Device {
	return []Device{
		{IP: "192.0.2.10", Port: 443, Product: "nginx", Version: "1.24.0", Hostname: "www.example.com", OS: "Linux", Transport: "tcp"},
		{IP: "192.0.2.10", Port: 80, Product: "nginx", Version: "1.24.0", Hostname: "www.example.com", OS: "Linux", Transport: "tcp"},
		{IP: "198.51.100.5", Port: 22, Product: "OpenSSH", Version: "9.6", Hostname: "bastion.example.com", OS: "Linux", Transport: "tcp"},
		{IP: "198.51.100.6", Port: 3389, Product: "RDP", Version: "10.0", Hostname: "dc01.example.com", OS: "Windows 2022", Transport: "tcp"},
	}
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// API is the real Shodan Source (live-gated): it queries
// https://api.shodan.io/shodan/host/search?key=...&query=... with a
// user-supplied API key. Read-only GET; results are limited to the first
// page (5 results) to stay cheap.
type API struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
	Timeout time.Duration
}

// NewAPI returns an API source with defaults.
func NewAPI() *API {
	return &API{
		BaseURL: "https://api.shodan.io",
		Client:  &http.Client{},
		Timeout: 10 * time.Second,
	}
}

// Name implements Source.
func (a *API) Name() string { return "shodan" }

// Query implements Source against the Shodan host/search endpoint.
func (a *API) Query(ctx context.Context, dork string) ([]Device, error) {
	if a.APIKey == "" {
		return nil, fmt.Errorf("shodan API key required (live-gate)")
	}
	if a.Client == nil {
		a.Client = &http.Client{}
	}
	if a.Timeout <= 0 {
		a.Timeout = 10 * time.Second
	}
	if a.BaseURL == "" {
		a.BaseURL = "https://api.shodan.io"
	}
	u := a.BaseURL + "/shodan/host/search?key=" + a.APIKey + "&query=" + urlQuery(dork) + "&size=5"
	ctx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "attack-path/0.1 (+https://github.com/Schildkrote/open-security-platform)")
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan status %d", resp.StatusCode)
	}
	var body struct {
		Count int `json:"total"`
		Data  []struct {
			IP        string `json:"ip_str"`
			Port      int    `json:"port"`
			Product   string `json:"product"`
			Version   string `json:"version"`
			Hostname  string `json:"hostname"`
			OS        string `json:"os"`
			Transport string `json:"transport"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(body.Data))
	for _, d := range body.Data {
		out = append(out, Device{
			IP: d.IP, Port: d.Port, Product: d.Product, Version: d.Version,
			Hostname: d.Hostname, OS: d.OS, Transport: d.Transport,
		})
	}
	return out, nil
}

// urlQuery percent-encodes a dork for a query string (spaces become +).
func urlQuery(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ':
			b.WriteByte('+')
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '~' || r == ':' || r == '"' || r == '=':
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, "%%%02X", r)
		}
	}
	return b.String()
}
