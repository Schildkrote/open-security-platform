// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package source

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Mock is an offline Source backed by a bundled sample breach file. The
// sample is a small JSON array of records shaped like HIBP breach objects so
// the real and mock paths stay shape-compatible.
type Mock struct {
	path string // path to the sample JSON ("" = embedded sample)
}

// NewMock returns a Mock using the embedded sample data.
func NewMock() *Mock { return &Mock{} }

// NewMockFile returns a Mock using a user-supplied JSON file.
func NewMockFile(path string) *Mock { return &Mock{path: path} }

// Name implements Source.
func (m *Mock) Name() string { return "mock" }

// Pwned implements Source against the bundled sample data.
func (m *Mock) Pwned(_ context.Context, identifier string) (Answer, error) {
	id := strings.ToLower(strings.TrimSpace(identifier))
	if id == "" {
		return Answer{}, fmt.Errorf("empty identifier")
	}
	records, err := m.records()
	if err != nil {
		return Answer{}, err
	}
	sha := sha1Hex(id)
	var breaches []Breach
	count := 0
	for _, r := range records {
		if !containsFold(r.Emails, id) {
			continue
		}
		count++
		breaches = append(breaches, Breach{
			Title:    r.Title,
			Name:     r.Name,
			Year:     r.Year,
			DataType: "Email addresses",
			Logo:     r.Logo,
		})
	}
	sort.Slice(breaches, func(i, j int) bool { return breaches[i].Year < breaches[j].Year })
	return Answer{
		IdentifierHash: sha,
		Source:         "mock",
		Pwned:          len(breaches) > 0,
		Count:          count,
		Breaches:       breaches,
	}, nil
}

type mockRecord struct {
	Title  string   `json:"Title"`
	Name   string   `json:"Name"`
	Year   int      `json:"Year"`
	Logo   string   `json:"Logo"`
	Emails []string `json:"emails"`
}

func (m *Mock) records() ([]mockRecord, error) {
	if m.path != "" {
		data, err := os.ReadFile(m.path)
		if err != nil {
			return nil, fmt.Errorf("read mock file: %w", err)
		}
		var out []mockRecord
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("parse mock file: %w", err)
		}
		return out, nil
	}
	var out []mockRecord
	if err := json.Unmarshal(embeddedSample, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// embeddedSample is a small, clearly synthetic sample breach set. Names are
// fictitious; the emails are example.com / test addresses only.
var embeddedSample = []byte(`[
  {
    "Title": "ExampleCorp Data Incident",
    "Name": "examplecorp",
    "Year": 2021,
    "Logo": "",
    "emails": ["alice@example.com", "bob@example.com"]
  },
  {
    "Title": "Test Provider Leak",
    "Name": "testprovider",
    "Year": 2019,
    "Logo": "",
    "emails": ["carol@example.com"]
  }
]`)
