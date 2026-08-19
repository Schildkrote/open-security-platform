// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package ospconnector normalizes open-security-platform findings into ontology objects.
package ospconnector

import (
	"fmt"
	"time"

	"github.com/Schildkrote/ontology"
)

// Finding is a generic OSP / OSINT finding envelope.
type Finding struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"` // username_hit|breach|shodan|attack_path|other
	Subject    string         `json:"subject,omitempty"`
	Summary    string         `json:"summary"`
	Severity   string         `json:"severity,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
	TS         time.Time      `json:"ts"`
	Source     string         `json:"source"` // e.g. offensive/username-enum
}

// Ingest writes findings as Finding objects, optional Person link.
func Ingest(store *ontology.Store, f Finding) (string, error) {
	if f.ID == "" {
		return "", fmt.Errorf("finding id required")
	}
	if f.TS.IsZero() {
		f.TS = time.Now().UTC()
	}
	if f.Source == "" {
		f.Source = "osp"
	}
	id := ontology.MakeID(ontology.TypeFinding, f.ID)
	props := map[string]any{
		"kind":     f.Kind,
		"summary":  f.Summary,
		"severity": f.Severity,
		"ts":       f.TS.UTC().Format(time.RFC3339),
	}
	for k, v := range f.Properties {
		props[k] = v
	}
	if _, err := store.UpsertObject(ontology.Object{
		ID: id, Type: ontology.TypeFinding, Properties: props,
		Classification: "internal",
		Provenance:     ontology.Provenance{Source: f.Source, ExternalID: f.ID, Pipeline: "osp"},
	}); err != nil {
		return "", err
	}
	if f.Subject != "" {
		pid := f.Subject
		if len(pid) < 8 || pid[:7] != "person:" {
			pid = ontology.MakeID(ontology.TypePerson, f.Subject)
		}
		if _, err := store.UpsertObject(ontology.Object{
			ID: pid, Type: ontology.TypePerson,
			Properties: map[string]any{"label": f.Subject},
			Provenance: ontology.Provenance{Source: f.Source},
		}); err != nil {
			return "", err
		}
		if _, err := store.AddLink(ontology.Link{
			Type: ontology.LinkAssociatedWith, From: id, To: pid,
			Provenance: ontology.Provenance{Source: f.Source},
		}); err != nil {
			return "", err
		}
	}
	return id, nil
}

// MockFindings demo OSP traffic.
func MockFindings() []Finding {
	return []Finding{
		{ID: "u1", Kind: "username_hit", Subject: "alice", Summary: "username alice found on github", Severity: "low", Source: "offensive/username-enum"},
		{ID: "b1", Kind: "breach", Subject: "alice", Summary: "email in mock breach list", Severity: "medium", Source: "offensive/credential-intel", Properties: map[string]any{"breach": "mock-corp-2024"}},
	}
}
