// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package obpconnector ingests open-biometric-platform match hits.
// Raw embeddings/images never enter the ontology — only pseudonyms + scores.
package obpconnector

import (
	"fmt"
	"time"

	"github.com/Schildkrote/ontology"
)

// MatchHit is a redacted OBP match event.
type MatchHit struct {
	ID            string    `json:"id"`
	ClientPseudo  string    `json:"client_pseudo"` // not real name
	ProbeID       string    `json:"probe_id"`
	Score         float64   `json:"score"`
	Source        string    `json:"source"` // targeted_search|cctv_authorized|...
	TS            time.Time `json:"ts"`
	RetentionDays int       `json:"retention_days,omitempty"`
}

// Ingest writes BiometricHit + Person(pseudo) objects.
func Ingest(store *ontology.Store, h MatchHit) (string, error) {
	if h.ID == "" || h.ClientPseudo == "" {
		return "", fmt.Errorf("id and client_pseudo required")
	}
	if h.TS.IsZero() {
		h.TS = time.Now().UTC()
	}
	if h.Source == "" {
		h.Source = "obp"
	}
	personID := ontology.MakeID(ontology.TypePerson, h.ClientPseudo)
	if _, err := store.UpsertObject(ontology.Object{
		ID:             personID,
		Type:           ontology.TypePerson,
		Classification: "restricted",
		Properties: map[string]any{
			"pseudo":     h.ClientPseudo,
			"protection": true,
		},
		Provenance: ontology.Provenance{Source: "obp", ExternalID: h.ClientPseudo},
	}); err != nil {
		return "", err
	}
	hitID := ontology.MakeID(ontology.TypeBiometricHit, h.ID)
	if _, err := store.UpsertObject(ontology.Object{
		ID:             hitID,
		Type:           ontology.TypeBiometricHit,
		Classification: "restricted",
		Properties: map[string]any{
			"score":          h.Score,
			"probe_id":       h.ProbeID,
			"source":         h.Source,
			"ts":             h.TS.UTC().Format(time.RFC3339),
			"retention_days": h.RetentionDays,
		},
		Provenance: ontology.Provenance{Source: "obp", ExternalID: h.ID, Pipeline: "match"},
	}); err != nil {
		return "", err
	}
	if _, err := store.AddLink(ontology.Link{
		Type: ontology.LinkAssociatedWith, From: hitID, To: personID,
		Provenance: ontology.Provenance{Source: "obp"},
	}); err != nil {
		return "", err
	}
	return hitID, nil
}

// MockHits demo OBP traffic.
func MockHits() []MatchHit {
	return []MatchHit{
		{ID: "m1", ClientPseudo: "2bd806c97f0e", ProbeID: "web-77", Score: 0.91, Source: "targeted_search", RetentionDays: 30},
		{ID: "m2", ClientPseudo: "2bd806c97f0e", ProbeID: "news-12", Score: 0.87, Source: "targeted_search", RetentionDays: 30},
	}
}
