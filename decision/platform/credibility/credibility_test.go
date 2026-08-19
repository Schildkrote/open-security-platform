// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package credibility

import (
	"testing"
	"time"
)

// TestAnnotateGolden pins the reliability formula: a fixed observation set
// must always produce the same score, grade, and digest.
func TestAnnotateGolden(t *testing.T) {
	obs := []Observation{
		{Source: "credential-intel", Provenance: ProvenancePrimary, Supports: true, Age: 24 * time.Hour, Independent: true},
		{Source: "people-search:spokeo", Provenance: ProvenanceAggregator, Supports: true, Age: 72 * time.Hour, Independent: true},
		{Source: "voter-records", Provenance: ProvenancePrimary, Supports: true, Age: 30 * 24 * time.Hour, Independent: true},
	}
	a := Annotate("subject is in breach X", obs)

	// provenance: best independent supporting = primary → 1.0
	// corroboration: 3 independent supporting → 0.8
	// recency: freshest = 24h → 1.0
	// consistency: 0 contradictions → 1.0
	// score = (1.0+0.8+1.0+1.0)/4 = 0.95
	if a.Score != 0.95 {
		t.Errorf("score = %.2f, want 0.95", a.Score)
	}
	if a.Grade != "very-high" {
		t.Errorf("grade = %q, want very-high", a.Grade)
	}
	if !a.Advisory {
		t.Error("annotation must be marked advisory")
	}
	if len(a.Factors) != 4 {
		t.Fatalf("factors len = %d, want 4", len(a.Factors))
	}
}

func TestAnnotateContradiction(t *testing.T) {
	obs := []Observation{
		{Source: "a", Provenance: ProvenancePrimary, Supports: true, Age: time.Hour, Independent: true},
		{Source: "b", Provenance: ProvenancePrimary, Supports: false, Age: time.Hour, Independent: true},
	}
	a := Annotate("claim", obs)
	// consistency: 1 contradiction → 0.5
	var cons *Factor
	for i := range a.Factors {
		if a.Factors[i].Name == "consistency" {
			cons = &a.Factors[i]
		}
	}
	if cons == nil || cons.Value != 0.5 {
		t.Errorf("consistency factor = %v, want 0.5", cons)
	}
}

func TestAnnotateEmpty(t *testing.T) {
	a := Annotate("claim", nil)
	if a.Score >= 0.5 {
		t.Errorf("score = %.2f, want < 0.5 with no observations", a.Score)
	}
	if a.Grade == "very-high" {
		t.Error("no observations should not be very-high")
	}
	if a.Digest == "" {
		t.Error("digest must be set")
	}
}

func TestDigestDeterministic(t *testing.T) {
	obs := []Observation{{Source: "x", Provenance: ProvenanceSecondary, Supports: true, Age: time.Hour, Independent: true}}
	a1 := Annotate("c", obs)
	a2 := Annotate("c", obs)
	if a1.Digest != a2.Digest {
		t.Error("digest not deterministic")
	}
}

func TestClaimHashed(t *testing.T) {
	a := Annotate("sensitive claim text", nil)
	if a.ClaimHash == "" || len(a.ClaimHash) != 12 {
		t.Errorf("claim hash = %q, want 12 hex chars", a.ClaimHash)
	}
}

func TestProvenanceRanking(t *testing.T) {
	if !(ProvenancePrimary > ProvenanceSecondary) ||
		!(ProvenanceSecondary > ProvenanceAggregator) ||
		!(ProvenanceAggregator > ProvenanceUnknown) {
		t.Error("provenance ranking broken")
	}
}
