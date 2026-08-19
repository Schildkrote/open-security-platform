// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package credibility produces an advisory evidence-reliability annotation
// for a claim backed by one or more OSINT observations. It is deliberately
// advisory: it never emits a guilt / credibility verdict, only a graded
// reliability label with the factors that produced it.
//
// Reliability factors (each 0.0..1.0, averaged into the final grade):
//
//   - provenance:    how primary the source is (direct record > secondary
//     report > aggregator > unknown)
//   - corroboration: how many independent sources agree (0 = single source)
//   - recency:       how fresh the oldest supporting observation is
//   - consistency:   whether the sources contradict each other on the claim
//
// The output carries an explicit "advisory" marker and the factor breakdown,
// so a buyer can audit why the grade was assigned.
package credibility

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Provenance ranks source types by how primary they are.
type Provenance int

const (
	ProvenanceUnknown Provenance = iota
	ProvenanceAggregator
	ProvenanceSecondary
	ProvenancePrimary
)

// ProvenanceLabel is the human-readable provenance name.
func (p Provenance) Label() string {
	switch p {
	case ProvenancePrimary:
		return "primary"
	case ProvenanceSecondary:
		return "secondary"
	case ProvenanceAggregator:
		return "aggregator"
	default:
		return "unknown"
	}
}

// Observation is one piece of evidence for (or against) a claim.
type Observation struct {
	// Source is the OSINT source (e.g. "credential-intel", "people-search:spokeo").
	Source string `json:"source"`
	// Provenance ranks how primary the source is.
	Provenance Provenance `json:"provenance"`
	// Supports indicates whether this observation supports (true) or
	// contradicts (false) the claim.
	Supports bool `json:"supports"`
	// Age is how old the observation is (0 = unknown / fresh).
	Age time.Duration `json:"age"`
	// Independent marks whether the source is independent of the others
	// (e.g. two people-search aggregators may share one upstream).
	Independent bool `json:"independent"`
}

// Factor is one reliability factor and its 0.0..1.0 value.
type Factor struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Note  string  `json:"note,omitempty"`
}

// Annotation is the advisory reliability output.
type Annotation struct {
	// ClaimHash is a SHA-256 (first 12 hex) of the claim text.
	ClaimHash string `json:"claim_hash"`
	// Grade is the reliability label: low | medium | high | very-high.
	Grade string `json:"grade"`
	// Score is the 0.0..1.0 average of the factors.
	Score float64 `json:"score"`
	// Factors is the per-factor breakdown.
	Factors []Factor `json:"factors"`
	// Advisory marks this as an annotation, not a verdict.
	Advisory bool `json:"advisory"`
	// Observations is the input list (redacted).
	Observations []Observation `json:"observations"`
	// Generated is the generation timestamp.
	Generated time.Time `json:"generated"`
	// Digest is a SHA-256 of the canonical annotation (for the audit chain).
	Digest string `json:"digest"`
}

// Grade assigns a label from a 0.0..1.0 score.
func Grade(score float64) string {
	switch {
	case score < 0.25:
		return "low"
	case score < 0.5:
		return "medium"
	case score < 0.75:
		return "high"
	default:
		return "very-high"
	}
}

// Annotate computes the reliability annotation for a claim from its
// observations.
func Annotate(claim string, obs []Observation) *Annotation {
	// --- provenance: best provenance among supporting, independent sources
	provScore := 0.0
	bestProv := ProvenanceUnknown
	for _, o := range obs {
		if o.Supports && o.Independent && o.Provenance > bestProv {
			bestProv = o.Provenance
		}
	}
	switch bestProv {
	case ProvenancePrimary:
		provScore = 1.0
	case ProvenanceSecondary:
		provScore = 0.7
	case ProvenanceAggregator:
		provScore = 0.4
	default:
		provScore = 0.2
	}
	provNote := fmt.Sprintf("best independent supporting source: %s", bestProv.Label())

	// --- corroboration: count of independent supporting sources
	supporting := 0
	for _, o := range obs {
		if o.Supports && o.Independent {
			supporting++
		}
	}
	corrScore := 0.0
	if supporting >= 4 {
		corrScore = 1.0
	} else if supporting >= 3 {
		corrScore = 0.8
	} else if supporting == 2 {
		corrScore = 0.5
	} else if supporting == 1 {
		corrScore = 0.2
	}
	corrNote := fmt.Sprintf("%d independent supporting source(s)", supporting)

	// --- recency: freshest supporting observation
	freshest := time.Duration(0)
	freshFound := false
	for _, o := range obs {
		if o.Supports {
			if !freshFound || o.Age < freshest {
				freshest = o.Age
				freshFound = true
			}
		}
	}
	recScore := 0.5
	recNote := "no supporting observations"
	if freshFound {
		switch {
		case freshest <= 7*24*time.Hour:
			recScore = 1.0
		case freshest <= 30*24*time.Hour:
			recScore = 0.8
		case freshest <= 90*24*time.Hour:
			recScore = 0.5
		case freshest <= 365*24*time.Hour:
			recScore = 0.3
		default:
			recScore = 0.1
		}
		recNote = fmt.Sprintf("freshest supporting observation: %s old", freshest.Round(time.Hour))
	}

	// --- consistency: do any independent sources contradict the claim?
	contradictions := 0
	for _, o := range obs {
		if !o.Supports && o.Independent {
			contradictions++
		}
	}
	consScore := 1.0
	if contradictions >= 2 {
		consScore = 0.2
	} else if contradictions == 1 {
		consScore = 0.5
	}
	consNote := fmt.Sprintf("%d independent contradicting source(s)", contradictions)

	factors := []Factor{
		{Name: "provenance", Value: round2(provScore), Note: provNote},
		{Name: "corroboration", Value: round2(corrScore), Note: corrNote},
		{Name: "recency", Value: round2(recScore), Note: recNote},
		{Name: "consistency", Value: round2(consScore), Note: consNote},
	}
	score := round2((provScore + corrScore + recScore + consScore) / 4.0)

	claimSum := sha256.Sum256([]byte(claim))
	a := &Annotation{
		ClaimHash:    hex.EncodeToString(claimSum[:])[:12],
		Grade:        Grade(score),
		Score:        score,
		Factors:      factors,
		Advisory:     true,
		Observations: obs,
		Generated:    time.Now().UTC(),
	}
	a.Digest = a.digest()
	return a
}

func (a *Annotation) digest() string {
	s := "claim=" + a.ClaimHash + "\nscore=" + fmt.Sprintf("%.2f", a.Score) + "\n"
	for _, f := range a.Factors {
		s += fmt.Sprintf("factor=%s value=%.2f\n", f.Name, f.Value)
	}
	for _, o := range a.Observations {
		s += fmt.Sprintf("obs src=%s prov=%s supports=%v indep=%v\n", o.Source, o.Provenance.Label(), o.Supports, o.Independent)
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
