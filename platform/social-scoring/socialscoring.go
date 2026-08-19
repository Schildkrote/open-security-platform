// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package socialscoring generates a scored, explainable OSINT dossier from a
// set of hits. It is deliberately an evidence pack, not a verdict engine:
//
//   - Every score contribution cites its input (source, category, weight).
//   - The formula is fixed and exposed (see Formula below), so a buyer can
//     recompute the score from the dossier alone.
//   - The output carries an explicit "advisory" marker and a list of the
//     lawful bases that must be in place before the dossier is used.
//   - No automated guilt / credibility decision is emitted (that is the
//     credibility pack's advisory annotation, and even that is advisory).
//
// This matches the product stance: ODP emits decisions about processing
// (consent / basis / retention), never about people.
package socialscoring

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Hit is one OSINT observation fed to the scorer.
type Hit struct {
	// Source is the OSINT source (e.g. "credential-intel", "username-enum",
	// "people-search:spokeo").
	Source string `json:"source"`
	// Category is the osint-taxonomy category id (e.g. "breach-credential").
	Category string `json:"category"`
	// Detail is a redacted one-line description (no raw PII).
	Detail string `json:"detail,omitempty"`
	// Recency is how old the observation is (0 = unknown).
	Recency time.Duration `json:"recency"`
}

// Weight is the per-category scoring weight. Weights are fixed and exposed;
// they are tunable per-pack in the future but default to these values.
type Weight struct {
	Category string  `json:"category"`
	Name     string  `json:"name"`
	Value    float64 `json:"value"`
}

// DefaultWeights is the fixed, exposed scoring formula.
//
// The score is a weighted sum of hit categories, capped at 1.0, with a
// recency decay (observations older than 90 days count for half).
var DefaultWeights = []Weight{
	{"breach-credential", "Breach / credential-dump exposure", 0.30},
	{"recovery-reveal", "Masked-identity reveal", 0.20},
	{"username-enum", "Username enumeration", 0.10},
	{"account-existence", "Account-existence enumeration", 0.10},
	{"people-search", "People-search / background-check", 0.15},
	{"auth-scrape", "Authenticated platform scraping", 0.10},
	{"active-scanning", "Active attack-surface scanning", 0.05},
	{"shodan", "Shodan / internet-wide query", 0.05},
	{"geolocation", "Geolocation enrichment", 0.10},
}

// Formula is the human-readable scoring formula (embedded in every dossier).
const Formula = "score = min(1.0, sum(weight[category] * recency_factor) / max_possible); recency_factor = 1.0 if age <= 90d else 0.5; max_possible = sum of all weights"

// Score is the per-category contribution to the final score.
type Score struct {
	Category string  `json:"category"`
	Name     string  `json:"name"`
	Weight   float64 `json:"weight"`
	Hits     int     `json:"hits"`
	Decayed  bool    `json:"decayed"`
	Points   float64 `json:"points"`
}

// Dossier is the scored, explainable output.
type Dossier struct {
	// SubjectHash is a SHA-256 (first 12 hex) of the subject identifier.
	// The raw identifier is never stored.
	SubjectHash string `json:"subject_hash"`
	// Score is the final 0.0..1.0 score.
	Score float64 `json:"score"`
	// Levels is a human-readable band (low/medium/high/elevated).
	Level string `json:"level"`
	// Formula is the scoring formula (fixed, exposed).
	Formula string `json:"formula"`
	// Breakdown is the per-category contribution.
	Breakdown []Score `json:"breakdown"`
	// Hits is the redacted input list.
	Hits []Hit `json:"hits"`
	// Advisory marks this as an evidence pack, not a verdict.
	Advisory bool `json:"advisory"`
	// Bases is the list of lawful bases that must be in place before use.
	Bases []string `json:"bases"`
	// Generated is the generation timestamp.
	Generated time.Time `json:"generated"`
	// Digest is a SHA-256 of the canonical dossier (for the audit chain).
	Digest string `json:"digest"`
}

// ScoreHits computes the dossier for a subject from a set of hits.
func ScoreHits(subject string, hits []Hit) *Dossier {
	maxPossible := 0.0
	for _, w := range DefaultWeights {
		maxPossible += w.Value
	}

	var pointsTotal float64
	var breakdown []Score
	for _, w := range DefaultWeights {
		n := 0
		anyDecay := false
		for _, h := range hits {
			if h.Category == w.Category {
				n++
				if h.Recency > 90*24*time.Hour {
					anyDecay = true
				}
			}
		}
		if n == 0 {
			continue
		}
		factor := 1.0
		if anyDecay {
			factor = 0.5
		}
		points := w.Value * factor
		pointsTotal += points
		breakdown = append(breakdown, Score{
			Category: w.Category,
			Name:     w.Name,
			Weight:   w.Value,
			Hits:     n,
			Decayed:  anyDecay,
			Points:   round4(points),
		})
	}

	score := 0.0
	if maxPossible > 0 {
		score = round4(pointsTotal / maxPossible)
	}

	subjHash := sha256.Sum256([]byte(strings.TrimSpace(subject)))
	d := &Dossier{
		SubjectHash: hex.EncodeToString(subjHash[:])[:12],
		Score:       score,
		Level:       level(score),
		Formula:     Formula,
		Breakdown:   breakdown,
		Hits:        hits,
		Advisory:    true,
		Bases:       []string{"consent", "legitimate_interest", "dpia_acknowledged"},
		Generated:   time.Now().UTC(),
	}
	d.Digest = d.digest()
	return d
}

func (d *Dossier) digest() string {
	var b strings.Builder
	b.WriteString("subject=" + d.SubjectHash + "\n")
	b.WriteString(fmt.Sprintf("score=%.4f\n", d.Score))
	for _, s := range d.Breakdown {
		b.WriteString(fmt.Sprintf("cat=%s hits=%d decayed=%v points=%.4f\n", s.Category, s.Hits, s.Decayed, s.Points))
	}
	for _, h := range d.Hits {
		b.WriteString(fmt.Sprintf("hit src=%s cat=%s\n", h.Source, h.Category))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func level(s float64) string {
	switch {
	case s < 0.2:
		return "low"
	case s < 0.4:
		return "medium"
	case s < 0.7:
		return "high"
	default:
		return "elevated"
	}
}

func round4(f float64) float64 {
	return float64(int(f*10000+0.5)) / 10000
}

// SortBreakdown orders the breakdown by points descending (for display).
func SortBreakdown(d *Dossier) {
	sort.Slice(d.Breakdown, func(i, j int) bool {
		return d.Breakdown[i].Points > d.Breakdown[j].Points
	})
}
