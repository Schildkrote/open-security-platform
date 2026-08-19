// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package basis

import (
	"encoding/json"
	"os"
	"testing"
)

// matrix.json is the single source of truth for lawful-basis decisions.
// This test interprets it and checks that Decide() conforms. Editing the
// matrix without updating Decide (or vice versa) fails the build.

type matrixCategory struct {
	Special bool `json:"special"`
}

type matrixPurpose struct {
	Rule          string   `json:"rule"`
	RetentionDays int      `json:"retention_days"`
	Aliases       []string `json:"aliases"`
}

type matrixFile struct {
	Version          int                       `json:"version"`
	DefaultRegime    string                    `json:"default_regime"`
	DefaultCategory  string                    `json:"default_category"`
	RetentionMaxDays map[string]int            `json:"retention_max_days"`
	Categories       map[string]matrixCategory `json:"categories"`
	Purposes         map[string]matrixPurpose  `json:"purposes"`
}

func loadMatrix(t *testing.T) matrixFile {
	t.Helper()
	b, err := os.ReadFile("matrix.json") // tests run in package dir
	if err != nil {
		t.Fatalf("read matrix.json: %v", err)
	}
	var m matrixFile
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse matrix.json: %v", err)
	}
	return m
}

// interpret implements the canonical decision procedure over the matrix
// (see the $comment order in matrix.json).
//
// Pinned retention semantics: RetentionMax = clamp(requested, cap); requested
// <= 0 stays 0 (caller's choice); prohibited -> 0.
func (m matrixFile) interpret(t *testing.T, req Request) (outcome Outcome, retention int) {
	purpose := req.Purpose
	if purpose == PurposeClientProtection {
		purpose = PurposeTargetedSearch
	}
	cat := req.Category
	if cat == "" {
		cat = m.DefaultCategory
	}
	maxDays, _ := m.RetentionMaxDays["general"]
	if m.Categories[cat].Special {
		maxDays, _ = m.RetentionMaxDays["special"]
	}
	// Step 2: resolve aliases; unknown purpose -> prohibited.
	p, known := m.Purposes[purpose]
	if !known {
		for _, mp := range m.Purposes {
			for _, a := range mp.Aliases {
				if a == purpose {
					p = mp
					known = true
				}
			}
		}
	}
	if !known {
		return Prohibited, 0
	}
	retention = 0
	if req.RetentionDays > 0 {
		if req.RetentionDays > maxDays {
			retention = maxDays
		} else {
			retention = req.RetentionDays
		}
	}
	special := m.Categories[cat].Special

	// Step 3: hard prohibitions.
	if purpose == PurposeUntargetedMassID {
		return Prohibited, 0
	}
	if purpose == PurposeRBRPublic && !req.IsLawEnforcement {
		return Prohibited, 0
	}
	// Step 4: LE RBR without DPiA.
	if purpose == PurposeRBRPublic && !req.DPIAAcknowledged {
		return RequiresDPIA, retention
	}
	// Step 5: special category without DPiA.
	if special && !req.DPIAAcknowledged {
		return RequiresDPIA, retention
	}
	// Step 6: special category without consent (non-LE).
	if special && !req.HasConsent && purpose != PurposeRBRPublic {
		return RequiresConsent, retention
	}
	// Step 7: purpose rule.
	switch p.Rule {
	case "prohibited":
		return Prohibited, 0
	case "le+dpia":
		return Permitted, retention // steps 3-4 already gated it
	case "consent":
		if !req.HasConsent {
			return RequiresConsent, retention
		}
		return Permitted, retention
	case "consent+dpia":
		if !req.HasConsent {
			return RequiresConsent, retention
		}
		if !req.DPIAAcknowledged {
			return RequiresDPIA, retention
		}
		return Permitted, retention
	default:
		t.Fatalf("matrix: unknown rule %q", p.Rule)
	}
	t.Fatal("unreachable")
	return Prohibited, 0
}

// Name is set after alias resolution.

func TestDecideConformsToMatrix(t *testing.T) {
	m := loadMatrix(t)

	categories := []string{"", "general", "public_figure", "employee", "minor", "health_context", "religion_context"}
	purposes := []string{}
	for name, p := range m.Purposes {
		purposes = append(purposes, name)
		purposes = append(purposes, p.Aliases...)
	}
	purposes = append(purposes, "not_a_real_purpose")

	conflags := []struct {
		consent bool
		dpia    bool
		le      bool
		retain  int
	}{
		{false, false, false, 0},
		{false, false, false, 30},
		{true, false, false, 30},
		{true, true, false, 30},
		{false, true, true, 30},
		{true, true, true, 30},
		{true, false, false, 120}, // retention clamp check
	}

	for _, cat := range categories {
		for _, purpose := range purposes {
			for _, f := range conflags {
				req := Request{
					Purpose:          purpose,
					Category:         cat,
					HasConsent:       f.consent,
					DPIAAcknowledged: f.dpia,
					IsLawEnforcement: f.le,
					RetentionDays:    f.retain,
					Regime:           "gdpr",
				}
				got := Decide(req)
				wantOut, wantRet := m.interpret(t, req)
				if got.Outcome != wantOut {
					t.Errorf("purpose=%q cat=%q consent=%v dpia=%v le=%v: outcome %s, matrix wants %s (reason: %s)",
						purpose, cat, f.consent, f.dpia, f.le, got.Outcome, wantOut, got.Reason)
				}
				if f.retain > 0 && got.RetentionMax != wantRet {
					t.Errorf("purpose=%q cat=%q consent=%v dpia=%v le=%v: retention %d, matrix wants %d",
						purpose, cat, f.consent, f.dpia, f.le, got.RetentionMax, wantRet)
				}
			}
		}
	}

	// Invariant: requesting the matrix's standard retention for a purpose
	// must be honoured for general categories (it is the documented request
	// callers pass), so the standard value is meaningful, not decorative.
	for name, p := range m.Purposes {
		d := Decide(Request{
			Purpose:          name,
			Regime:           RegimeGDPR,
			Category:         CatGeneral,
			HasConsent:       true,
			DPIAAcknowledged: true,
			IsLawEnforcement: true,
			RetentionDays:    p.RetentionDays,
		})
		if d.RetentionMax != p.RetentionDays {
			t.Errorf("matrix: requesting %s standard retention %d returns %d", name, p.RetentionDays, d.RetentionMax)
		}
	}
}

// TestMatrixKnownOutcomes pins a few business-critical decisions by name so
// a regression is obvious in the failure message.
func TestMatrixKnownOutcomes(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		want Outcome
	}{
		{
			"untargeted mass ID always prohibited",
			Request{Purpose: PurposeUntargetedMassID, HasConsent: true},
			Prohibited,
		},
		{
			"RBR public without LE prohibited",
			Request{Purpose: PurposeRBRPublic, HasConsent: true, DPIAAcknowledged: true},
			Prohibited,
		},
		{
			"RBR public LE without DPiA requires DPiA",
			Request{Purpose: PurposeRBRPublic, IsLawEnforcement: true},
			RequiresDPIA,
		},
		{
			"RBR public LE with DPiA permitted",
			Request{Purpose: PurposeRBRPublic, IsLawEnforcement: true, DPIAAcknowledged: true},
			Permitted,
		},
		{
			"enrolment without consent requires consent",
			Request{Purpose: PurposeEnrolment},
			RequiresConsent,
		},
		{
			"enrolment with consent permitted",
			Request{Purpose: PurposeEnrolment, HasConsent: true},
			Permitted,
		},
		{
			"minor without DPiA requires DPiA even with consent",
			Request{Purpose: PurposeEnrolment, Category: CatMinor, HasConsent: true},
			RequiresDPIA,
		},
		{
			"minor with DPiA+consent permitted",
			Request{Purpose: PurposeEnrolment, Category: CatMinor, HasConsent: true, DPIAAcknowledged: true},
			Permitted,
		},
		{
			"cross-agency share needs consent and DPiA",
			Request{Purpose: PurposeCrossAgencyShare, HasConsent: true},
			RequiresDPIA,
		},
		{
			"unknown purpose prohibited",
			Request{Purpose: "vibes"},
			Prohibited,
		},
	}
	for _, c := range cases {
		if got := Decide(c.req); got.Outcome != c.want {
			t.Errorf("%s: got %s want %s", c.name, got.Outcome, c.want)
		}
	}
}
