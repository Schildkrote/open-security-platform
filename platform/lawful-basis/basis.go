// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package basis is the lawful-basis decision engine.
//
// Given (purpose, legal regime, data-subject category, retention days) it
// returns one of: permitted | requires_consent | requires_dpia | prohibited.
// Every face-touching component must call Decide before the operation.
package basis

import (
	"fmt"
	"strings"
	"time"
)

// Outcome of a lawful-basis decision.
type Outcome string

const (
	Permitted       Outcome = "permitted"
	RequiresConsent Outcome = "requires_consent"
	RequiresDPIA    Outcome = "requires_dpia"
	Prohibited      Outcome = "prohibited"
)

// Purpose identifiers used across the platform.
const (
	PurposeEnrolment        = "enrolment"          // client enrols own images
	PurposeTraining         = "training"           // train/fine-tune on enrolled
	PurposeTargetedSearch   = "targeted_search"    // search for enrolled clients
	PurposeClientProtection = "client_protection"  // alias of targeted_search
	PurposeUntargetedMassID = "untargeted_mass_id" // mass ID of public — banned
	PurposeRBRPublic        = "rbr_public"         // RBRIS in public spaces
	PurposeGraphLink        = "graph_link"         // person-graph linking
	PurposeCrossAgencyShare = "cross_agency_share" // share match events
)

// Regime identifiers.
const (
	RegimeGDPR  = "gdpr"
	RegimeAIAct = "ai_act"
	RegimeBSR   = "bsr" // German BDSG / state police laws, simplified
	RegimeUS    = "us"  // US state biometric laws (BIPA-class), simplified
)

// Category from biometric-categorise.
const (
	CatPublicFigure    = "public_figure"
	CatEmployee        = "employee"
	CatMinor           = "minor"
	CatHealthContext   = "health_context"
	CatReligionContext = "religion_context"
	CatGeneral         = "general"
)

// Request is the input to Decide.
type Request struct {
	Purpose       string `json:"purpose"`
	Regime        string `json:"regime"`
	Category      string `json:"category"`
	RetentionDays int    `json:"retention_days"`
	// HasConsent is true when a valid, unrevoked client consent record exists
	// for this purpose and subject.
	HasConsent bool `json:"has_consent"`
	// DPIAAcknowledged is true when a DPiA has been filed and acknowledged
	// for this purpose.
	DPIAAcknowledged bool `json:"dpia_acknowledged"`
	// IsLawEnforcement is true when the operator is an LE authority acting
	// under a warrant / statutory basis (AI Act Art. 5 exception path).
	IsLawEnforcement bool `json:"is_law_enforcement"`
}

// Decision is the result of Decide.
type Decision struct {
	Outcome       Outcome   `json:"outcome"`
	Purpose       string    `json:"purpose"`
	Regime        string    `json:"regime"`
	Category      string    `json:"category"`
	Reason        string    `json:"reason"`
	RetentionMax  int       `json:"retention_max_days"` // 0 = no storage
	DecidedAt     time.Time `json:"decided_at"`
	RequiresAudit bool      `json:"requires_audit"`
}

// Allowed reports whether the operation may proceed under this decision.
func (d Decision) Allowed() bool {
	return d.Outcome == Permitted
}

// Decide applies the regime × purpose × category matrix.
func Decide(req Request) Decision {
	req = normalize(req)
	d := Decision{
		Purpose:       req.Purpose,
		Regime:        req.Regime,
		Category:      req.Category,
		DecidedAt:     time.Now().UTC(),
		RequiresAudit: true,
		RetentionMax:  clampRetention(req.RetentionDays, req.Category),
	}

	// Hard prohibitions first.
	if req.Purpose == PurposeUntargetedMassID {
		d.Outcome = Prohibited
		d.Reason = "untargeted mass biometric ID of the public is prohibited by product policy and AI Act Art. 5"
		d.RetentionMax = 0
		return d
	}
	if req.Purpose == PurposeRBRPublic && !req.IsLawEnforcement {
		d.Outcome = Prohibited
		d.Reason = "RBRIS in public spaces without LE statutory basis is prohibited (AI Act Art. 5)"
		d.RetentionMax = 0
		return d
	}
	if req.Purpose == PurposeRBRPublic && req.IsLawEnforcement && !req.DPIAAcknowledged {
		d.Outcome = RequiresDPIA
		d.Reason = "LE RBRIS requires an acknowledged DPiA"
		return d
	}

	// Unknown purposes are prohibited BEFORE special-category gates can
	// turn them into "needs DPiA" — the matrix's canonical order pins this
	// (see matrix.json $comment and matrix_test.go).
	if !knownPurpose(req.Purpose) {
		d.Outcome = Prohibited
		d.Reason = fmt.Sprintf("unknown or unsupported purpose %q", req.Purpose)
		d.RetentionMax = 0
		return d
	}

	// Special-category contexts always elevate.
	if isSpecial(req.Category) {
		if !req.DPIAAcknowledged {
			d.Outcome = RequiresDPIA
			d.Reason = fmt.Sprintf("category %q is special-category; DPiA required", req.Category)
			return d
		}
		if !req.HasConsent && req.Purpose != PurposeRBRPublic {
			d.Outcome = RequiresConsent
			d.Reason = fmt.Sprintf("category %q requires explicit consent even with DPiA (non-LE)", req.Category)
			return d
		}
	}

	// Core consent-gated purposes (the product path).
	switch req.Purpose {
	case PurposeEnrolment, PurposeTraining, PurposeTargetedSearch, PurposeClientProtection, PurposeGraphLink:
		if !req.HasConsent {
			d.Outcome = RequiresConsent
			d.Reason = fmt.Sprintf("purpose %q requires valid client consent", req.Purpose)
			return d
		}
		d.Outcome = Permitted
		d.Reason = fmt.Sprintf("client consent present for purpose %q under %s", req.Purpose, req.Regime)
		return d

	case PurposeCrossAgencyShare:
		if !req.HasConsent {
			d.Outcome = RequiresConsent
			d.Reason = "cross-agency share requires the originating client's consent covering share"
			return d
		}
		if !req.DPIAAcknowledged {
			d.Outcome = RequiresDPIA
			d.Reason = "cross-agency share requires DPiA"
			return d
		}
		d.Outcome = Permitted
		d.Reason = "consent + DPiA present for cross-agency share"
		return d

	case PurposeRBRPublic:
		// LE + DPiA already checked above.
		d.Outcome = Permitted
		d.Reason = "LE RBRIS with DPiA"
		return d

	default:
		// Unreachable: unknown purposes are rejected earlier (canonical
		// order). Kept for exhaustiveness.
		d.Outcome = Prohibited
		d.Reason = fmt.Sprintf("unknown or unsupported purpose %q", req.Purpose)
		d.RetentionMax = 0
		return d
	}
}

// knownPurpose reports whether p (already normalized) is a purpose the
// matrix defines.
func knownPurpose(p string) bool {
	switch p {
	case PurposeEnrolment, PurposeTraining, PurposeTargetedSearch,
		PurposeGraphLink, PurposeCrossAgencyShare, PurposeRBRPublic,
		PurposeUntargetedMassID:
		return true
	}
	return false
}

func normalize(r Request) Request {
	r.Purpose = strings.ToLower(strings.TrimSpace(r.Purpose))
	r.Regime = strings.ToLower(strings.TrimSpace(r.Regime))
	r.Category = strings.ToLower(strings.TrimSpace(r.Category))
	if r.Regime == "" {
		r.Regime = RegimeGDPR
	}
	if r.Category == "" {
		r.Category = CatGeneral
	}
	// Aliases.
	if r.Purpose == PurposeClientProtection {
		r.Purpose = PurposeTargetedSearch
	}
	if r.Purpose == "corpus_ingest" {
		r.Purpose = PurposeTraining
	}
	return r
}

func isSpecial(cat string) bool {
	switch cat {
	case CatMinor, CatHealthContext, CatReligionContext:
		return true
	}
	return false
}

// clampRetention applies category-differentiated max retention.
// Minors/health/religion: max 7 days. General/public_figure/employee: max 90.
// Requested 0 means "no storage" and is preserved.
func clampRetention(requested int, cat string) int {
	if requested <= 0 {
		return 0
	}
	max := 90
	if isSpecial(cat) {
		max = 7
	}
	if requested > max {
		return max
	}
	return requested
}

// Purposes returns the known purpose identifiers.
func Purposes() []string {
	return []string{
		PurposeEnrolment, PurposeTraining, PurposeTargetedSearch,
		PurposeClientProtection, PurposeUntargetedMassID, PurposeRBRPublic,
		PurposeGraphLink, PurposeCrossAgencyShare,
	}
}

// Regimes returns the known regime identifiers.
func Regimes() []string {
	return []string{RegimeGDPR, RegimeAIAct, RegimeBSR, RegimeUS}
}

// Categories returns the known category identifiers.
func Categories() []string {
	return []string{
		CatPublicFigure, CatEmployee, CatMinor,
		CatHealthContext, CatReligionContext, CatGeneral,
	}
}
