// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package basis

import (
	"testing"
	"time"
)

func TestEnrolmentRequiresConsent(t *testing.T) {
	d := Decide(Request{Purpose: PurposeEnrolment, Regime: RegimeGDPR, Category: CatGeneral})
	if d.Outcome != RequiresConsent {
		t.Fatalf("want requires_consent, got %s (%s)", d.Outcome, d.Reason)
	}
	d = Decide(Request{Purpose: PurposeEnrolment, Regime: RegimeGDPR, Category: CatGeneral, HasConsent: true})
	if !d.Allowed() {
		t.Fatalf("with consent should permit: %s", d.Reason)
	}
}

func TestTrainingRequiresConsent(t *testing.T) {
	d := Decide(Request{Purpose: PurposeTraining, HasConsent: true, Category: CatGeneral})
	if !d.Allowed() {
		t.Fatalf("training with consent: %s", d.Reason)
	}
	d = Decide(Request{Purpose: PurposeTraining, Category: CatGeneral})
	if d.Outcome != RequiresConsent {
		t.Fatalf("want requires_consent, got %s", d.Outcome)
	}
}

func TestUntargetedMassIDProhibited(t *testing.T) {
	d := Decide(Request{Purpose: PurposeUntargetedMassID, HasConsent: true, IsLawEnforcement: true, DPIAAcknowledged: true})
	if d.Outcome != Prohibited {
		t.Fatalf("untargeted mass ID must be prohibited, got %s", d.Outcome)
	}
	if d.RetentionMax != 0 {
		t.Fatal("prohibited ops must set retention 0")
	}
}

func TestRBRPublicWithoutLE(t *testing.T) {
	d := Decide(Request{Purpose: PurposeRBRPublic, HasConsent: true, DPIAAcknowledged: true})
	if d.Outcome != Prohibited {
		t.Fatalf("RBR public without LE: want prohibited, got %s", d.Outcome)
	}
}

func TestRBRPublicLENeedsDPIA(t *testing.T) {
	d := Decide(Request{Purpose: PurposeRBRPublic, IsLawEnforcement: true})
	if d.Outcome != RequiresDPIA {
		t.Fatalf("LE RBR without DPiA: want requires_dpia, got %s", d.Outcome)
	}
	d = Decide(Request{Purpose: PurposeRBRPublic, IsLawEnforcement: true, DPIAAcknowledged: true})
	if !d.Allowed() {
		t.Fatalf("LE + DPiA should permit: %s", d.Reason)
	}
}

func TestMinorRequiresDPIA(t *testing.T) {
	d := Decide(Request{Purpose: PurposeTargetedSearch, Category: CatMinor, HasConsent: true})
	if d.Outcome != RequiresDPIA {
		t.Fatalf("minor without DPiA: want requires_dpia, got %s", d.Outcome)
	}
	d = Decide(Request{
		Purpose: PurposeTargetedSearch, Category: CatMinor,
		HasConsent: true, DPIAAcknowledged: true,
	})
	if !d.Allowed() {
		t.Fatalf("minor + consent + DPiA should permit: %s", d.Reason)
	}
}

func TestRetentionClamp(t *testing.T) {
	d := Decide(Request{
		Purpose: PurposeEnrolment, HasConsent: true,
		Category: CatGeneral, RetentionDays: 365,
	})
	if d.RetentionMax != 90 {
		t.Fatalf("general max retention 90, got %d", d.RetentionMax)
	}
	d = Decide(Request{
		Purpose: PurposeEnrolment, HasConsent: true, DPIAAcknowledged: true,
		Category: CatMinor, RetentionDays: 365,
	})
	if d.RetentionMax != 7 {
		t.Fatalf("minor max retention 7, got %d", d.RetentionMax)
	}
	d = Decide(Request{
		Purpose: PurposeEnrolment, HasConsent: true,
		Category: CatGeneral, RetentionDays: 0,
	})
	if d.RetentionMax != 0 {
		t.Fatalf("requested 0 must stay 0, got %d", d.RetentionMax)
	}
}

func TestCrossAgencyNeedsBoth(t *testing.T) {
	d := Decide(Request{Purpose: PurposeCrossAgencyShare, HasConsent: true})
	if d.Outcome != RequiresDPIA {
		t.Fatalf("cross-agency with consent only: want requires_dpia, got %s", d.Outcome)
	}
	d = Decide(Request{Purpose: PurposeCrossAgencyShare, DPIAAcknowledged: true})
	if d.Outcome != RequiresConsent {
		t.Fatalf("cross-agency with DPiA only: want requires_consent, got %s", d.Outcome)
	}
	d = Decide(Request{Purpose: PurposeCrossAgencyShare, HasConsent: true, DPIAAcknowledged: true})
	if !d.Allowed() {
		t.Fatalf("both should permit: %s", d.Reason)
	}
}

func TestClientProtectionAlias(t *testing.T) {
	d := Decide(Request{Purpose: PurposeClientProtection, HasConsent: true, Category: CatGeneral})
	if d.Purpose != PurposeTargetedSearch {
		t.Fatalf("alias should normalize to targeted_search, got %s", d.Purpose)
	}
	if !d.Allowed() {
		t.Fatalf("should permit: %s", d.Reason)
	}
}

func TestDecisionTimestamp(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	d := Decide(Request{Purpose: PurposeEnrolment, HasConsent: true})
	if d.DecidedAt.Before(before) {
		t.Fatal("DecidedAt not set")
	}
}

func TestCatalogsNonEmpty(t *testing.T) {
	if len(Purposes()) == 0 || len(Regimes()) == 0 || len(Categories()) == 0 {
		t.Fatal("catalogs must be non-empty")
	}
}
