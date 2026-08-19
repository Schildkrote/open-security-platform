// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package policy

import "testing"

func TestClientProtection(t *testing.T) {
	d := Evaluate(Request{Purpose: PurposeClientProtect, Role: RoleClientApp, ObjectType: "BiometricHit"})
	if !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestALPRHistoricalNeedsWarrant(t *testing.T) {
	d := Evaluate(Request{
		Purpose: PurposePatternOfLife, Role: RoleOfficer, ObjectType: "PlateRead", Action: "query_historical",
	})
	if d.Outcome != RequireWarrant {
		t.Fatalf("%+v", d)
	}
	d = Evaluate(Request{
		Purpose: PurposePatternOfLife, Role: RoleOfficer, ObjectType: "PlateRead",
		Action: "query_historical", HasWarrant: true, WarrantID: "W-1",
	})
	if !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestPatrolAlert(t *testing.T) {
	d := Evaluate(Request{Purpose: PurposePatrolAlert, Role: RoleOfficer, ObjectType: "PlateRead", Action: "read"})
	if !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestInvestigationNeedsCase(t *testing.T) {
	d := Evaluate(Request{Purpose: PurposeInvestigation, Role: RoleAnalyst, Classification: "restricted"})
	if d.Outcome != RequireCase {
		t.Fatalf("%+v", d)
	}
	d = Evaluate(Request{Purpose: PurposeInvestigation, Role: RoleAnalyst, Classification: "restricted", HasCase: true, CaseID: "C1"})
	if !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestDenyDefault(t *testing.T) {
	d := Evaluate(Request{Purpose: "nope", Role: RoleOfficer})
	if d.Allowed {
		t.Fatal("want deny")
	}
}
