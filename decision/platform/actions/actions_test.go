// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/policy"
)

func TestOpenCaseAndAlert(t *testing.T) {
	s := ontology.NewStore()
	e := NewEngine(s, audit.New())
	ctx := Context{Actor: "off1", Role: policy.RoleOfficer, Purpose: policy.PurposePatrolAlert}
	// open_case under patrol may deny — use investigation+case path for case open via admin
	admin := Context{Actor: "admin", Role: policy.RoleAdmin, Purpose: policy.PurposeAdmin}
	r := e.OpenCase(admin, "c1", "Stolen vehicle ring")
	if !r.OK {
		t.Fatalf("open case: %+v", r)
	}
	_, _ = s.UpsertObject(ontology.Object{ID: "vehicle:1", Type: ontology.TypeVehicle})
	r = e.IssueAlert(ctx, "a1", "vehicle:1", "hotlist hit")
	if !r.OK {
		t.Fatalf("alert: %+v", r)
	}
	if err := e.Log.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestWarrantPackageNeedsCase(t *testing.T) {
	s := ontology.NewStore()
	e := NewEngine(s, audit.New())
	ctx := Context{Actor: "a", Role: policy.RoleAnalyst, Purpose: policy.PurposeInvestigation}
	r := e.RequestWarrantPackage(ctx, "wdoc1", "case:missing", "need historical ALPR")
	if r.OK {
		t.Fatal("want fail")
	}
	admin := Context{Actor: "admin", Role: policy.RoleAdmin, Purpose: policy.PurposeAdmin}
	cr := e.OpenCase(admin, "c2", "test")
	ctx.HasCase = true
	ctx.CaseID = cr.ObjectID
	r = e.RequestWarrantPackage(ctx, "wdoc1", cr.ObjectID, "need historical ALPR")
	if !r.OK {
		t.Fatalf("%+v", r)
	}
}
