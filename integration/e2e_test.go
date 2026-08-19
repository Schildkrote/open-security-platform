// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Schildkrote/actions"
	"github.com/Schildkrote/aip"
	"github.com/Schildkrote/connector-alpr"
	obpconnector "github.com/Schildkrote/connector-obp"
	ospconnector "github.com/Schildkrote/connector-osp"
	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/odp-events"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/packs"
	"github.com/Schildkrote/policy"
)

func packsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "packs")
}

// End-to-end: OSP findings + OBP hits + ALPR hotlist → ontology → case action.
func TestE2EConnectorsAndAction(t *testing.T) {
	s := ontology.NewStore()
	log := audit.New()
	eng := actions.NewEngine(s, log)

	for _, f := range ospconnector.MockFindings() {
		if _, err := ospconnector.Ingest(s, f); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range obpconnector.MockHits() {
		if _, err := obpconnector.Ingest(s, h); err != nil {
			t.Fatal(err)
		}
	}
	hot := alpr.NewHotlist([]alpr.HotlistEntry{
		{Plate: "ABC123", Reason: "stolen", Source: "NCIC-mock", CaseID: "case1", Priority: 1},
	})
	ing := &alpr.Ingestor{Store: s, Log: log, Hotlist: hot}
	ctx := alpr.IngestContext{Actor: "unit", Role: policy.RoleOfficer, Purpose: policy.PurposePatrolAlert}
	var alertID string
	for _, ev := range alpr.MockStream() {
		r := ing.Ingest(ctx, ev)
		if r.Error != "" {
			t.Fatal(r.Error)
		}
		if r.AlertID != "" {
			alertID = r.AlertID
		}
	}
	if alertID == "" {
		t.Fatal("expected hotlist alert")
	}

	admin := actions.Context{Actor: "admin", Role: policy.RoleAdmin, Purpose: policy.PurposeAdmin}
	cr := eng.OpenCase(admin, "case1", "Stolen ABC123")
	if !cr.OK {
		t.Fatalf("case: %+v", cr)
	}
	reads := s.QueryObjects(ontology.Query{Type: ontology.TypePlateRead, PropertyEq: map[string]any{"plate": "ABC123"}})
	if len(reads) == 0 {
		t.Fatal("no reads")
	}
	off := actions.Context{
		Actor: "off1", Role: policy.RoleOfficer, Purpose: policy.PurposeInvestigation,
		HasCase: true, CaseID: cr.ObjectID,
	}
	lr := eng.LinkEvidence(off, reads[0].ID, cr.ObjectID)
	if !lr.OK {
		t.Fatalf("link: %+v", lr)
	}

	_, _, err := ing.QueryHistorical(alpr.IngestContext{Actor: "off1", Role: policy.RoleOfficer}, "ABC123")
	if err == nil {
		t.Fatal("historical should require warrant")
	}
	hist, _, err := ing.QueryHistorical(alpr.IngestContext{
		Actor: "off1", Role: policy.RoleOfficer, HasWarrant: true, WarrantID: "W-9",
		HasCase: true, CaseID: cr.ObjectID,
	}, "ABC123")
	if err != nil || len(hist) < 1 {
		t.Fatalf("hist: %v n=%d", err, len(hist))
	}

	if _, ok := s.Get("person:2bd806c97f0e"); !ok {
		t.Fatal("obp person")
	}
	objs, links := s.Expand("vehicle:ABC123", 2)
	if len(objs) < 2 || len(links) < 1 {
		t.Fatalf("expand vehicle: o=%d l=%d", len(objs), len(links))
	}

	if err := log.Verify(); err != nil {
		t.Fatal(err)
	}
	_ = time.Now()
	if len(s.QueryObjects(ontology.Query{})) < 8 {
		t.Fatalf("expected rich graph, got %d objects", len(s.QueryObjects(ontology.Query{})))
	}
}

func TestE2EWebhookPacksContextBundle(t *testing.T) {
	s := ontology.NewStore()
	log := audit.New()

	// 1) OSP webhook spine
	h := events.NewHandler(s, log)
	ev := events.BuildEvent(events.Genesis, "finding.created", "offensive/username-enum", "add_finding", "carol", map[string]any{
		"summary": "carol username hit", "severity": "low",
	})
	res, err := h.Ingest(ev)
	if err != nil || res.ObjectID == "" {
		t.Fatalf("webhook ingest: %+v %v", res, err)
	}
	if _, ok := s.Get("person:carol"); !ok {
		t.Fatal("carol missing")
	}

	// 2) Jurisdiction packs
	dir := packsDir(t)
	loaded, err := packs.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) < 2 {
		t.Fatalf("expected packs, got %d", len(loaded))
	}
	eng := packs.NewEngine(loaded...)
	d := eng.Evaluate(policy.Request{
		Purpose: policy.PurposePatternOfLife, Role: policy.RoleOfficer,
		ObjectType: "PlateRead", Action: "query_historical",
	})
	if d.Allowed || d.Outcome != policy.RequireWarrant {
		t.Fatalf("us-4a pack: %+v", d)
	}
	d = eng.Evaluate(policy.Request{
		Purpose: policy.PurposeResearch, Role: policy.RoleAnalyst,
		ObjectType: "BiometricHit", Classification: "restricted",
	})
	if d.Allowed {
		t.Fatalf("gdpr pack should deny research biometric: %+v", d)
	}

	// 3) ContextBundle
	_, _ = s.UpsertObject(ontology.Object{
		ID: "person:carol", Type: ontology.TypePerson,
		Properties: map[string]any{"label": "carol", "embedding": "RAW", "token": "x"},
	})
	b, err := aip.Export(s, aip.ExportOptions{
		RootID: "person:carol", Depth: 1,
		Purpose: policy.PurposeClientProtect, Role: policy.RoleAgent,
		IncludeHints: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Objects) < 1 {
		t.Fatal("bundle empty")
	}
	for _, o := range b.Objects {
		if _, ok := o.Properties["embedding"]; ok {
			t.Fatal("embedding leaked")
		}
	}
}
