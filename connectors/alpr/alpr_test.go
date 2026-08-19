// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package alpr

import (
	"testing"

	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/policy"
)

func TestLiveHotlist(t *testing.T) {
	s := ontology.NewStore()
	h := NewHotlist([]HotlistEntry{{Plate: "ABC123", Reason: "stolen", Source: "local", Priority: 1}})
	in := &Ingestor{Store: s, Log: audit.New(), Hotlist: h}
	ctx := IngestContext{Actor: "off1", Role: policy.RoleOfficer, Purpose: policy.PurposePatrolAlert}
	for _, ev := range MockStream() {
		r := in.Ingest(ctx, ev)
		if r.Error != "" {
			t.Fatalf("%+v", r)
		}
		if ev.Plate == "ABC123" && !r.HotHit {
			t.Fatal("expected hot hit")
		}
	}
}

func TestHistoricalNeedsWarrant(t *testing.T) {
	s := ontology.NewStore()
	in := &Ingestor{Store: s, Log: audit.New(), Hotlist: NewHotlist(nil)}
	ctx := IngestContext{Actor: "off1", Role: policy.RoleOfficer, Purpose: policy.PurposePatrolAlert}
	_ = in.Ingest(ctx, MockStream()[0])
	_, d, err := in.QueryHistorical(IngestContext{Actor: "off1", Role: policy.RoleOfficer}, "ABC123")
	if err == nil || d.Outcome != policy.RequireWarrant {
		t.Fatalf("want warrant gate: %v %+v", err, d)
	}
	out, d, err := in.QueryHistorical(IngestContext{
		Actor: "off1", Role: policy.RoleOfficer, HasWarrant: true, WarrantID: "W1",
	}, "ABC123")
	if err != nil || !d.Allowed || len(out) != 1 {
		t.Fatalf("hist: %v %+v n=%d", err, d, len(out))
	}
}
