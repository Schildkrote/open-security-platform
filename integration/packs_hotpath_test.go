// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package integration_test

// Proves jurisdiction packs are enforced on the hot paths (ALPR, actions,
// webhook), per AGENTS.md scaffold-honesty: "Wire packs.Engine before
// claiming pack enforcement everywhere."
//
// Each test asserts the PACK's outcome against a control that runs the same
// request on core policy alone — so the pack's effect, not the core's, is
// what's pinned.

import (
	"strings"
	"testing"

	"github.com/Schildkrote/actions"
	"github.com/Schildkrote/connector-alpr"
	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/odp-events"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/packs"
	"github.com/Schildkrote/policy"
)

func loadPacks(t *testing.T) *packs.Engine {
	t.Helper()
	loaded, err := packs.LoadDir(packsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) < 2 {
		t.Fatalf("expected packs, got %d", len(loaded))
	}
	return packs.NewEngine(loaded...)
}

func TestPacksHotPathALPR(t *testing.T) {
	s := ontology.NewStore()
	ing := &alpr.Ingestor{Store: s, Log: audit.New(), Eval: loadPacks(t)}

	// research + query_historical: core → RequireWarrant,
	// us-4a-alpr "no-civilian-mass-alpr" → force deny.
	_, d, err := ing.QueryHistorical(alpr.IngestContext{
		Actor: "analyst1", Role: policy.RoleAnalyst, Purpose: policy.PurposeResearch,
	}, "ABC123")
	if err == nil {
		t.Fatal("expected refusal")
	}
	if d.Outcome != policy.Deny {
		t.Fatalf("pack should force-deny research ALPR, got %s (%s)", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "us-4a-alpr") && !strings.Contains(d.Reason, "not available outside LE") {
		t.Fatalf("reason should be the pack's, got: %s", d.Reason)
	}

	// Control: same request on core policy → only RequireWarrant.
	core := &alpr.Ingestor{Store: s, Log: audit.New()}
	_, dCore, _ := core.QueryHistorical(alpr.IngestContext{
		Actor: "analyst1", Role: policy.RoleAnalyst, Purpose: policy.PurposeResearch,
	}, "ABC123")
	if dCore.Outcome != policy.RequireWarrant {
		t.Fatalf("core should be RequireWarrant, got %s", dCore.Outcome)
	}

	// Live patrol_alert: unaffected by packs.
	r := ing.Ingest(alpr.IngestContext{Actor: "off1", Role: policy.RoleOfficer, Purpose: policy.PurposePatrolAlert},
		alpr.PlateEvent{EventID: "pe1", Plate: "abc123", CameraID: "cam-north"})
	if r.Error != "" {
		t.Fatalf("patrol ingest failed: %s", r.Error)
	}
}

func TestPacksHotPathActions(t *testing.T) {
	pk := &packs.Pack{
		ID: "test-pack",
		Rules: []packs.Rule{{
			ID: "open-case-needs-case", Purposes: []string{"investigation"},
			Actions: []string{"action:open_case"}, RequireCase: true,
			OnFailOutcome: "require_case",
			OnFailReason:  "test pack: open_case needs a case",
		}},
	}
	s := ontology.NewStore()
	eng := actions.NewEngine(s, audit.New())
	eng.Eval = packs.NewEngine(pk)

	ctx := actions.Context{Actor: "a1", Role: policy.RoleAdmin, Purpose: policy.PurposeInvestigation}
	r := eng.OpenCase(ctx, "c1", "test")
	if r.OK || r.Policy.Outcome != policy.RequireCase {
		t.Fatalf("want require_case, got ok=%v %s (%s)", r.OK, r.Policy.Outcome, r.Policy.Reason)
	}
	if !strings.Contains(r.Policy.Reason, "test pack") {
		t.Fatalf("reason should be the pack's, got: %s", r.Policy.Reason)
	}

	ctx.HasCase, ctx.CaseID = true, "case:pre"
	if r = eng.OpenCase(ctx, "c1", "test"); !r.OK {
		t.Fatalf("open_case with case should pass: %s", r.Reason)
	}

	// Control: core allows admin investigation open_case without a case.
	coreEng := actions.NewEngine(ontology.NewStore(), audit.New())
	if rc := coreEng.OpenCase(actions.Context{Actor: "a1", Role: policy.RoleAdmin, Purpose: policy.PurposeInvestigation}, "c1", "test"); !rc.OK {
		t.Fatalf("core should allow: %s", rc.Reason)
	}
}

func TestPacksHotPathWebhook(t *testing.T) {
	// investigation/admin + biometric hit, no case:
	// core policy → allow (admin investigation);
	// eu-ai-act-rbi "post-remote-investigation" (roles incl. admin,
	// require_case) → RequireCase. Pack changes the outcome.
	newHandler := func(eval *packs.Engine) *events.Handler {
		h := events.NewHandler(ontology.NewStore(), audit.New())
		if eval != nil { // avoid typed-nil interface
			h.Eval = eval
		}
		h.Pol = events.PolicyContext{Purpose: policy.PurposeInvestigation, Role: policy.RoleAdmin}
		return h
	}
	ev := events.BuildEvent(events.Genesis, "biometric.match", "obp", "match_hit", "2bd806c97f0e",
		map[string]any{"summary": "obp match", "severity": "medium"})

	// Control: core policy allows the same webhook event.
	if _, err := newHandler(nil).Ingest(ev); err != nil {
		t.Fatalf("core should allow admin investigation biometric webhook: %v", err)
	}

	// With packs: gated by the EU AI Act pack.
	h := newHandler(loadPacks(t))
	if _, err := h.Ingest(ev); err == nil {
		t.Fatal("packs should require case context for investigation biometric webhook")
	}

	// Non-biometric finding with the same pack engine: unaffected.
	h2 := events.NewHandler(ontology.NewStore(), audit.New())
	h2.Eval = loadPacks(t)
	h2.Pol = events.PolicyContext{Purpose: policy.PurposeInvestigation, Role: policy.RoleAdmin}
	ev2 := events.BuildEvent(events.Genesis, "finding.created", "offensive/username-enum", "add_finding", "carol",
		map[string]any{"summary": "carol username hit", "severity": "low"})
	if _, err := h2.Ingest(ev2); err != nil {
		t.Fatalf("finding webhook should pass: %v", err)
	}
}
