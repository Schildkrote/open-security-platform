// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package rbr

import (
	"testing"

	"github.com/Schildkrote/biometric-audit"
	"github.com/Schildkrote/lawful-basis"
)

func TestAuditChainOnEnrolMatchRevoke(t *testing.T) {
	store := audit.NewMemory()
	g := NewGallery(nil)
	g.SetAudit(store)

	d := basis.Decide(basis.Request{Purpose: basis.PurposeEnrolment, HasConsent: true, Category: basis.CatGeneral})
	if err := g.Enrol(FaceRecord{ID: "g1", ClientID: "alice", ImageHash: "hash-alice-1"}, d); err != nil {
		t.Fatal(err)
	}

	res := g.MatchProbe(FaceRecord{ID: "p1", ImageHash: "hash-alice-1"}, 0.5, true, basis.CatGeneral)
	if res.Refused {
		t.Fatalf("match refused: %s", res.Reason)
	}

	// A refused match must also be audited.
	resRefused := g.MatchProbe(FaceRecord{ID: "p2", ImageHash: "hash-alice-1"}, 0.5, false, basis.CatGeneral)
	if !resRefused.Refused {
		t.Fatal("no-consent match must refuse")
	}

	g.Revoke("alice")

	if err := store.Verify(); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	all := store.All()
	if len(all) != 4 {
		t.Fatalf("want 4 audit entries (enrol, match, match_refused, revoke), got %d", len(all))
	}
	want := []string{"enrol", "match", "match_refused", "revoke"}
	for i, e := range all {
		if e.Action != want[i] {
			t.Errorf("entry %d: action %q, want %q", i+1, e.Action, want[i])
		}
		if e.Component != "rbr" {
			t.Errorf("entry %d: component %q", i+1, e.Component)
		}
		if e.Basis.Outcome == "" {
			t.Errorf("entry %d: empty basis outcome", i+1)
		}
	}
	// The enrol entry must carry the lawful-basis decision.
	if all[0].Basis.Outcome != basis.Permitted {
		t.Errorf("enrol entry basis: %s", all[0].Basis.Outcome)
	}
}

func TestAuditDisabledByDefault(t *testing.T) {
	g := NewGallery(nil)
	if err := g.Enrol(FaceRecord{ID: "g1", ClientID: "alice", ImageHash: "h"}, permittedD()); err != nil {
		t.Fatal(err)
	}
	g.MatchProbe(FaceRecord{ID: "p", ImageHash: "h"}, 0.5, true, basis.CatGeneral)
	g.Revoke("alice")
	// No panic, no entries — audit is opt-in.
	if g.Audit() != nil {
		t.Fatal("audit store should be nil when not set")
	}
}
