// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package rbr

import (
	"math"
	"testing"

	"github.com/Schildkrote/lawful-basis"
)

// permittedD is a pre-approved lawful-basis decision for tests where the
// basis engine itself is not under test (the matrix is pinned in
// platform/lawful-basis tests).
func permittedD() basis.Decision {
	return basis.Decide(basis.Request{
		Purpose: basis.PurposeEnrolment, HasConsent: true, Category: basis.CatGeneral,
	})
}

func TestMockEmbedDeterministic(t *testing.T) {
	e := NewMockEmbedder()
	a, err := e.Embed("hash-alice-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := e.Embed("hash-alice-1")
	if Cosine(a, b) < 0.999 {
		t.Fatalf("same hash should be identical, cos=%f", Cosine(a, b))
	}
	c, _ := e.Embed("hash-bob-1")
	if Cosine(a, c) > 0.99 {
		t.Fatalf("different hashes should differ, cos=%f", Cosine(a, c))
	}
	// Unit length.
	var sum float64
	for _, x := range a {
		sum += x * x
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Fatalf("not unit length: %f", sum)
	}
}

func TestMatchRequiresConsent(t *testing.T) {
	g := NewGallery(nil)
	_ = g.Enrol(FaceRecord{ID: "g1", ClientID: "alice", ImageHash: "hash-alice-1"}, permittedD())
	res := g.MatchProbe(FaceRecord{ID: "p1", ImageHash: "hash-alice-1"}, 0.5, false, basis.CatGeneral)
	if !res.Refused {
		t.Fatal("match without consent must refuse")
	}
}

func TestMatchWithConsent(t *testing.T) {
	g := NewGallery(nil)
	_ = g.Enrol(FaceRecord{ID: "g1", ClientID: "alice", ImageHash: "hash-alice-1"}, permittedD())
	// Same hash → perfect match.
	res := g.MatchProbe(FaceRecord{ID: "p1", ImageHash: "hash-alice-1"}, 0.5, true, basis.CatGeneral)
	if res.Refused {
		t.Fatalf("refused: %s", res.Reason)
	}
	if len(res.Matches) != 1 || res.Matches[0].ClientID != "alice" {
		t.Fatalf("matches = %+v", res.Matches)
	}
	if res.Matches[0].Score < 0.99 {
		t.Fatalf("score = %f", res.Matches[0].Score)
	}
}

func TestThresholdFilters(t *testing.T) {
	g := NewGallery(nil)
	_ = g.Enrol(FaceRecord{ID: "g1", ClientID: "alice", ImageHash: "hash-alice-1"}, permittedD())
	res := g.MatchProbe(FaceRecord{ID: "p1", ImageHash: "hash-totally-other"}, 0.99, true, basis.CatGeneral)
	if res.Refused {
		t.Fatalf("refused: %s", res.Reason)
	}
	if len(res.Matches) != 0 {
		t.Fatalf("expected no hits above 0.99, got %+v", res.Matches)
	}
}

func TestRevoke(t *testing.T) {
	g := NewGallery(nil)
	_ = g.Enrol(FaceRecord{ID: "g1", ClientID: "alice", ImageHash: "h1"}, permittedD())
	_ = g.Enrol(FaceRecord{ID: "g2", ClientID: "bob", ImageHash: "h2"}, permittedD())
	n := g.Revoke("alice")
	if n != 1 || len(g.Records) != 1 || g.Records[0].ClientID != "bob" {
		t.Fatalf("revoke failed: n=%d records=%+v", n, g.Records)
	}
}

func TestStream(t *testing.T) {
	g := NewGallery(nil)
	_ = g.Enrol(FaceRecord{ID: "g1", ClientID: "alice", ImageHash: "hash-alice-1"}, permittedD())
	events := []StreamEvent{
		{FrameID: "f1", ImageHash: "hash-alice-1"},
		{FrameID: "f2", ImageHash: "hash-other"},
	}
	out := g.Stream(events, 0.5, true)
	if len(out) != 2 {
		t.Fatalf("len=%d", len(out))
	}
	if len(out[0].Matches) != 1 {
		t.Fatalf("frame1 matches=%+v", out[0].Matches)
	}
}

func TestMinorNeedsDPIA(t *testing.T) {
	g := NewGallery(nil)
	_ = g.Enrol(FaceRecord{ID: "g1", ClientID: "kid", ImageHash: "h", Category: basis.CatMinor}, permittedD())
	res := g.MatchProbe(FaceRecord{ID: "p", ImageHash: "h"}, 0.5, true, basis.CatMinor)
	if !res.Refused || res.Basis.Outcome != basis.RequiresDPIA {
		t.Fatalf("minor without DPiA should refuse with requires_dpia: %+v", res)
	}
}
