// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"

	"github.com/Schildkrote/lawful-basis"
)

func TestChainAppendAndVerify(t *testing.T) {
	s := NewMemory()
	d := basis.Decide(basis.Request{
		Purpose: basis.PurposeEnrolment, HasConsent: true, Category: basis.CatGeneral,
	})
	e1, err := Record(s, "test", "enrol", Pseudo("alice"), "ok", d, true)
	if err != nil {
		t.Fatal(err)
	}
	if e1.Seq != 1 || e1.Hash == "" || e1.PrevHash != "" {
		t.Fatalf("bad first entry: %+v", e1)
	}
	e2, err := Record(s, "test", "train", Pseudo("alice"), "ok", d, true)
	if err != nil {
		t.Fatal(err)
	}
	if e2.Seq != 2 || e2.PrevHash != e1.Hash {
		t.Fatalf("bad second entry: %+v", e2)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d", s.Len())
	}
}

func TestTamperDetected(t *testing.T) {
	s := NewMemory()
	d := basis.Decide(basis.Request{Purpose: basis.PurposeEnrolment, HasConsent: true})
	_, _ = Record(s, "test", "enrol", Pseudo("bob"), "", d, true)
	_, _ = Record(s, "test", "train", Pseudo("bob"), "", d, true)
	// Tamper with the stored entry.
	s.mu.Lock()
	s.entries[0].Detail = "tampered"
	s.mu.Unlock()
	if err := s.Verify(); err == nil {
		t.Fatal("tamper should be detected")
	}
}

func TestPseudoStable(t *testing.T) {
	a := Pseudo("alice")
	b := Pseudo("alice")
	c := Pseudo("carol")
	if a != b || a == c || len(a) != 64 {
		t.Fatalf("Pseudo unstable or wrong length: %s / %s / %s", a, b, c)
	}
}

func TestRetentionFilled(t *testing.T) {
	s := NewMemory()
	d := basis.Decide(basis.Request{
		Purpose: basis.PurposeEnrolment, HasConsent: true,
		Category: basis.CatGeneral, RetentionDays: 30,
	})
	e, _ := Record(s, "test", "enrol", Pseudo("x"), "", d, true)
	if e.RetentionExp.IsZero() {
		t.Fatal("RetentionExp should be set from basis.RetentionMax")
	}
}
