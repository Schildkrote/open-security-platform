// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

func TestChain(t *testing.T) {
	l := New()
	l.Append(Entry{Kind: "policy", Actor: "officer1", Purpose: "patrol_alert", Outcome: "allow"})
	l.Append(Entry{Kind: "action", Actor: "officer1", Action: "issue_alert", ObjectID: "alert:1", Outcome: "ok"})
	if err := l.Verify(); err != nil {
		t.Fatal(err)
	}
	if len(l.Entries()) != 2 {
		t.Fatal("len")
	}
	// tamper
	l.entries[1].Outcome = "tampered"
	if err := l.Verify(); err == nil {
		t.Fatal("want verify fail")
	}
}
