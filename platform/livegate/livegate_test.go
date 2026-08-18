// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package livegate

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		want    []string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"single", "active-scanning", []string{"active-scanning"}, false},
		{"all", strings.Join(AllFeatures, ","), AllFeatures, false},
		{"whitespace", " people-search , active-scanning ", []string{"people-search", "active-scanning"}, false},
		{"dupes", "active-scanning,active-scanning", []string{"active-scanning"}, false},
		{"unknown", "nmap-everything", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.spec)
			if c.wantErr != (err != nil) {
				t.Fatalf("Parse(%q) err=%v, wantErr=%v", c.spec, err, c.wantErr)
			}
			if !c.wantErr && len(got) != len(c.want) {
				t.Fatalf("Parse(%q) = %v, want %v", c.spec, got, c.want)
			}
		})
	}
}

func TestEnabledAndValid(t *testing.T) {
	enabled := []string{FeatureActiveScanning, FeaturePeopleSearch}
	if !Enabled(enabled, FeatureActiveScanning) {
		t.Fatal("active-scanning should be enabled")
	}
	if Enabled(enabled, FeatureRecoveryProbing) {
		t.Fatal("recovery-probing should be disabled")
	}
	for _, f := range AllFeatures {
		if !Valid(f) {
			t.Fatalf("feature %q should be valid", f)
		}
	}
	if Valid("bogus") {
		t.Fatal("bogus should not be valid")
	}
}

func TestExceptionsComplete(t *testing.T) {
	if len(Exceptions) != len(AllFeatures) {
		t.Fatalf("Exceptions has %d entries, want %d", len(Exceptions), len(AllFeatures))
	}
	for _, f := range AllFeatures {
		e, ok := Exceptions[f]
		if !ok {
			t.Fatalf("missing exception for %q", f)
		}
		if e.Feature != f || e.Summary == "" || e.Conditions == "" || !strings.Contains(e.Flag, f) {
			t.Fatalf("exception for %q is incomplete: %+v", f, e)
		}
	}
}

func TestSummaryMentionsGateState(t *testing.T) {
	s := Summary([]string{FeaturePeopleSearch})
	for _, f := range AllFeatures {
		if !strings.Contains(s, f) {
			t.Fatalf("summary missing feature %q:\n%s", f, s)
		}
	}
	if !strings.Contains(s, "ON") {
		t.Fatalf("summary should mark the enabled feature ON:\n%s", s)
	}
}
