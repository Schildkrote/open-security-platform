// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package packs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Schildkrote/policy"
)

func writePack(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUS4AALPRPack(t *testing.T) {
	dir := t.TempDir()
	// use real pack from repo if present
	repoPack := filepath.Join("..", "..", "packs", "us-4a-alpr.json")
	var p *Pack
	var err error
	if _, err2 := os.Stat(repoPack); err2 == nil {
		p, err = Load(repoPack)
	} else {
		path := writePack(t, dir, "us.json", `{
		  "id": "us-4a-alpr",
		  "name": "US Fourth Amendment ALPR",
		  "rules": [{
		    "id": "historical-warrant",
		    "purposes": ["pattern_of_life"],
		    "object_types": ["PlateRead"],
		    "actions": ["query_historical", "read"],
		    "require_warrant": true,
		    "on_fail_outcome": "require_warrant",
		    "on_fail_reason": "long-term ALPR location DB treated as search (Norfolk-style)",
		    "allow_if_ok": true
		  }]
		}`)
		p, err = Load(path)
	}
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(p)
	d := eng.Evaluate(policy.Request{
		Purpose: policy.PurposePatternOfLife, Role: policy.RoleOfficer,
		ObjectType: "PlateRead", Action: "query_historical",
	})
	if d.Allowed || d.Outcome != policy.RequireWarrant {
		t.Fatalf("%+v", d)
	}
	d = eng.Evaluate(policy.Request{
		Purpose: policy.PurposePatternOfLife, Role: policy.RoleOfficer,
		ObjectType: "PlateRead", Action: "query_historical",
		HasWarrant: true, WarrantID: "W1",
	})
	if !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestGDPRBiometricPack(t *testing.T) {
	dir := t.TempDir()
	path := writePack(t, dir, "gdpr.json", `{
	  "id": "gdpr-biometric",
	  "name": "GDPR Art.9 biometric",
	  "rules": [{
	    "id": "no-untargeted",
	    "object_types": ["BiometricHit"],
	    "purposes": ["research"],
	    "force_deny": true,
	    "deny_reason": "special category biometrics not for open research purpose"
	  },{
	    "id": "client-protect-ok",
	    "purposes": ["client_protection"],
	    "object_types": ["BiometricHit"],
	    "roles": ["client_app", "analyst", "admin", "agent"],
	    "allow_if_ok": true
	  }]
	}`)
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(p)
	d := eng.Evaluate(policy.Request{
		Purpose: policy.PurposeResearch, Role: policy.RoleAnalyst,
		ObjectType: "BiometricHit", Classification: "restricted",
	})
	if d.Allowed {
		t.Fatalf("want deny research biometric: %+v", d)
	}
	d = eng.Evaluate(policy.Request{
		Purpose: policy.PurposeClientProtect, Role: policy.RoleClientApp,
		ObjectType: "BiometricHit",
	})
	if !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "a.json", `{"id":"a","name":"A","rules":[]}`)
	writePack(t, dir, "b.json", `{"id":"b","name":"B","rules":[]}`)
	ps, err := LoadDir(dir)
	if err != nil || len(ps) != 2 {
		t.Fatalf("%v n=%d", err, len(ps))
	}
}
