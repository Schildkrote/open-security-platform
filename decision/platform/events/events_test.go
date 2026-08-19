// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/ontology"
)

func TestIngestFindingEvent(t *testing.T) {
	s := ontology.NewStore()
	h := NewHandler(s, audit.New())
	ev := BuildEvent(Genesis, "finding.created", "offensive/username-enum", "add_finding", "alice", map[string]any{
		"summary":  "username alice on github",
		"severity": "low",
	})
	res, err := h.Ingest(ev)
	if err != nil {
		t.Fatal(err)
	}
	if res.ObjectID == "" {
		t.Fatal("no object")
	}
	if _, ok := s.Get(res.ObjectID); !ok {
		t.Fatal("missing finding object")
	}
	if _, ok := s.Get("person:alice"); !ok {
		t.Fatal("person not linked")
	}
	res2, err := h.Ingest(ev)
	if err != nil || !res2.Duplicate {
		t.Fatalf("want duplicate: %+v %v", res2, err)
	}
}

func TestHTTPWebhook(t *testing.T) {
	s := ontology.NewStore()
	h := NewHandler(s, audit.New())
	h.Token = "secret"
	ev := BuildEvent(Genesis, "breach.found", "offensive/credential-intel", "lookup", "bob", map[string]any{
		"summary":  "email in breach",
		"severity": "high",
		"breach":   "mock-2024",
	})
	body, _ := json.Marshal(ev)

	req := httptest.NewRequest(http.MethodPost, "/hooks/osp", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/hooks/osp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok := s.Get("person:bob"); !ok {
		t.Fatal("bob missing")
	}
}

func TestStrictChain(t *testing.T) {
	s := ontology.NewStore()
	h := NewHandler(s, audit.New())
	h.StrictChain = true
	ev1 := BuildEvent(Genesis, "finding.created", "osp", "add", "x", nil)
	if _, err := h.Ingest(ev1); err != nil {
		t.Fatal(err)
	}
	ev2 := BuildEvent("deadbeef", "finding.created", "osp", "add", "y", nil)
	if _, err := h.Ingest(ev2); err == nil {
		t.Fatal("want prev_hash error")
	}
	ev3 := BuildEvent(ev1.Hash, "finding.created", "osp", "add", "y", nil)
	if _, err := h.Ingest(ev3); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyHash(t *testing.T) {
	ev := BuildEvent(Genesis, "t", "s", "a", "", nil)
	if !ev.VerifyHash() {
		t.Fatal("hash should verify")
	}
	ev.Hash = "nope"
	if ev.VerifyHash() {
		t.Fatal("tampered hash should fail")
	}
}
