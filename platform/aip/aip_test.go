// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package aip

import (
	"testing"

	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/policy"
)

func TestExportRedactsAndFilters(t *testing.T) {
	s := ontology.NewStore()
	_, _ = s.UpsertObject(ontology.Object{
		ID: "person:alice", Type: ontology.TypePerson, Classification: "internal",
		Properties: map[string]any{"label": "alice", "embedding": []float64{1, 2, 3}, "token": "sekrit"},
	})
	_, _ = s.UpsertObject(ontology.Object{
		ID: "finding:1", Type: ontology.TypeFinding, Classification: "internal",
		Properties: map[string]any{"summary": "hit"},
	})
	_, _ = s.AddLink(ontology.Link{Type: ontology.LinkAssociatedWith, From: "finding:1", To: "person:alice"})

	// secret object should be denied for agent without warrant+case
	_, _ = s.UpsertObject(ontology.Object{
		ID: "document:secret1", Type: ontology.TypeDocument, Classification: "secret",
		Properties: map[string]any{"title": "classified"},
	})
	_, _ = s.AddLink(ontology.Link{Type: ontology.LinkAssociatedWith, From: "person:alice", To: "document:secret1"})

	b, err := Export(s, ExportOptions{
		RootID: "person:alice", Depth: 2,
		Purpose: policy.PurposeClientProtect, Role: policy.RoleAgent,
		IncludeHints: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Objects) < 1 {
		t.Fatal("expected objects")
	}
	for _, o := range b.Objects {
		if o.ID == "document:secret1" {
			t.Fatal("secret doc should be denied")
		}
		if _, ok := o.Properties["embedding"]; ok {
			t.Fatal("embedding should be redacted")
		}
		if _, ok := o.Properties["token"]; ok {
			t.Fatal("token should be redacted")
		}
	}
	if b.Redacted < 1 {
		t.Fatal("expected redactions")
	}
	md := b.Markdown()
	if md == "" {
		t.Fatal("empty markdown")
	}
}

func TestExportRequiresRoot(t *testing.T) {
	_, err := Export(ontology.NewStore(), ExportOptions{})
	if err == nil {
		t.Fatal("want error")
	}
}
