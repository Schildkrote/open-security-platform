// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package osint

import (
	"testing"

	"github.com/Schildkrote/ontology"
)

func TestIngestMap(t *testing.T) {
	s := ontology.NewStore()
	id, err := IngestMap(s, "x1", "note", "bob", "hello", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(id); !ok {
		t.Fatal("missing")
	}
}
