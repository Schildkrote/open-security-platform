// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package obpconnector

import (
	"testing"

	"github.com/Schildkrote/ontology"
)

func TestIngest(t *testing.T) {
	s := ontology.NewStore()
	for _, h := range MockHits() {
		if _, err := Ingest(s, h); err != nil {
			t.Fatal(err)
		}
	}
	hits := s.QueryObjects(ontology.Query{Type: ontology.TypeBiometricHit})
	if len(hits) != 2 {
		t.Fatalf("hits=%d", len(hits))
	}
}
