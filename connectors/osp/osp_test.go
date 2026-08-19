// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package ospconnector

import (
	"testing"

	"github.com/Schildkrote/ontology"
)

func TestIngest(t *testing.T) {
	s := ontology.NewStore()
	for _, f := range MockFindings() {
		id, err := Ingest(s, f)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := s.Get(id); !ok {
			t.Fatal("missing finding")
		}
	}
	if _, ok := s.Get("person:alice"); !ok {
		t.Fatal("person")
	}
}
