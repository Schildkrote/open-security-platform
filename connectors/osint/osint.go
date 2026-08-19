// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package osint is a thin alias envelope for non-OSP generic findings.
package osint

import (
	ospconnector "github.com/Schildkrote/connector-osp"
	"github.com/Schildkrote/ontology"
)

// Re-export pattern: normalize generic maps into OSP finding shape.
func IngestMap(store *ontology.Store, id, kind, subject, summary, source string) (string, error) {
	return ospconnector.Ingest(store, ospconnector.Finding{
		ID: id, Kind: kind, Subject: subject, Summary: summary, Source: source,
	})
}
