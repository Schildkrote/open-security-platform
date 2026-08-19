module github.com/Schildkrote/odp-ingest

go 1.26

require (
	github.com/Schildkrote/connector-alpr v0.0.0
	github.com/Schildkrote/connector-obp v0.0.0
	github.com/Schildkrote/connector-osp v0.0.0
	github.com/Schildkrote/odp-audit v0.0.0
	github.com/Schildkrote/ontology v0.0.0
	github.com/Schildkrote/policy v0.0.0
)

replace github.com/Schildkrote/connector-alpr => ../../connectors/alpr

replace github.com/Schildkrote/connector-obp => ../../connectors/obp

replace github.com/Schildkrote/connector-osp => ../../connectors/osp

replace github.com/Schildkrote/odp-audit => ../../platform/audit

replace github.com/Schildkrote/ontology => ../../platform/ontology

replace github.com/Schildkrote/policy => ../../platform/policy
