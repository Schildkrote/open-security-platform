module github.com/Schildkrote/odp-webhook

go 1.26

require (
	github.com/Schildkrote/odp-audit v0.0.0
	github.com/Schildkrote/odp-events v0.0.0
	github.com/Schildkrote/ontology v0.0.0
	github.com/Schildkrote/packs v0.0.0
)

require (
	github.com/Schildkrote/connector-osp v0.0.0 // indirect
	github.com/Schildkrote/policy v0.0.0 // indirect
)

replace github.com/Schildkrote/odp-audit => ../../platform/audit

replace github.com/Schildkrote/odp-events => ../../platform/events

replace github.com/Schildkrote/ontology => ../../platform/ontology

replace github.com/Schildkrote/connector-osp => ../../connectors/osp

replace github.com/Schildkrote/packs => ../../platform/packs

replace github.com/Schildkrote/policy => ../../platform/policy
