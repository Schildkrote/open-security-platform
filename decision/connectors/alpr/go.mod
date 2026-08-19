module github.com/Schildkrote/connector-alpr

go 1.26

require (
	github.com/Schildkrote/odp-audit v0.0.0
	github.com/Schildkrote/ontology v0.0.0
	github.com/Schildkrote/policy v0.0.0
)

replace github.com/Schildkrote/ontology => ../../platform/ontology

replace github.com/Schildkrote/policy => ../../platform/policy

replace github.com/Schildkrote/odp-audit => ../../platform/audit
