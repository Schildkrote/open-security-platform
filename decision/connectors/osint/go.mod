module github.com/Schildkrote/connector-osint

go 1.26

require (
	github.com/Schildkrote/connector-osp v0.0.0
	github.com/Schildkrote/ontology v0.0.0
)

replace github.com/Schildkrote/ontology => ../../platform/ontology

replace github.com/Schildkrote/connector-osp => ../osp
