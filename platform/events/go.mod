module github.com/Schildkrote/odp-events

go 1.26

require (
	github.com/Schildkrote/connector-obp v0.0.0
	github.com/Schildkrote/connector-osp v0.0.0
	github.com/Schildkrote/odp-audit v0.0.0
	github.com/Schildkrote/ontology v0.0.0
	github.com/Schildkrote/policy v0.0.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.47.0 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.57.0 // indirect
)

replace github.com/Schildkrote/connector-osp => ../../connectors/osp

replace github.com/Schildkrote/odp-audit => ../audit

replace github.com/Schildkrote/ontology => ../ontology

replace github.com/Schildkrote/policy => ../policy

replace github.com/Schildkrote/connector-obp => ../../connectors/obp
