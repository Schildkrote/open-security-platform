module github.com/Schildkrote/biometric-rbr

go 1.26

require (
	github.com/Schildkrote/biometric-audit v0.0.0
	github.com/Schildkrote/lawful-basis v0.0.0
)

replace github.com/Schildkrote/lawful-basis => ../platform/lawful-basis

replace github.com/Schildkrote/biometric-audit => ../platform/biometric-audit
