# open-biometric-platform — polyglot monorepo orchestration.

GO_DIRS := platform/lawful-basis platform/biometric-audit biometric-rbr biometric-graph
PY_DIRS := platform/basis-matrix platform/audit-log biometric-categorise biometric-scrape biometric-train biometric-cctv integration

.PHONY: list test test-go test-python lint fmt verify docs

list:
	@echo "Go:     $(GO_DIRS)"
	@echo "Python: $(PY_DIRS)"

test: test-go test-python

test-go:
	@for d in $(GO_DIRS); do \
		echo "==> go test $$d"; \
		( cd $$d && go test ./... ); \
	done

test-python:
	@for d in $(PY_DIRS); do \
		echo "==> unittest $$d"; \
		( cd $$d && python3 -m unittest discover -s tests -v ); \
	done

lint:
	@for d in $(GO_DIRS); do \
		echo "==> go vet $$d"; \
		( cd $$d && go vet ./... ); \
	done
	@echo "==> gofmt check"
	@unformatted=$$(gofmt -l $(GO_DIRS) 2>/dev/null); \
		if [ -n "$$unformatted" ]; then echo "$$unformatted"; exit 1; fi

fmt:
	@gofmt -w $(GO_DIRS)

verify: lint test
	@echo "verify OK"
