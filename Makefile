# open-decision-platform

GO_DIRS := platform/ontology platform/policy platform/audit platform/actions \
	platform/events platform/packs platform/aip platform/social-scoring platform/credibility \
	connectors/osp connectors/obp connectors/alpr connectors/osint \
	apps/graph apps/dossier apps/ingest apps/webhook apps/contextbundle \
	integration

.PHONY: list test lint fmt verify

list:
	@echo $(GO_DIRS)

test:
	@for d in $(GO_DIRS); do \
		echo "==> go test $$d"; \
		( cd $$d && go test ./... ); \
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
