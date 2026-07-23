# open-security-platform — polyglot monorepo orchestration.
# Fans out build/test/lint across Go, Node/TS and Python components.

GO_DIRS   := platform identity/oiaf identity/open-pam-jit ai-security/open-ai-gateway offensive/attack-path
NODE_DIRS := identity/agent-identity ai-security/ai-access-broker ai-security/mcp-security-gateway offensive/pentest-manager soc/open-soar
PY_DIRS   := ai-security/rag-authorization ai-security/agent-sandbox ai-governance/ai-compliance-hub ai-governance/ai-redteam-evals ai-governance/ai-redteam-platform offensive/purple-team offensive/agent-redteam-range

.PHONY: help test test-go test-node test-python build build-go lint fmt verify docs clean list

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

list: ## List components by language
	@echo "Go:     $(GO_DIRS)"
	@echo "Node:   $(NODE_DIRS)"
	@echo "Python: $(PY_DIRS)"

test: test-go test-node test-python ## Run all component test suites

test-go: ## Run Go tests
	@for d in $(GO_DIRS); do echo "==> go test $$d"; (cd $$d && go test ./...) || exit 1; done

test-node: ## Run Node/TS tests
	@for d in $(NODE_DIRS); do echo "==> npm test $$d"; (cd $$d && npm test) || exit 1; done

test-python: ## Run Python tests
	@for d in $(PY_DIRS); do echo "==> unittest $$d"; (cd $$d && python3 -m unittest discover -s tests) || exit 1; done

build: build-go ## Build compiled components
	@echo "Node/TS and Python components run from source (see each README)."

build-go: ## Build Go binaries
	@for d in $(GO_DIRS); do echo "==> go build $$d"; (cd $$d && go build ./...) || exit 1; done

lint: ## Lint Go components (vet + gofmt check)
	@for d in $(GO_DIRS); do echo "==> go vet $$d"; (cd $$d && go vet ./...) || exit 1; done
	@echo "==> gofmt check"
	@test -z "$$(gofmt -l $(GO_DIRS) 2>/dev/null)" || (gofmt -l $(GO_DIRS); exit 1)

fmt: ## Format Go code
	@gofmt -w $(GO_DIRS)

verify: lint test ## Lint then test everything

docs: ## Serve the docs site with mkdocs (if installed)
	@command -v mkdocs >/dev/null 2>&1 && mkdocs serve || echo "mkdocs not installed (pip install mkdocs)"

clean: ## Remove build/test artifacts
	@for d in $(NODE_DIRS); do rm -rf $$d/node_modules; done
	@find . -type d -name __pycache__ -prune -exec rm -rf {} +
	@rm -rf bin/ tmp/ site/
