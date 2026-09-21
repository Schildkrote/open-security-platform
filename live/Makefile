# Live proof harness — local Docker stack + Mock->Real connector proofs.
# REQUIRES DOCKER (compose v2 plugin). Never invoked by the root Makefile's
# test/verify fan-out, so offline CI is unaffected.
#
# Usage (from live/):
#   make env      # generate .env with random local-only credentials
#   make config   # fetch + sha256-verify the pinned Wazuh config files
#   make certs    # one-shot: generate Wazuh TLS certs (needs Docker)
#   make up       # config + certs + compose up -d, wait for all healthy
#   make proofs   # run every proof script (stack must be up)
#   make proof-openbao | proof-defectdojo | proof-ollama | proof-keycloak | proof-wazuh
#   make down     # compose down + remove named volumes (destroys all state)
#   make verify-compose  # offline: python yaml checks incl. loopback-only ports

COMPOSE := docker compose --env-file .env

SERVICES_WITH_HEALTH := keycloak wazuh-indexer wazuh defectdojo-postgres \
	defectdojo-valkey defectdojo-uwsgi defectdojo openbao ollama

.PHONY: help env config certs up down down-keep-volumes wait proofs \
	proof-openbao proof-defectdojo proof-ollama proof-keycloak proof-wazuh \
	verify-compose ps logs

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

env: ## Generate live/.env with random local-only credentials (never commit)
	@bash scripts/gen-env.sh

config: ## Fetch + sha256-verify the pinned Wazuh v4.14.7 config files
	@bash scripts/fetch-wazuh-config.sh

certs: config ## Generate Wazuh TLS certs via the one-shot cert-generator service
	@mkdir -p config/wazuh/certs
	@if [ -f config/wazuh/certs/root-ca.pem ]; then \
		echo "certs already present (delete live/config/wazuh/certs/ to regenerate)"; \
	else \
		$(COMPOSE) --profile setup run --rm wazuh-certs-generator || exit 1; \
		test -f config/wazuh/certs/root-ca.pem || { echo "cert generation failed" >&2; exit 1; }; \
	fi

up: env config certs ## Bring the whole stack up (detached) and wait for health
	@$(COMPOSE) up -d
	@$(MAKE) wait

wait: ## Block until every service reports healthy (all listed services define healthchecks)
	@echo "waiting for services to become healthy (several minutes on first run; DefectDojo runs migrations in the initializer)..."
	@for s in $(SERVICES_WITH_HEALTH); do \
		echo "==> waiting for $$s"; \
		cid=$$($(COMPOSE) ps -q $$s 2>/dev/null | head -1); \
		if [ -z "$$cid" ]; then echo "    $$s has no container (not started?)" >&2; exit 1; fi; \
		deadline=$$(python3 -c 'import time; print(int(time.time()) + 1800)'); \
		while true; do \
			state=$$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$$cid" 2>/dev/null || echo unknown); \
			case "$$state" in \
				healthy) echo "    $$s healthy"; break ;; \
				unhealthy) echo "    $$s UNHEALTHY — check: $(COMPOSE) logs $$s" >&2; exit 1 ;; \
				exited) echo "    $$s exited unexpectedly — check: $(COMPOSE) logs $$s" >&2; exit 1 ;; \
			esac; \
			if [ $$(python3 -c 'import time; print(int(time.time()))') -ge $$deadline ]; then echo "    timed out waiting for $$s (last state: $$state)" >&2; exit 1; fi; \
			sleep 5; \
		done; \
	done
	@echo "stack is up: keycloak http://127.0.0.1:18080  wazuh https://127.0.0.1:15500  defectdojo http://127.0.0.1:18082  openbao http://127.0.0.1:18200  ollama http://127.0.0.1:11434"

proofs: ## Run all proof scripts against the running stack
	@bash scripts/run-proofs.sh

proof-openbao: ## Proof: open-pam-jit -> OpenBao via internal/bao (Real client)
	@bash proofs/openbao.sh

proof-defectdojo: ## Proof: pentest-manager -> DefectDojo via FindingsSink (--live gate)
	@bash proofs/defectdojo.sh

proof-ollama: ## Proof: open-ai-gateway -> Ollama via the Real provider connector
	@bash proofs/ollama.sh

proof-keycloak: ## Proof: Keycloak OIDC smoke check (well-known + token endpoint)
	@bash proofs/keycloak.sh

proof-wazuh: ## Proof: Wazuh manager API smoke check (see script header for scope)
	@bash proofs/wazuh.sh

verify-compose: ## OFFLINE validation: YAML parses, all ports loopback-only, healthchecks + volumes present
	@python3 scripts/validate_compose.py

ps: ## Show compose service state
	@$(COMPOSE) ps

logs: ## Tail all stack logs (Ctrl-C to stop)
	@$(COMPOSE) logs -f

down: ## Stop the stack AND remove all named volumes (destroys all state)
	@$(COMPOSE) down -v --remove-orphans

down-keep-volumes: ## Stop the stack but keep named volumes (faster restart)
	@$(COMPOSE) down --remove-orphans
