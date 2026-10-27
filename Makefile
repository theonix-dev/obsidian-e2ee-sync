# Obsidian E2EE Sync — developer and operator conveniences.
#
# Container lifecycle : make up | down | logs | ps | restart
# Operations          : make backup | restore BACKUP=path/to/tar.gz
# Development         : make build-plugin | test | install-plugin VAULT=...
# See README.md for the full documentation.

COMPOSE ?= docker compose
SERVICE := sync-server
BACKUP_DIR ?= ./backups

.DEFAULT_GOAL := help
.PHONY: help up down restart logs ps backup restore test build-plugin install-plugin clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}'

up: ## Start the storage server in the background (docker compose up -d)
	@test -f .env || { echo "ERROR: .env is missing — run: cp .env.example .env and set AUTH_TOKEN" >&2; exit 1; }
	$(COMPOSE) up -d --build
	@echo "Server: http://127.0.0.1:8080 (health: make ps)"

down: ## Stop the server; the data volume is preserved
	$(COMPOSE) down

restart: ## Restart the server
	$(COMPOSE) restart

logs: ## Follow server logs
	$(COMPOSE) logs -f --tail=100 $(SERVICE)

ps: ## Show container status and health
	$(COMPOSE) ps

backup: ## Archive the server data to backups/<timestamp>.tar.gz (server must be up)
	@mkdir -p $(BACKUP_DIR)
	$(COMPOSE) exec -T $(SERVICE) tar -czf - -C /data . \
		> $(BACKUP_DIR)/$$(date +%Y-%m-%d_%H-%M-%S)_obsidian-sync.tar.gz
	@echo "Backup written to $(BACKUP_DIR)/ (latest: $$(ls -t $(BACKUP_DIR) | head -1))"

restore: ## Restore server data; usage: make restore BACKUP=backups/<file>.tar.gz
	@test -n "$(BACKUP)" || { echo "ERROR: specify BACKUP=backups/<file>.tar.gz" >&2; exit 1; }
	@test -f "$(BACKUP)" || { echo "ERROR: file not found: $(BACKUP)" >&2; exit 1; }
	@echo "WARNING: this replaces the current server data."
	@read -r -p "Type 'yes' to continue: " ans; [ "$$ans" = "yes" ] || { echo "Aborted."; exit 1; }
	$(COMPOSE) exec -T $(SERVICE) sh -c "rm -rf /data/* && tar -xzf - -C /data" < $(BACKUP)
	$(COMPOSE) restart
	@echo "Restore complete."

test: ## Run the 42-assertion server integration suite
	node server/test-e2e.mjs

build-plugin: ## Build the Obsidian plugin bundle (plugin/main.js)
	cd plugin && npm install --no-fund --no-audit && npm run build

install-plugin: ## Install the plugin into a vault; usage: make install-plugin VAULT=/path/to/vault
	@test -n "$(VAULT)" || { echo "ERROR: specify VAULT=/path/to/vault" >&2; exit 1; }
	@test -f plugin/main.js || { echo "ERROR: plugin/main.js missing — run make build-plugin" >&2; exit 1; }
	@mkdir -p $(VAULT)/.obsidian/plugins/e2ee-vault-sync
	cp plugin/main.js plugin/manifest.json plugin/styles.css $(VAULT)/.obsidian/plugins/e2ee-vault-sync/
	@echo "Installed into $(VAULT)/.obsidian/plugins/e2ee-vault-sync/"

clean: ## Remove local wizard/server runtime state (logs, pid)
	rm -f server/server.pid server/*.log
