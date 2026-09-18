# Development shortcuts. `make` alone lists them.
#
# Everything here wraps a command documented in GETTING-STARTED.md and
# CONTRIBUTING.md; nothing is required to build or run rIDM. Ports and URLs
# come from `.env` (copy `.env.example`), with the defaults below when a key is
# absent, and any of them can be overridden on the command line:
#
#   make ui UI_PORT=3120
#   make token ADMIN=root

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# The last `KEY=value` line of .env, quotes stripped; empty when absent.
envval = $(shell sed -n 's/^$(1)=//p' .env 2>/dev/null | tail -n 1 | tr -d "\"'")

PG_PORT      ?= $(or $(call envval,RIDM_PG_PORT),5432)
MAILPIT_PORT ?= $(or $(call envval,RIDM_MAILPIT_UI_PORT),8025)
API_URL      ?= $(or $(call envval,PUBLIC_URL),http://localhost:8090)
UI_PORT      ?= 3110
UI_URL       ?= http://localhost:$(UI_PORT)
# The owner `make token` mints for; empty means BOOTSTRAP_ADMIN_USERNAME, else `admin`.
ADMIN        ?=
TOKEN_FILE   := target/dev/token
MIGRATOR_URL ?= postgres://$(or $(call envval,RIDM_MIGRATOR_USER),ridm_migrator):$(or $(call envval,RIDM_MIGRATOR_PASSWORD),ridm_migrator)@localhost:$(PG_PORT)/ridm

COMPOSE := docker compose --env-file .env -f deploy/docker-compose.yml
RIDM    := target/debug/ridm

##@ Local stack

.PHONY: up
up: .env ## Start Postgres, Valkey and Mailpit
	$(COMPOSE) up -d --wait postgres valkey mailpit
	@echo "Mailpit: http://localhost:$(MAILPIT_PORT)"

.PHONY: down
down: ## Stop them (data is kept)
	$(COMPOSE) stop postgres valkey mailpit

.PHONY: reset
reset: ## Delete the database and cache volumes (asks first)
	@read -r -p "Delete every tenant, user and key in the local database? [type yes] " ans; \
	  [ "$$ans" = yes ] || { echo "Nothing deleted."; exit 1; }
	$(COMPOSE) down -v

.PHONY: ps
ps: ## Show the stack's containers
	$(COMPOSE) ps

.PHONY: migrate
migrate: ## Apply pending migrations as the schema owner
	DATABASE_URL=$(MIGRATOR_URL) cargo run -q -p ridm-api -- migrate

.PHONY: setup
setup: up migrate token ## First run: stack, migrations, first admin and a token
	@echo
	@echo "Next: 'make api' and 'make ui' in two terminals, then 'make seed'."

##@ Run

.PHONY: api
api: ## Run the API from source (reads .env)
	UI_URL=$(UI_URL) cargo run -p ridm-api

.PHONY: watch
watch: ## Run the API and restart it when Rust, SQL or TOML changes (needs watchexec)
	@command -v watchexec >/dev/null || { \
	  echo "watchexec is not installed: cargo binstall watchexec-cli (or cargo install)"; exit 1; }
	UI_URL=$(UI_URL) watchexec --restart --stop-signal SIGTERM \
	  --watch api/src --watch api/migrations --watch crates --watch Cargo.toml \
	  --exts rs,sql,toml -- cargo run -p ridm-api

.PHONY: ui
ui: ui/node_modules ## Run the UI dev server (hot reload) against the API
	cd ui && API_PROXY=$(API_URL) npx next dev -p $(UI_PORT)

.PHONY: mail
mail: ## Print the Mailpit address
	@echo "http://localhost:$(MAILPIT_PORT)"

##@ Data

.PHONY: token
token: ## Make sure an owner exists and mint an admin token into target/dev/token
	cargo build -q -p ridm-cli
	@mkdir -p $(dir $(TOKEN_FILE))
	@umask 077; $(RIDM) bootstrap --no-migrate $(if $(ADMIN),--username $(ADMIN)) \
	  --issue-token "make-token $$(date +%F)" > $(TOKEN_FILE).new || { \
	  rm -f $(TOKEN_FILE).new; echo "(name the owner with: make token ADMIN=<username>)"; exit 1; }
	@mv $(TOKEN_FILE).new $(TOKEN_FILE)
	@echo "Token written to $(TOKEN_FILE). For the CLI:  export RIDM_URL=$(API_URL) RIDM_TOKEN=\$$(cat $(TOKEN_FILE))"

.PHONY: seed
seed: ## Load the demo and acme tenants into the running API
	@[ -s $(TOKEN_FILE) ] || { echo "No $(TOKEN_FILE): run 'make token' first."; exit 1; }
	cargo build -q -p ridm-cli
	RIDM_URL=$(API_URL) RIDM_TOKEN=$$(cat $(TOKEN_FILE)) dev/seed.sh

##@ Checks

.PHONY: fmt
fmt: ## Format Rust
	cargo fmt --all

.PHONY: lint
lint: ui/node_modules ## rustfmt, clippy as CI runs it, UI lint and types
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cd ui && npm run lint && npm run typecheck

.PHONY: test
test: ## Unit tests
	cargo test --workspace --lib --bins

.PHONY: test-all
test-all: ## Unit and integration tests (starts test containers if needed)
	cargo test --workspace

.PHONY: e2e
e2e: ui/node_modules ## Browser suite (Playwright)
	cd ui && npm run e2e

.PHONY: openapi
openapi: ## Regenerate api/openapi.json
	cargo run -q -p ridm-api -- openapi > api/openapi.json.new
	mv api/openapi.json.new api/openapi.json

.PHONY: docs
docs: ## Build the documentation site into docs/book
	docs/build.sh

##@ Help

.PHONY: help
help: ## List the targets
	@awk 'BEGIN { FS = ":.*## " } \
	  /^##@/ { printf "\n%s\n", substr($$0, 5) } \
	  /^[a-z0-9-]+:.*## / { printf "  %-10s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.env:
	@echo "No .env: cp .env.example .env, then set MASTER_KEY=\$$(openssl rand -hex 32)"; exit 1

ui/node_modules: ui/package-lock.json
	cd ui && npm ci
	@touch $@
