# Messaging platform — development and operations entry points.
#
# `make help` lists everything.

SHELL := /bin/bash
.DEFAULT_GOAL := help
.ONESHELL:

# Every deployable, with the path to its main package. The consumers live a
# level deeper, which is why this is a lookup rather than a flat list.
SERVICES := auth-service chat-service realtime-gateway presence-service \
            media-service notification-service
CONSUMERS := persister pusher indexer
ALL_SERVICES := $(SERVICES) $(CONSUMERS)

GO ?= go
PROJECT_ID ?= messaging-dev
REGION ?= europe-west1
ENV ?= dev
REGISTRY ?= $(REGION)-docker.pkg.dev/$(PROJECT_ID)/messaging-app
TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

COMPOSE ?= docker compose

# Local development environment. Every service reads these.
export ENV := dev
export LOG_LEVEL ?= debug
export LOG_PRETTY ?= true
export KAFKA_BROKERS ?= localhost:9092
export KAFKA_TLS ?= false
export KAFKA_OAUTH ?= false
export REDIS_ADDRS ?= localhost:6379
export REDIS_CLUSTER ?= false
export REDIS_TLS ?= false
export POSTGRES_DSN ?= postgres://messaging:localdev@localhost:5432/messaging?sslmode=disable
export CASSANDRA_HOSTS ?= localhost:9042
export CASSANDRA_KEYSPACE ?= messaging
export CASSANDRA_LOCAL_DC ?= europe-west1
export ELASTICSEARCH_ADDRS ?= http://localhost:9200
export GCP_PROJECT_ID ?= $(PROJECT_ID)
export GCP_REGION ?= $(REGION)

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Build and test
# ---------------------------------------------------------------------------

.PHONY: build
build: ## Compile every service
	$(GO) build ./...

.PHONY: test
test: ## Run the unit tests
	$(GO) test -count=1 ./...

.PHONY: test-race
test-race: ## Run the tests with the race detector
	$(GO) test -race -count=1 ./...

.PHONY: test-cover
test-cover: ## Run the tests and report coverage
	$(GO) test -race -count=1 -covermode=atomic -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -30
	@echo
	@echo "html report: go tool cover -html=coverage.out"

.PHONY: vet
vet: ## Run go vet and check formatting
	$(GO) vet ./...
	@test -z "$$(gofmt -l ./pkg ./services ./tools 2>/dev/null)" || { \
	  echo "not gofmt-formatted:"; gofmt -l ./pkg ./services ./tools; exit 1; }

.PHONY: fmt
fmt: ## Format the Go source
	gofmt -w ./pkg ./services ./tools

.PHONY: lint
lint: ## Run golangci-lint (requires golangci-lint on PATH)
	golangci-lint run --timeout=10m ./...

.PHONY: vulncheck
vulncheck: ## Report reachable vulnerabilities
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: web-test
web-test: ## Typecheck and test the web client's MTProto implementation
	cd web && npm run typecheck && npm test

.PHONY: android-test
android-test: ## Compile and test the Kotlin MTProto module (needs kotlinc + a JDK)
	./scripts/android-test.sh

.PHONY: cross-check
cross-check: ## Verify all three protocol implementations agree
	@echo "=== Go ==="
	$(GO) test -count=1 -run 'CrossImplementation|KnownAnswer' ./pkg/mtproto/
	@echo "=== TypeScript ==="
	cd web && npm test
	@echo "=== Kotlin ==="
	./scripts/android-test.sh

.PHONY: check
check: vet test-race ## Everything CI runs on a pull request

# ---------------------------------------------------------------------------
# Local stack
# ---------------------------------------------------------------------------

.PHONY: dev-up
dev-up: ## Start Kafka, Cassandra, Postgres, Redis and Elasticsearch
	$(COMPOSE) up -d
	@echo "waiting for the stack to become healthy (Cassandra takes ~90s)"
	@$(COMPOSE) up --wait --wait-timeout 300 2>/dev/null || true
	@$(COMPOSE) ps

.PHONY: dev-down
dev-down: ## Stop the stack, keeping the data
	$(COMPOSE) down

.PHONY: dev-clean
dev-clean: ## Stop the stack and delete every volume
	$(COMPOSE) down -v

.PHONY: dev-logs
dev-logs: ## Tail the stack logs
	$(COMPOSE) logs -f

.PHONY: dev-tools
dev-tools: ## Start the optional Kafka UI on :8090
	$(COMPOSE) --profile tools up -d kafka-ui
	@echo "kafka ui: http://localhost:8090"

.PHONY: dev-migrate
dev-migrate: ## Apply the Postgres and Cassandra schemas locally
	@echo "--- postgres ---"
	@for f in db/postgres/migrations/*.sql; do \
	  echo "  $$f"; \
	  PGPASSWORD=localdev psql -h localhost -U messaging -d messaging \
	    -v ON_ERROR_STOP=1 -q -f "$$f" || exit 1; \
	done
	@echo "--- cassandra ---"
	@docker exec -i messaging-cassandra cqlsh < db/cassandra/schema.cql
	@echo "schemas applied"

.PHONY: dev-reset
dev-reset: dev-clean dev-up dev-migrate ## Rebuild the local stack from scratch

# ---------------------------------------------------------------------------
# Running services locally
# ---------------------------------------------------------------------------

local/mtproto-server-key.pem:
	./scripts/gen-mtproto-key.sh $@

local/jwt-signing-key.pem:
	@mkdir -p local
	openssl ecparam -name prime256v1 -genkey -noout -out local/jwt-ec.pem 2>/dev/null
	openssl pkcs8 -topk8 -nocrypt -in local/jwt-ec.pem -out $@
	@rm -f local/jwt-ec.pem
	@echo "generated $@"

.PHONY: keys
keys: local/mtproto-server-key.pem local/jwt-signing-key.pem ## Generate local development keys

# The _FILE form, matching the cluster. In production the CSI driver projects
# every secret as a file and nothing reads a credential from the environment;
# using the same path locally is how a file-handling bug is caught here rather
# than after a rollout.

.PHONY: run-auth
run-auth: local/jwt-signing-key.pem ## Run the auth service
	JWT_SIGNING_KEY_PEM_FILE=local/jwt-signing-key.pem \
	JWT_SIGNING_KEY_ID=local \
	SMS_PROVIDER=log \
	HTTP_ADDR=:8081 ADMIN_ADDR=:9081 \
	$(GO) run ./services/auth-service

.PHONY: run-chat
run-chat: local/jwt-signing-key.pem ## Run the chat service
	JWT_SIGNING_KEY_PEM_FILE=local/jwt-signing-key.pem \
	JWT_SIGNING_KEY_ID=local \
	HTTP_ADDR=:8082 ADMIN_ADDR=:9082 \
	$(GO) run ./services/chat-service

.PHONY: run-gateway
run-gateway: keys ## Run the realtime gateway
	MTPROTO_SERVER_KEY_PEM_FILE=local/mtproto-server-key.pem \
	AUTH_SERVICE_URL=http://localhost:8081 \
	CHAT_SERVICE_URL=http://localhost:8082 \
	PRESENCE_SERVICE_URL=http://localhost:8083 \
	MTPROTO_WS_ADDR=:8080 ADMIN_ADDR=:9080 \
	$(GO) run ./services/realtime-gateway

.PHONY: run-search
run-search: ## Run the search service
	HTTP_ADDR=:8085 ADMIN_ADDR=:9085 $(GO) run ./services/search-service

.PHONY: run-call
run-call: ## Run the call signalling service
	TURN_SECRET=local-development-secret \
	HTTP_ADDR=:8086 ADMIN_ADDR=:9086 $(GO) run ./services/call-service

.PHONY: run-mediaproc
run-mediaproc: ## Run the media processing consumer (needs ffmpeg)
	ADMIN_ADDR=:9087 $(GO) run ./services/consumers/mediaproc

.PHONY: run-auditor
run-auditor: ## Run the audit trail verifier (needs a GCS bucket)
	AUDIT_ARCHIVE_BUCKET=$${AUDIT_ARCHIVE_BUCKET:-messaging-dev-audit-archive} \
	ADMIN_ADDR=:9088 $(GO) run ./services/consumers/auditor

.PHONY: run-presence
run-presence: ## Run the presence service
	HTTP_ADDR=:8083 ADMIN_ADDR=:9083 $(GO) run ./services/presence-service

.PHONY: run-persister
run-persister: ## Run the persister consumer
	ADMIN_ADDR=:9084 $(GO) run ./services/consumers/persister

.PHONY: run-indexer
run-indexer: ## Run the search indexer
	ADMIN_ADDR=:9085 $(GO) run ./services/consumers/indexer

# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------

.PHONY: docker-build
docker-build: ## Build every service image locally
	@for s in $(SERVICES); do \
	  echo "--- $$s ---"; \
	  docker build -f build/Dockerfile \
	    --build-arg SERVICE=$$s --build-arg VERSION=$(TAG) \
	    -t $(REGISTRY)/$$s:$(TAG) . || exit 1; \
	done
	@for s in $(CONSUMERS); do \
	  echo "--- $$s ---"; \
	  docker build -f build/Dockerfile \
	    --build-arg SERVICE=consumers/$$s --build-arg VERSION=$(TAG) \
	    -t $(REGISTRY)/$$s:$(TAG) . || exit 1; \
	done

.PHONY: docker-push
docker-push: ## Push every image
	@for s in $(ALL_SERVICES); do docker push $(REGISTRY)/$$s:$(TAG) || exit 1; done

# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

.PHONY: tf-init
tf-init: ## terraform init for $(ENV)
	cd deploy/terraform && terraform init -backend-config=envs/$(ENV)/backend.hcl

.PHONY: tf-plan
tf-plan: ## terraform plan for $(ENV)
	cd deploy/terraform && terraform plan -var-file=envs/$(ENV)/terraform.tfvars

.PHONY: tf-apply
tf-apply: ## terraform apply for $(ENV)
	cd deploy/terraform && terraform apply -var-file=envs/$(ENV)/terraform.tfvars

.PHONY: tf-validate
tf-validate: ## Validate the Terraform without a backend
	cd deploy/terraform && terraform fmt -check -recursive && \
	  terraform init -backend=false -input=false >/dev/null && terraform validate

# ---------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------

# Everything below goes through scripts/render-manifests.sh rather than
# `kubectl kustomize` directly. Kustomize cannot substitute PROJECT_ID and ENV,
# because they appear inside strings — service-account annotations and Secret
# Manager resource paths — and applying an overlay raw deploys those literals.
# The script substitutes them and refuses to emit anything with a placeholder
# left in it.

.PHONY: k8s-build
k8s-build: ## Render the manifests for $(ENV)
	./scripts/render-manifests.sh $(ENV)

.PHONY: k8s-validate
k8s-validate: ## Render and schema-validate every overlay
	@for e in dev staging prod; do \
	  echo "=== $$e ==="; \
	  ./scripts/render-manifests.sh $$e > /tmp/messaging-$$e.yaml || exit 1; \
	  echo "  $$(grep -c '^kind:' /tmp/messaging-$$e.yaml) resources"; \
	  command -v kubeconform >/dev/null && \
	    kubeconform -summary -strict -ignore-missing-schemas /tmp/messaging-$$e.yaml || \
	    echo "  (install kubeconform for schema validation)"; \
	done

.PHONY: k8s-apply
k8s-apply: ## Apply the manifests for $(ENV)
	./scripts/render-manifests.sh $(ENV) | kubectl apply -f -

.PHONY: k8s-diff
k8s-diff: ## Diff the manifests for $(ENV) against the cluster
	./scripts/render-manifests.sh $(ENV) | kubectl diff -f - || true

# ---------------------------------------------------------------------------
# Load testing
# ---------------------------------------------------------------------------

.PHONY: loadgen
loadgen: ## Drive the gateway with synthetic clients
	$(GO) run ./tools/loadgen -addr localhost:4443 -clients 100 -duration 60s

.PHONY: clean
clean: ## Remove build artifacts
	rm -f coverage.out
	rm -rf local/
	$(GO) clean -cache -testcache
