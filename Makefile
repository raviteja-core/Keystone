.PHONY: all up down test lint vuln fmt e2e bench gen dev-secrets clean

SHELL := /bin/bash
GOLANGCI_LINT ?= $(shell which golangci-lint 2>/dev/null || echo "$$HOME/.local/bin/golangci-lint")
GOVULNCHECK   ?= $(shell which govulncheck 2>/dev/null || echo "$$HOME/.local/bin/govulncheck")

all: fmt lint test vuln

dev-secrets:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
	fi
	@SECRET=$$(openssl rand -base64 32); \
	sed -i.bak "s|^KEYSTONE_MASTER_KEY=.*|KEYSTONE_MASTER_KEY=$$SECRET|" .env && rm -f .env.bak
	@echo "Generated random 32-byte KEYSTONE_MASTER_KEY in .env"

up: dev-secrets
	docker compose up -d --build

down:
	docker compose down -v

fmt:
	gofmt -s -w .

lint:
	gofmt -s -l .
	go vet ./...
	$(GOLANGCI_LINT) run ./...

test:
	go test -race -v -count=1 -cover ./...
	(cd java && mvn -B test)

vuln:
	$(GOVULNCHECK) ./...

e2e:
	@echo "Running e2e verification suite..."
	@curl -sf http://localhost:9100/readyz || (echo "Auth server not ready" && exit 1)
	@curl -sf http://localhost:9101/readyz || (echo "Authz engine not ready" && exit 1)
	@echo "All services healthy and ready."

bench:
	go test -bench=. -benchmem ./...

gen:
	go generate ./...

clean:
	rm -rf bin/ dist/ target/ coverage.out
