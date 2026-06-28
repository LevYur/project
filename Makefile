.PHONY: help env infra app up down logs ps test

# -------------------------------------------
# Help
# -------------------------------------------

help:
	@echo ""
	@echo "Available commands:"
	@echo ""
	@echo "  make up      - Create .env.local files, start infrastructure and services"
	@echo "  make down    - Stop all containers"
	@echo "  make logs    - Show application logs"
	@echo "  make ps      - Show running containers"
	@echo "  make test    - Run Go tests"
	@echo ""

# -------------------------------------------
# Environment
# -------------------------------------------

env:
	cp -n gateway/config/.env.example gateway/config/.env.local || true
	cp -n auth/config/.env.example auth/config/.env.local || true
	cp -n products/config/.env.example products/config/.env.local || true
	cp -n cart/config/.env.example cart/config/.env.local || true

# -------------------------------------------
# Infrastructure
# -------------------------------------------

infra:
	docker compose -f compose.infra.yaml up -d

# -------------------------------------------
# Application
# -------------------------------------------

app:
	docker compose up -d --build

# -------------------------------------------
# Main commands
# -------------------------------------------

up: env infra app

down:
	docker compose down
	docker compose -f compose.infra.yaml down

logs:
	docker compose logs -f

ps:
	docker compose ps

test:
	go test ./...
