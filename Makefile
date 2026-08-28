# Kai -- pcap browsing and search for ICS/OT research
#
# Common project tasks. Run `make help` for the full list.
# Customize tools, paths, or image tags via environment variables, e.g.:
#   make container-build PODMAN=docker IMAGE=kai:dev
#   make quadlet QUADLET_DIR=/etc/containers/systemd

PREFIX        ?= /usr/local
QUADLET_DIR   ?= /etc/containers/systemd
IMAGE         ?= kai:latest
CONTAINERFILE ?= Containerfile
PORT          ?= 3022
BACKUP_DIR    ?= $(CURDIR)/backups

PODMAN        ?= podman
UV            ?= uv
MANAGE        ?= ${UV} run python manage.py
TAILWINDCSS   ?= tailwindcss

.DEFAULT_GOAL := help

.PHONY: help \
        install setup \
        db-migrate db-prepare \
        server worker shell \
        test lint lint-fix format \
        collectstatic tailwind-build \
        backup \
        container-build container-install container-run container-clean \
        compose-up compose-down \
        quadlet deploy

help: ## Show this help message
	@awk 'BEGIN { FS = ":.*?## "; print "Kai -- available make targets:\n" } \
	      /^[a-zA-Z0-9_-]+:.*?## / { printf "  %-22s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

## --- Setup -----------------------------------------------------------------

install: ## Install Python dependencies via uv
	${UV} sync

setup: install db-prepare ## First-run setup: install dependencies and migrate DB

## --- Database --------------------------------------------------------------

db-migrate: ## Run pending database migrations
	${MANAGE} migrate

db-prepare: db-migrate ## Prepare the database

backup: ## Back up PostgreSQL and uploaded pcaps into BACKUP_DIR (default: ./backups)
	mkdir -p "${BACKUP_DIR}"
	${PODMAN} compose run --rm --no-deps -v "${BACKUP_DIR}:/backups" app backup /backups

## --- Run -------------------------------------------------------------------

server: ## Start the development server on 0.0.0.0:${PORT}
	DJANGO_DEBUG=$${DJANGO_DEBUG:-1} DJANGO_SECURE_COOKIES=$${DJANGO_SECURE_COOKIES:-0} ${MANAGE} runserver 0.0.0.0:${PORT}

worker: ## Process queued capture analysis
	${MANAGE} analyze_pcaps

shell: ## Start a Django shell
	${MANAGE} shell

## --- Test and lint ---------------------------------------------------------

test: ## Run the full test suite
	${UV} run pytest

lint: ## Run ruff checks
	${UV} run ruff check .

lint-fix: ## Run ruff with auto-fix
	${UV} run ruff check --fix .

format: ## Format code with ruff
	${UV} run ruff format .

## --- Assets ----------------------------------------------------------------

collectstatic: ## Collect static files for production serving
	${MANAGE} collectstatic --noinput

tailwind-build: ## Rebuild kai/static/css/tailwind.css (needs the tailwindcss standalone CLI)
	${TAILWINDCSS} --input tailwind/application.css --output kai/static/css/tailwind.css --minify

## --- Container -------------------------------------------------------------

container-build: ## Build the container image (${IMAGE})
	${PODMAN} build -t ${IMAGE} -f ${CONTAINERFILE} .

container-install: ## Copy the built image into root podman storage for system Quadlet
	${PODMAN} save ${IMAGE} | sudo ${PODMAN} load

container-run: ## Run the container locally, exposing port 3022
	${PODMAN} run --rm -p 3022:3022 ${IMAGE}

container-clean: ## Remove the built container image
	-${PODMAN} rmi ${IMAGE}

compose-up: ## Start app + postgres via compose.yaml
	${PODMAN} compose up

compose-down: ## Stop and remove compose services
	${PODMAN} compose down

## --- Deploy ----------------------------------------------------------------

quadlet: ## Install Quadlet unit files to ${QUADLET_DIR} (requires sudo)
	@for f in deploy/systemd/*; do \
	  sudo cp "$${f}" "${QUADLET_DIR}/" ; \
	done
	sudo systemctl daemon-reload
	@echo "Quadlet units installed. Start with: sudo systemctl enable --now kai-app kai-worker"

deploy: container-build container-install quadlet ## Build the image, copy it to root storage, and install Quadlet units
