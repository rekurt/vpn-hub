SHELL := /bin/bash

TF_DIR := deploy/terraform
TF     := tofu -chdir=$(TF_DIR)

LAB_IP = $(shell $(TF) output -raw ipv4 2>/dev/null)
SSH    = ssh -o StrictHostKeyChecking=accept-new root@$(LAB_IP)

# Evaluated only for the targets that talk to DigitalOcean.
STAND_TARGETS := stand-init stand-plan stand-up stand-down stand-ip
$(STAND_TARGETS): export TF_VAR_do_token = $(shell $(TF_DIR)/do-token.sh)

.DEFAULT_GOAL := help

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'

## fmt: format Go sources and Terraform files
fmt:
	gofmt -w .
	$(TF) fmt

## lint: report formatting and vet problems
lint:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go vet ./...
	# Build-tagged files are invisible to the plain vet, and CI checks them.
	go vet -tags=integration ./...

## test: run the unit suite with the race detector
test:
	go test -race ./...

## publication-check: reject secrets and runtime state before publishing
publication-check:
	sh scripts/check-publication.sh
	sh scripts/check-publication_test.sh

## test-integration: drive real interfaces, rules and traffic (Linux, needs root)
# Stop any running agent first: it reconciles on a timer and will restore its own
# ruleset over the one under test.
test-integration:
	sudo -E env "PATH=$$PATH" go test -tags=integration -count=1 -timeout 15m ./internal/adapters/linux/

## test-integration-box: the same suite in a throwaway container (works off Linux)
# For a workstation that is not the Linux host those tests need. Same suite, same
# sing-box, same systemd. Extra arguments reach go test: make test-integration-box
# ARGS='-run Reality'.
test-integration-box:
	deploy/testbox/run.sh $(ARGS)

## ci: run what CI runs, locally -- everything but the integration job
# Worth having on its own: the four jobs are spread across a workflow file, and
# finding out which of them a change breaks should not require pushing.
ci: lint golangci terraform-check test build-linux
	@echo "build, lint and terraform pass locally; integration is make test-integration-box"

## golangci: the linter CI runs, with the repository's own configuration
golangci:
	golangci-lint run

## terraform-check: formatting and validation, as the terraform job does them
terraform-check:
	$(TF) fmt -check -diff
	# Validation contacts no provider API, so this needs no credentials.
	$(TF) init -backend=false
	$(TF) validate

## build: build both binaries for the host platform
build:
	go build -o bin/ ./cmd/...

## build-linux: cross-compile both binaries for the hub
build-linux:
	GOOS=linux GOARCH=amd64 go build -trimpath -o bin/linux/ ./cmd/...

## stand-init: download the DigitalOcean provider
stand-init:
	$(TF) init

## stand-plan: show what would change on the lab host
stand-plan:
	$(TF) plan

## stand-up: create or update the lab host (this costs money)
stand-up:
	$(TF) apply -auto-approve
	@echo "waiting for cloud-init to finish (AmneziaWG builds via DKMS, this takes a few minutes)"
	@until $(SSH) 'cloud-init status --wait' 2>/dev/null; do sleep 10; done

## stand-ip: print the lab host address
stand-ip:
	@$(TF) output -raw ipv4

## stand-down: destroy the lab host
stand-down:
	$(TF) destroy -auto-approve

## deploy-lab: install binaries and the systemd units onto the lab host
# Binaries land in a staging directory first: scp cannot write over a running
# executable (ETXTBSY), whereas `install` replaces the directory entry and leaves the
# running process on the old inode until it restarts. The procedure itself is
# deploy/install.sh -- the same script the deploy workflow runs, so the two paths
# cannot drift.
deploy-lab: build-linux
	@test -n "$(LAB_IP)" || { echo "no lab host; run make stand-up"; exit 1; }
	$(SSH) 'rm -rf /run/vpn-hub-stage && mkdir -p /run/vpn-hub-stage/systemd'
	scp bin/linux/hubctl bin/linux/vpn-hub-agent bin/linux/vpn-hub-bot deploy/install.sh root@$(LAB_IP):/run/vpn-hub-stage/
	scp deploy/systemd/vpn-hub-agent.service deploy/systemd/vpn-hub-bot.service root@$(LAB_IP):/run/vpn-hub-stage/systemd/
	$(SSH) 'sh /run/vpn-hub-stage/install.sh'

## ssh: open a shell on the lab host
ssh:
	$(SSH)

## logs: follow the agent journal on the lab host
logs:
	$(SSH) 'journalctl -u vpn-hub-agent -f'

## logs-bot: follow the bot journal on the lab host
logs-bot:
	$(SSH) 'journalctl -u vpn-hub-bot -f'

.PHONY: help fmt lint test test-integration test-integration-box ci golangci terraform-check build build-linux $(STAND_TARGETS) deploy-lab ssh logs logs-bot
