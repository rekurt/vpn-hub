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

## test: run the unit suite with the race detector
test:
	go test -race ./...

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

## deploy-lab: install binaries and the systemd unit onto the lab host
deploy-lab: build-linux
	@test -n "$(LAB_IP)" || { echo "no lab host; run make stand-up"; exit 1; }
	scp bin/linux/hubctl bin/linux/vpn-hub-agent root@$(LAB_IP):/usr/local/bin/
	scp deploy/systemd/vpn-hub-agent.service root@$(LAB_IP):/etc/systemd/system/
	$(SSH) 'systemctl daemon-reload && systemctl enable --now vpn-hub-agent'

## ssh: open a shell on the lab host
ssh:
	$(SSH)

## logs: follow the agent journal on the lab host
logs:
	$(SSH) 'journalctl -u vpn-hub-agent -f'

.PHONY: help fmt lint test build build-linux $(STAND_TARGETS) deploy-lab ssh logs
