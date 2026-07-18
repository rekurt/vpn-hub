SHELL := /bin/bash

# Lab droplet parameters. Override on the command line, e.g. `make stand-up REGION=ams3`.
DROPLET ?= vpn-hub-lab
REGION  ?= fra1
SIZE    ?= s-1vcpu-1gb
IMAGE   ?= debian-12-x64
SSH_PUB ?= $(HOME)/.ssh/id_ed25519.pub

# DigitalOcean identifies SSH keys by their MD5 fingerprint.
SSH_FP = $(shell ssh-keygen -E md5 -lf $(SSH_PUB) | awk '{print $$2}' | sed 's/^MD5://')
LAB_IP = $(shell doctl compute droplet get $(DROPLET) --format PublicIPv4 --no-header 2>/dev/null)
SSH    = ssh -o StrictHostKeyChecking=accept-new root@$(LAB_IP)

.DEFAULT_GOAL := help

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'

## fmt: format sources
fmt:
	gofmt -w .

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

## stand-key: register $(SSH_PUB) with DigitalOcean if it is not there yet
stand-key:
	@doctl compute ssh-key list --format FingerPrint --no-header | grep -qx '$(SSH_FP)' || \
		doctl compute ssh-key import $(DROPLET) --public-key-file $(SSH_PUB)

## stand-up: create the lab droplet (this costs money)
stand-up: stand-key
	doctl compute droplet create $(DROPLET) \
		--image $(IMAGE) --size $(SIZE) --region $(REGION) \
		--ssh-keys $(SSH_FP) --wait --format ID,Name,PublicIPv4

## stand-ip: print the lab droplet public address
stand-ip:
	@echo $(LAB_IP)

## stand-down: destroy the lab droplet
stand-down:
	doctl compute droplet delete $(DROPLET) --force

## deploy-lab: install binaries, unit and tmpfiles rule onto the lab droplet
deploy-lab: build-linux
	@test -n "$(LAB_IP)" || { echo "no droplet named $(DROPLET); run make stand-up"; exit 1; }
	scp bin/linux/hubctl bin/linux/vpn-hub-agent root@$(LAB_IP):/usr/local/bin/
	scp deploy/systemd/vpn-hub-agent.service root@$(LAB_IP):/etc/systemd/system/
	scp deploy/tmpfiles/vpn-hub.conf root@$(LAB_IP):/usr/lib/tmpfiles.d/
	$(SSH) 'systemd-tmpfiles --create && systemctl daemon-reload && systemctl enable --now vpn-hub-agent'

## ssh: open a shell on the lab droplet
ssh:
	$(SSH)

## logs: follow the agent journal on the lab droplet
logs:
	$(SSH) 'journalctl -u vpn-hub-agent -f'

.PHONY: help fmt lint test build build-linux stand-key stand-up stand-ip stand-down deploy-lab ssh logs
