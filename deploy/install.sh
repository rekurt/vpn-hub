#!/bin/sh
# Runs on the hub as root. Both deploy paths -- `make deploy-lab` and the deploy
# workflow -- stage binaries and unit files and then run this script, so the
# install procedure exists exactly once and cannot drift between them again: the
# workflow used to restart the agent without enabling it, so a hub deployed only
# through CI silently lost its agent on the first reboot.
#
# Contract: binaries at $STAGE/, unit files at $STAGE/systemd/. Binaries install
# if present -- a rollback artifact may predate the bot. Unit files install by
# glob, so a new unit ships by being staged, not by editing this script.
set -eu

STAGE="${STAGE:-/run/vpn-hub-stage}"

for binary in hubctl vpn-hub-agent vpn-hub-bot; do
	if [ -f "$STAGE/$binary" ]; then
		install -m 0755 "$STAGE/$binary" /usr/local/bin/
	fi
done

# Guarded on the glob matching, not just the directory existing: an unexpanded
# `*` makes install fail, and under `set -e` that would abort the deploy after the
# binaries are already in place but before the agent is enabled and restarted.
set -- "$STAGE"/systemd/*
if [ -e "$1" ]; then
	install -m 0644 "$@" /etc/systemd/system/
fi

# Migration from units this repository no longer ships. The subscription timer's
# job lives in the bot's own scheduler (hubctl subscription refresh remains the
# SSH fallback); the 443 fallbacks live in the reconciled ruleset and a transient
# unit, gated by hub.fallback in hub.yaml. Drop these lines once every host has
# taken one deploy past them.
# `systemctl stop` expands a glob over loaded units; `systemctl disable` does not
# -- it mangles the `*` into a literal instance name and quietly does nothing. So
# the enablement symlinks go by hand, or a real instance would keep its dangling
# symlink and a not-found unit after the template below is deleted.
systemctl stop 'vpn-hub-subscription@*.timer' >/dev/null 2>&1 || true
rm -f /etc/systemd/system/timers.target.wants/vpn-hub-subscription@*.timer
systemctl disable --now vpn-hub-alt-udp443.service vpn-hub-vless-reality.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/vpn-hub-subscription@.service \
	/etc/systemd/system/vpn-hub-subscription@.timer \
	/etc/systemd/system/vpn-hub-alt-udp443.service \
	/etc/systemd/system/vpn-hub-vless-reality.service \
	/etc/vpn-hub/vpn-hub-alt-udp443.nft
# The retired listener's configuration holds a REALITY private key and a UUID per
# device. A secret must not outlive the thing that justified it.
rm -rf /etc/vpn-hub/vless-reality
nft delete table ip vpn_hub_alt_udp443 2>/dev/null || true

systemctl daemon-reload
systemctl enable --now vpn-hub-agent
systemctl restart vpn-hub-agent

# The bot starts only where its config and binary exist: a host without a token
# must not grow a crash-looping unit.
if [ -f /etc/vpn-hub/telegram.yaml ] && [ -x /usr/local/bin/vpn-hub-bot ]; then
	systemctl enable --now vpn-hub-bot
	systemctl restart vpn-hub-bot
else
	echo "no /etc/vpn-hub/telegram.yaml or no bot binary; vpn-hub-bot not enabled"
fi

rm -rf "$STAGE"
