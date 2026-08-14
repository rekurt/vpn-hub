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

# An artifact that ships no bot means this host runs no bot. The rollback path
# reaches for a build that predates it, and leaving the newer binary installed
# would have it started again beside a rolled-back agent -- mixing the versions
# the rollback exists to separate.
#
# Removed, not merely disabled. The presence of this binary is what every other
# step reads as "this hub has a bot", including the deploy workflow's own
# verification, so a disabled unit beside an executable that is still there
# leaves the two disagreeing. One rule instead: the artifact decides. Rolling
# forward reinstalls it in one deploy.
staged_bot=yes
[ -f "$STAGE/vpn-hub-bot" ] || staged_bot=no

if [ "$staged_bot" = no ] && [ -x /usr/local/bin/vpn-hub-bot ]; then
	echo "this artifact ships no bot; removing the one already installed"
	# The stop has to work before the binary is unlinked. A process keeps running
	# from its open inode, so a timed-out stop would leave the newer bot editing
	# configuration beside a rolled-back agent -- the exact version mixing this
	# removal exists to prevent -- while the deploy reported success. Only "there
	# is no such unit" is tolerated; systemd says so with exit 5 and those words.
	if ! stop_output=$(systemctl stop vpn-hub-bot 2>&1) &&
		! echo "$stop_output" | grep -q "not loaded"; then
		echo "cannot stop the installed bot, so its binary is left alone: $stop_output" >&2
		exit 1
	fi
	# The enablement symlink is bookkeeping: a unit whose binary is gone cannot
	# start, so failing here is not worth aborting a deploy over.
	systemctl disable vpn-hub-bot >/dev/null 2>&1 || true
	rm -f /usr/local/bin/vpn-hub-bot
fi

# Guarded on the glob matching, not just the directory existing: an unexpanded
# `*` makes install fail, and under `set -e` that would abort the deploy after the
# binaries are already in place but before the agent is enabled and restarted.
set -- "$STAGE"/systemd/*
if [ -e "$1" ]; then
	install -m 0644 "$@" /etc/systemd/system/
fi

# Migration from units this repository no longer ships. The 443 fallbacks live in
# the reconciled ruleset and a transient unit now, gated by hub.fallback in
# hub.yaml. Drop these lines once every host has taken one deploy past them.
# Stopped before their files are deleted, and the stop has to work. The retired
# REALITY listener holds TCP/443 with a device list of its own: left running, it
# would keep admitting devices this revision removed and would also stop the
# reconciled listener from binding the port -- while the deploy reported success
# and its configuration, key included, was already gone from disk.
for retired in vpn-hub-alt-udp443 vpn-hub-vless-reality; do
	if ! stop_output=$(systemctl stop "$retired.service" 2>&1) &&
		! echo "$stop_output" | grep -q "not loaded"; then
		echo "cannot stop the retired $retired, so its files are left alone: $stop_output" >&2
		exit 1
	fi
	systemctl disable "$retired.service" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/vpn-hub-alt-udp443.service \
	/etc/systemd/system/vpn-hub-vless-reality.service \
	/etc/vpn-hub/vpn-hub-alt-udp443.nft

# Whether a bot will actually be running when this script finishes -- which is
# not the same as whether the artifact shipped one. A host with no telegram.yaml
# gets the binary and no scheduler, and that is the condition the timer has to
# answer to as well.
bot_will_run=no
if [ "$staged_bot" = yes ] && [ -f /etc/vpn-hub/telegram.yaml ] && [ -x /usr/local/bin/vpn-hub-bot ]; then
	bot_will_run=yes
fi

# The subscription timer goes only when something replaces it. Its job moved into
# the bot's scheduler, so removing it where no bot will run leaves a host with
# neither, and subscriptions quietly stop refreshing -- on the rollback path this
# script exists to support, and equally on a hub that simply has no bot token.
#
# `systemctl stop` expands a glob over loaded units; `systemctl disable` does not
# -- it mangles the `*` into a literal instance name and quietly does nothing. So
# the enablement symlinks go by hand, or a real instance would keep its dangling
# symlink and a not-found unit after the template is deleted.
if [ "$bot_will_run" = yes ]; then
	systemctl stop 'vpn-hub-subscription@*.timer' >/dev/null 2>&1 || true
	rm -f /etc/systemd/system/timers.target.wants/vpn-hub-subscription@*.timer
	rm -f /etc/systemd/system/vpn-hub-subscription@.service \
		/etc/systemd/system/vpn-hub-subscription@.timer
elif ! ls /etc/systemd/system/timers.target.wants/vpn-hub-subscription@*.timer >/dev/null 2>&1; then
	# Asked of the enablement symlinks rather than the template, because the
	# template alone never scheduled anything: enabling an instance per tunnel was
	# always an operator's step, which is also why this script cannot put the
	# schedule back by itself -- it would have to know the tunnels.
	echo "warning: no bot will run here and no subscription timer is enabled." >&2
	echo "         Nothing refreshes subscriptions on a schedule. Either run" >&2
	echo "         'hubctl subscription refresh <tunnel>' when a provider rotates," >&2
	echo "         or enable a timer per subscription tunnel." >&2
fi
# The retired listener's configuration holds a REALITY private key and a UUID per
# device. A secret must not outlive the thing that justified it.
rm -rf /etc/vpn-hub/vless-reality
nft delete table ip vpn_hub_alt_udp443 2>/dev/null || true

systemctl daemon-reload
systemctl enable --now vpn-hub-agent
systemctl restart vpn-hub-agent

# The same condition the timer answered to, asked once and used twice: a host
# without a token must not grow a crash-looping unit, and whatever decides that
# has to be what decides whether the timer it replaces may go.
if [ "$bot_will_run" = yes ]; then
	systemctl enable --now vpn-hub-bot
	systemctl restart vpn-hub-bot
else
	echo "no /etc/vpn-hub/telegram.yaml or no bot binary; vpn-hub-bot not enabled"
fi

rm -rf "$STAGE"
