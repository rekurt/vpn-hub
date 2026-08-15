#!/usr/bin/env bash
# Run the integration suite in a throwaway container.
#
#   deploy/testbox/run.sh [go-test-args...]
#
# For workstations that are not the Linux host those tests need -- they build real
# interfaces and load a real ruleset, and there is no version of that which is
# polite to the machine you are typing on. What runs inside is the same suite, the
# same sing-box and the same systemd the hub has.
#
# A fresh container every time, deliberately: the suite takes ownership of the
# host's networking and removes the default route on its way through, so reusing
# one would make every later run measure the damage from the earlier one.
set -euo pipefail

cd "$(dirname "$0")/../.."
name="vpn-hub-testbox"
image="vpn-hub-testbox"

docker build -q -t "$image" deploy/testbox >/dev/null
docker rm -f "$name" >/dev/null 2>&1 || true
# --privileged and the host cgroup namespace: systemd as PID 1 needs both, and so
# does anything that creates network namespaces and loads nftables rules.
docker run -d --name "$name" --privileged --cgroupns=host \
	-v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
	-v "$PWD":/src:ro "$image" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

# Waited on by state, not by exit status. `is-system-running` exits non-zero for
# anything short of "fully running", and `degraded` -- systemd's word for "booted,
# with a unit that failed" -- is among those. A box that grows one failing unit
# would otherwise spin here for the whole minute and then carry on regardless,
# which is the second half of the problem: the loop had no way to say it gave up,
# so a systemd that never came up surfaced as confusing errors from the commands
# after it rather than as "systemd never came up".
state=
for _ in $(seq 60); do
	state=$(docker exec "$name" systemctl is-system-running 2>&1 || true)
	case "$state" in
	running | degraded) break ;;
	esac
	sleep 1
done
case "$state" in
running) ;;
degraded)
	# Usable, and worth naming: the failed unit is rarely the hub's, but a suite
	# that behaves oddly afterwards should not be the first hint that it exists.
	echo "note: the box booted degraded; failed units:" >&2
	docker exec "$name" systemctl list-units --state=failed --no-legend --no-pager >&2 || true
	;;
*)
	echo "systemd did not come up in the box (last state: ${state:-none})" >&2
	docker logs --tail 20 "$name" >&2 || true
	exit 1
	;;
esac

# Copied out of the read-only mount: the suite writes beside the sources, and the
# host's own tree is not its to touch.
docker exec "$name" sh -c '
set -e
cp -r /src /work && cd /work && rm -rf .git
sysctl -qw net.ipv4.ip_forward=1
# Loose reverse-path filtering, the setting cloud-init gives a real hub. Policy
# routing sends a reply back through an interface the main table does not name,
# and strict filtering drops it.
sysctl -qw net.ipv4.conf.all.rp_filter=2
sysctl -qw net.ipv4.conf.default.rp_filter=2
# Docker sets the iptables FORWARD policy to DROP, and netfilter runs every chain
# registered on a hook -- so that DROP would kill forwarded packets whatever the
# hub table accepts.
iptables -P FORWARD ACCEPT 2>/dev/null || true
' >/dev/null

log=/tmp/vpn-hub-testbox.log

# -v so a scenario that skipped itself is visible: a skip reads as a pass in the
# summary, and a test skipped for a missing binary has never run at all. The
# summary lines are what reaches the terminal; the whole log stays in the file.
#
# The verdict is go test's own exit status, taken through PIPESTATUS. Grepping the
# output for failures instead would call a suite that did not compile a pass --
# there are no "--- FAIL" lines when nothing ran.
set +e
docker exec "$name" sh -c \
	'cd /work && go test -tags=integration -count=1 -timeout 15m -v "$@" ./internal/adapters/linux/ 2>&1' \
	_ "$@" | tee "$log" | grep -E "^(--- (PASS|FAIL|SKIP)|ok|FAIL|PASS)"
status=${PIPESTATUS[0]}
set -e

echo
echo "full output: $log"

# A scenario that skipped because a package is missing has never run, and a skip
# reads as a pass in the summary -- so a box missing what the tests need is a
# failure, not a quiet note. Skips for an unreachable network are left alone:
# those say something about connectivity, and the suite removes its own default
# route on the way through, so later scenarios skip by design. Run a subset with
# -run to see them.
if grep -q "is not installed" "$log"; then
	echo "the box is missing something the tests need:" >&2
	grep "is not installed" "$log" >&2
	exit 1
fi
exit "$status"
