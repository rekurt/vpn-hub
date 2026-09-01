#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
allowlist="$script_dir/publication-allowlist.txt"
report_matches() {
	label=$1
	pattern=$2
	ref=$3
	if [ -n "$ref" ]; then
		matches=$(git grep -nE "$pattern" "$ref" -- ':!scripts/check-publication_test.sh' 2>/dev/null) || return 0
	else
		matches=$(git grep -nE "$pattern" -- ':!scripts/check-publication_test.sh' 2>/dev/null) || return 0
	fi
	if [ -n "$matches" ]; then
		echo "$label detected:" >&2
		printf '%s\n' "$matches" >&2
		return 1
	fi
}

is_allowed_ip() {
	ip=$1
	case "$ip" in
		0.*|10.*|127.*|169.254.*|192.168.*|192.0.2.*|198.51.100.*|203.0.113.*|255.255.255.*|1.1.1.1|9.9.9.9) return 0 ;;
		172.*)
			second=${ip#172.}
			second=${second%%.*}
			[ "$second" -ge 16 ] 2>/dev/null && [ "$second" -le 31 ] 2>/dev/null && return 0
			;;
	esac
	grep -Fxq "$ip" "$allowlist"
}

is_allowed_host() {
	host=$1
	case "$host" in
		*.example.com|*.example.net|*.example.org|example.com|example.net|example.org|*.github.com) return 0 ;;
	esac
	grep -Fxq "$host" "$allowlist"
}

check_addresses() {
	ref=$1
	if [ -n "$ref" ]; then
		lines=$(git grep -nE '([0-9]{1,3}\.){3}[0-9]{1,3}|([[:alnum:]-]+\.)+(com|net|org|io)' "$ref" -- ':!scripts/check-publication_test.sh' 2>/dev/null || true)
	else
		lines=$(git grep -nE '([0-9]{1,3}\.){3}[0-9]{1,3}|([[:alnum:]-]+\.)+(com|net|org|io)' -- ':!scripts/check-publication_test.sh' 2>/dev/null || true)
	fi
	bad=0
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		if [ -n "$ref" ]; then
			content=${line#*:*:*:}
		else
			content=${line#*:*:}
		fi
		for value in $(printf '%s\n' "$content" | perl -nle 'while (/(?<![A-Za-z0-9_-])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_-])|(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]{2,}\.)+(?:com|net|org|io)(?![A-Za-z0-9_-])/g) { print $& }' || true); do
			case "$value" in
				*[!0-9.]* )
					case "$value" in *.internal|*.test|localhost) continue ;; esac
					if ! is_allowed_host "$value"; then
						echo "unreviewed public hostname $value: $line" >&2
						bad=1
					fi
					;;
				*)
					if ! is_allowed_ip "$value"; then
						echo "unreviewed public IPv4 $value: $line" >&2
						bad=1
					fi
					;;
			esac
		done
	done <<EOF
$lines
EOF
	[ "$bad" -eq 0 ]
}

check_ref() {
	ref=$1
	failed=0
	report_matches 'private key' '(client_private_key|private_key)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9+/]{42,}={0,2}' "$ref" || failed=1
	report_matches 'Telegram bot token' '[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}' "$ref" || failed=1
	report_matches 'runtime state document' '"revision"[^}]*"hub"[[:space:]]*:' "$ref" || failed=1
	if [ -n "$ref" ]; then
		if matches=$(git ls-tree -r --name-only "$ref" | grep -E '(^|/)(state|device-profiles|backups?)/|desired-state\.json$'); then
			echo "runtime state detected in $ref:" >&2
			printf '%s\n' "$matches" >&2
			failed=1
		fi
	else
		if matches=$(git ls-files | grep -E '(^|/)(state|device-profiles|backups?)/|desired-state\.json$'); then
			echo "runtime state detected:" >&2
			printf '%s\n' "$matches" >&2
			failed=1
		fi
	fi
	check_addresses "$ref" || failed=1
	[ "$failed" -eq 0 ]
}

history=0
case "${1:-}" in
	'') ;;
	--history) history=1 ;;
	*) echo "usage: $0 [--history]" >&2; exit 2 ;;
esac

failed=0
check_ref '' || failed=1

if [ "$history" -eq 1 ]; then
	for commit in $(git rev-list --all); do
		check_ref "$commit" || failed=1
		email=$(git show -s --format=%ae "$commit")
		domain=${email##*@}
		if [ "$domain" != users.noreply.github.com ]; then
			echo "unreviewed author email in $commit: $email" >&2
			failed=1
		fi
		if git show -s --format=%B "$commit" | grep -iE '(co-authored-by:.*(assistant|copilot|chatgpt|claude)|generated-by:|ai-assisted)'; then
			echo "assistant attribution trailer in $commit" >&2
			failed=1
		fi
	done
fi

exit "$failed"
