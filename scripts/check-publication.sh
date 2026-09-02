#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
allowlist="$script_dir/publication-allowlist.txt"
schema="$script_dir/../site/src/data/config-schema.json"
schema_checker="$script_dir/../site/scripts/extract-config-schema.mjs"
active_allowlist=$(cat "$allowlist")
publication_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/vpn-hub-publication.XXXXXX")
trap 'rm -rf -- "$publication_tmp_dir"' EXIT HUP INT TERM

check_schema_inventory() {
	if [ ! -e "$schema" ] && [ ! -e "$schema_checker" ]; then
		return 0
	fi
	if [ ! -f "$schema" ] || [ -L "$schema" ] || [ ! -f "$schema_checker" ] || [ -L "$schema_checker" ]; then
		echo "configuration schema and checker must both be regular non-symlink files" >&2
		return 1
	fi
	(cd "$script_dir/../site" && node scripts/extract-config-schema.mjs --check)
}

report_matches() {
	label=$1
	pattern=$2
	ref=$3
	if [ -n "$ref" ]; then
		if matches=$(git grep -nE "$pattern" "$ref" -- ':!scripts/check-publication_test.sh' 2>/dev/null); then
			:
		else
			grep_status=$?
			[ "$grep_status" -eq 1 ] || {
				echo "$label scan failed for $ref" >&2
				return 1
			}
			matches=
		fi
		if [ -n "$matches" ]; then
			echo "$label detected:" >&2
			printf '%s\n' "$matches" >&2
			return 1
		fi
		return 0
	fi
	if index_matches=$(git grep --cached -nE "$pattern" -- ':!scripts/check-publication_test.sh' 2>/dev/null); then
		:
	else
		grep_status=$?
		[ "$grep_status" -eq 1 ] || {
			echo "$label index scan failed" >&2
			return 1
		}
		index_matches=
	fi
	if worktree_matches=$(git grep -nE "$pattern" -- ':!scripts/check-publication_test.sh' 2>/dev/null); then
		:
	else
		grep_status=$?
		[ "$grep_status" -eq 1 ] || {
			echo "$label worktree scan failed" >&2
			return 1
		}
		worktree_matches=
	fi
	if [ -z "$index_matches" ] && [ -z "$worktree_matches" ]; then
		return 0
	fi
	echo "$label detected:" >&2
	[ -z "$index_matches" ] || printf '%s\n' "$index_matches" | sed 's/^/[index] /' >&2
	while IFS= read -r match; do
		[ -n "$match" ] || continue
		if [ -n "$index_matches" ] && printf '%s\n' "$index_matches" | grep -Fqx -e "$match"; then
			continue
		fi
		printf '[worktree] %s\n' "$match" >&2
	done <<EOF
$worktree_matches
EOF
	return 1
}

is_allowed_ip() {
	ip=$1
	case "$ip" in
		0.*|10.*|127.*|169.254.*|192.168.*|192.0.2.*|198.51.100.*|203.0.113.*|1.1.1.1|9.9.9.9) return 0 ;;
		172.*)
			second=${ip#172.}
			second=${second%%.*}
			[ "$second" -ge 16 ] 2>/dev/null && [ "$second" -le 31 ] 2>/dev/null && return 0
			;;
	esac
	printf '%s\n' "$active_allowlist" | grep -Fxq "$ip"
}

is_allowed_host() {
	host=$(printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]')
	case "$host" in
		*.example.com|*.example.net|*.example.org|example.com|example.net|example.org|*.example|*.test|localhost) return 0 ;;
	esac
	printf '%s\n' "$active_allowlist" | grep -Fxq "$host"
}

extract_address_candidates() {
	node "$script_dir/check-publication-addresses.mjs" --schema "$schema"
}

check_text_sources() {
	ref=$1
	if [ -n "$ref" ]; then
		node "$script_dir/check-publication-addresses.mjs" --validate-text --ref "$ref"
	else
		node "$script_dir/check-publication-addresses.mjs" --validate-text
	fi
}

collect_address_records() {
	ref=$1
	scope=$2
	output=$3
	if [ -n "$ref" ]; then
		if git grep -n -z -e '' "$ref" -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' >"$output" 2>/dev/null; then
			return 0
		else
			grep_status=$?
		fi
	else
		if [ "$scope" = index ]; then
			if git grep --cached -n -z -e '' -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' >"$output" 2>/dev/null; then
				return 0
			else
				grep_status=$?
			fi
		else
			if git grep -n -z -e '' -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' >"$output" 2>/dev/null; then
				return 0
			else
				grep_status=$?
			fi
		fi
	fi
	if [ "$grep_status" -eq 1 ]; then
		: >"$output"
		return 0
	fi
	echo "address $scope scan failed${ref:+ for $ref}" >&2
	return 1
}

extract_address_file() {
	input=$1
	output=$2
	if extract_address_candidates <"$input" >"$output"; then
		return 0
	fi
	echo "address candidate classification failed" >&2
	return 1
}

report_address_candidates() {
	scope=$1
	candidate_lines=$2
	skip_lines=$3
	if [ -n "$skip_lines" ]; then
		candidate_lines=$(
			{
				printf '%s\n' "$skip_lines"
				printf '%s\n' '__VPN_HUB_PUBLICATION_SOURCE_BOUNDARY__'
				printf '%s\n' "$candidate_lines"
			} | awk '
				$0 == "__VPN_HUB_PUBLICATION_SOURCE_BOUNDARY__" { worktree = 1; next }
				!worktree { seen[$0] = 1; next }
				!seen[$0]
			'
		)
	fi
	candidate_bad=0
	while IFS= read -r candidate; do
		[ -n "$candidate" ] || continue
		value=${candidate%%|*}
		line=${candidate#*|}
		case "$value" in
			*[!0-9.]* )
				if ! is_allowed_host "$value"; then
					if [ -n "$scope" ]; then
						echo "unreviewed public hostname $value [$scope]: $line" >&2
					else
						echo "unreviewed public hostname $value: $line" >&2
					fi
					candidate_bad=1
				fi
				;;
			*)
				if ! is_allowed_ip "$value"; then
					if [ -n "$scope" ]; then
						echo "unreviewed public IPv4 $value [$scope]: $line" >&2
					else
						echo "unreviewed public IPv4 $value: $line" >&2
					fi
					candidate_bad=1
				fi
				;;
		esac
	done <<EOF
$candidate_lines
EOF
	[ "$candidate_bad" -eq 0 ]
}

check_addresses() {
	ref=$1
	if [ -n "$ref" ]; then
		collect_address_records "$ref" history "$publication_tmp_dir/history.records" || return 1
		extract_address_file "$publication_tmp_dir/history.records" "$publication_tmp_dir/history.candidates" || return 1
		candidates=$(cat "$publication_tmp_dir/history.candidates")
		report_address_candidates '' "$candidates" ''
		return
	fi
	collect_address_records '' index "$publication_tmp_dir/index.records" || return 1
	collect_address_records '' worktree "$publication_tmp_dir/worktree.records" || return 1
	extract_address_file "$publication_tmp_dir/index.records" "$publication_tmp_dir/index.candidates" || return 1
	extract_address_file "$publication_tmp_dir/worktree.records" "$publication_tmp_dir/worktree.candidates" || return 1
	index_candidates=$(cat "$publication_tmp_dir/index.candidates")
	worktree_candidates=$(cat "$publication_tmp_dir/worktree.candidates")
	address_failed=0
	report_address_candidates index "$index_candidates" '' || address_failed=1
	report_address_candidates worktree "$worktree_candidates" "$index_candidates" || address_failed=1
	[ "$address_failed" -eq 0 ]
}

check_package_locks() {
	ref=$1
	if ! command -v node >/dev/null 2>&1; then
		echo "The node executable is required to validate tracked package-lock files." >&2
		return 1
	fi
	if [ -n "$ref" ]; then
		node "$script_dir/check-package-locks.mjs" --ref "$ref"
	else
		node "$script_dir/check-package-locks.mjs"
	fi
}

check_ref() {
	ref=$1
	ref_failed=0
	check_text_sources "$ref" || ref_failed=1
	report_matches 'private key' '(client_private_key|private_key)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9+/]{42,}={0,2}' "$ref" || ref_failed=1
	report_matches 'Telegram bot token' '[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}' "$ref" || ref_failed=1
	report_matches 'runtime state document' '"revision"[^}]*"hub"[[:space:]]*:' "$ref" || ref_failed=1
	if [ -n "$ref" ]; then
		if matches=$(git ls-tree -r --name-only "$ref" | grep -E '(^|/)(state|device-profiles|backups?)/|desired-state\.json$'); then
			echo "runtime state detected in $ref:" >&2
			printf '%s\n' "$matches" >&2
			ref_failed=1
		fi
	else
		if matches=$(git ls-files | grep -E '(^|/)(state|device-profiles|backups?)/|desired-state\.json$'); then
			echo "runtime state detected:" >&2
			printf '%s\n' "$matches" >&2
			ref_failed=1
		fi
	fi
	if check_package_locks "$ref"; then
		check_addresses "$ref" || ref_failed=1
	else
		ref_failed=1
	fi
	[ "$ref_failed" -eq 0 ]
}

history=0
case "${1:-}" in
	'') ;;
	--history) history=1 ;;
	*) echo "usage: $0 [--history]" >&2; exit 2 ;;
esac

publication_failed=0
check_schema_inventory || publication_failed=1
check_ref '' || publication_failed=1

if [ "$history" -eq 1 ]; then
	for commit in $(git rev-list --all); do
		check_ref "$commit" || publication_failed=1
		email=$(git show -s --format=%ae "$commit")
		domain=${email##*@}
		if [ "$domain" != users.noreply.github.com ]; then
			echo "unreviewed author email in $commit: $email" >&2
			publication_failed=1
		fi
		if git show -s --format=%B "$commit" | grep -iE '(co-authored-by:.*(assistant|copilot|chatgpt|claude)|generated-by:|ai-assisted)'; then
			echo "assistant attribution trailer in $commit" >&2
			publication_failed=1
		fi
	done
fi

exit "$publication_failed"
