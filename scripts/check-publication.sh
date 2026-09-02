#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
allowlist="$script_dir/publication-allowlist.txt"
active_allowlist=$(cat "$allowlist")
report_matches() {
	label=$1
	pattern=$2
	ref=$3
	if [ -n "$ref" ]; then
		matches=$(git grep -nE "$pattern" "$ref" -- ':!scripts/check-publication_test.sh' 2>/dev/null) || return 0
		if [ -n "$matches" ]; then
			echo "$label detected:" >&2
			printf '%s\n' "$matches" >&2
			return 1
		fi
	else
		index_matches=$(git grep --cached -nE "$pattern" -- ':!scripts/check-publication_test.sh' 2>/dev/null) || index_matches=
		worktree_matches=$(git grep -nE "$pattern" -- ':!scripts/check-publication_test.sh' 2>/dev/null) || worktree_matches=
		if [ -n "$index_matches" ] || [ -n "$worktree_matches" ]; then
			echo "$label detected:" >&2
			if [ -n "$index_matches" ]; then
				printf '%s\n' "$index_matches" | sed 's/^/[index] /' >&2
			fi
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
		fi
	fi
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
	host=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
	case "$host" in
		*.example.com|*.example.net|*.example.org|example.com|example.net|example.org|*.internal|*.test|localhost) return 0 ;;
	esac
	printf '%s\n' "$active_allowlist" | grep -Fxq "$host"
}

is_non_network_literal() {
	# These tracked file names match the DNS grammar but cannot be hostnames.
	case "$1" in
		99-vpn-hub.conf|2026-09-01-publication-security-hardening.md|0-release-evidence.md) return 0 ;;
	esac
	return 1
}

extract_address_candidates() {
	perl -ne '
		BEGIN { $state = "code"; $current_path = ""; }

		sub go_text {
			my ($line) = @_;
			my $text = "";
			my $length = length $line;
			my $offset = 0;

			while ($offset < $length) {
				my $char = substr $line, $offset, 1;
				my $pair = substr $line, $offset, 2;
				if ($state eq "raw") {
					if ($char eq "`") {
						$state = "code";
						$text .= " ";
					} else {
						$text .= $char;
					}
					$offset++;
					next;
				}
				if ($state eq "block") {
					if ($pair eq "*/") {
						$state = "code";
						$text .= " ";
						$offset += 2;
					} else {
						$text .= $char;
						$offset++;
					}
					next;
				}
				if ($state eq "quoted") {
					if ($char eq "\\" && $offset + 1 < $length) {
						$text .= substr $line, $offset, 2;
						$offset += 2;
					} elsif ($char eq "\"") {
						$state = "code";
						$text .= " ";
						$offset++;
					} else {
						$text .= $char;
						$offset++;
					}
					next;
				}
				if ($state eq "rune") {
					if ($char eq "\\" && $offset + 1 < $length) {
						$offset += 2;
					} elsif ($char eq "\x27") {
						$state = "code";
						$offset++;
					} else {
						$offset++;
					}
					next;
				}

				if ($pair eq "//") {
					$text .= " " . substr($line, $offset + 2);
					last;
				}
				if ($pair eq "/*") {
					$state = "block";
					$text .= " ";
					$offset += 2;
					next;
				}
				if ($char eq "\"") {
					$state = "quoted";
					$text .= " ";
				} elsif ($char eq "`") {
					$state = "raw";
					$text .= " ";
				} elsif ($char eq "\x27") {
					$state = "rune";
				}
				$offset++;
			}

			$state = "code" if $state eq "quoted" || $state eq "rune";
			return $text;
		}

		chomp;
		next unless /^([^\0]+)\0([0-9]+)\0(.*)$/s;
		my ($path, $number, $content) = ($1, $2, $3);
		next if $path =~ m{(?:^|/)package-lock\.json$};
		if ($path ne $current_path) {
			$state = "code";
			$current_path = $path;
		}
		my $text = $path =~ /\.go$/ ? go_text($content) : $content;
		while ($text =~ /(?<![A-Za-z0-9_-])((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,})(?![A-Za-z0-9_-])/g) {
			print "$1|$path:$number:$content\n";
		}
	'
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
		is_non_network_literal "$value" && continue
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
		candidates=$(git grep -n -I -z -e '' "$ref" -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' 2>/dev/null | extract_address_candidates)
		report_address_candidates '' "$candidates" ''
	else
		index_candidates=$(git grep --cached -n -I -z -e '' -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' 2>/dev/null | extract_address_candidates)
		worktree_candidates=$(git grep -n -I -z -e '' -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' 2>/dev/null | extract_address_candidates)
		address_failed=0
		report_address_candidates index "$index_candidates" '' || address_failed=1
		report_address_candidates worktree "$worktree_candidates" "$index_candidates" || address_failed=1
		[ "$address_failed" -eq 0 ]
	fi
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
	if check_package_locks "$ref"; then
		check_addresses "$ref" || failed=1
	else
		failed=1
	fi
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
