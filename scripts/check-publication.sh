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
		0.*|10.*|127.*|169.254.*|192.168.*|192.0.2.*|198.51.100.*|203.0.113.*|1.1.1.1|9.9.9.9) return 0 ;;
		172.*)
			second=${ip#172.}
			second=${second%%.*}
			[ "$second" -ge 16 ] 2>/dev/null && [ "$second" -le 31 ] 2>/dev/null && return 0
			;;
	esac
	grep -Fxq "$ip" "$allowlist"
}

is_allowed_host() {
	host=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
	case "$host" in
		*.example.com|*.example.net|*.example.org|example.com|example.net|example.org|*.internal|*.test|localhost) return 0 ;;
	esac
	grep -Fxq "$host" "$allowlist"
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

check_addresses() {
	ref=$1
	if [ -n "$ref" ]; then
		candidates=$(git grep -n -I -z -e '' "$ref" -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' 2>/dev/null | extract_address_candidates)
	else
		candidates=$(git grep -n -I -z -e '' -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' 2>/dev/null | extract_address_candidates)
	fi
	bad=0
	while IFS='|' read -r value line; do
		[ -n "$value" ] || continue
		is_non_network_literal "$value" && continue
		case "$value" in
			*[!0-9.]* )
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
	done <<EOF
$candidates
EOF
	[ "$bad" -eq 0 ]
}

package_lock_paths() {
	ref=$1
	if [ -n "$ref" ]; then
		git ls-tree -r --name-only "$ref" | grep -E '(^|/)package-lock\.json$' || true
	else
		git ls-files | grep -E '(^|/)package-lock\.json$' || true
	fi
}

check_package_locks() {
	ref=$1
	if ! command -v node >/dev/null 2>&1; then
		echo "The node executable is required to validate tracked package-lock.json files." >&2
		return 1
	fi

	locks=$(package_lock_paths "$ref")
	[ -n "$locks" ] || return 0
	failed=0
	while IFS= read -r lock; do
		[ -n "$lock" ] || continue
		if [ -n "$ref" ]; then
			if ! git show "$ref:$lock" | node "$script_dir/validate-package-lock.mjs" "$lock"; then
				failed=1
			fi
		elif ! node "$script_dir/validate-package-lock.mjs" "$lock" <"$lock"; then
			failed=1
		fi
	done <<EOF
$locks
EOF
	[ "$failed" -eq 0 ]
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
