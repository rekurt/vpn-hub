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
	host=$(printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]')
	case "$host" in
		*.example.com|*.example.net|*.example.org|example.com|example.net|example.org|*.example|*.test|localhost) return 0 ;;
	esac
	printf '%s\n' "$active_allowlist" | grep -Fxq "$host"
}

is_non_network_literal() {
	value=$1
	evidence=$2
	tracked_names=$3
	case "$value" in
		Egress.Apply|DNS.Apply|sops-v*.linux|b.text|concurrency.group|main.version|http.server|hub.id|hub.endpoint|hub.dnsaddress|hub.fallback|hub.fallback.reality|hub.fallback.reality.enabled|source.kind|source.value|github.ref|github.token|net.ipv4.conf.*|net.ipv6.conf.*|Interface.DNS|Interface.MTU|Interface.PrivateKey|Interface.Address|Peer.PublicKey|Peer.Endpoint|Peer.PresharedKey|Peer.AllowedIPs|Peer.PersistentKeepalive) return 0 ;;
	esac
	content=${evidence#*:}
	content=${content#*:}
	before=${content%%"$value"*}
	after=${content#*"$value"}
	before=$(printf '%s' "$before" | perl -0777 -pe '$_ = substr($_, -80) if length($_) > 80')
	after=$(printf '%s' "$after" | perl -0777 -pe '$_ = substr($_, 0, 48) if length($_) > 48')
	surrounding=$before$after
	surrounding=$(printf '%s' "$surrounding" | LC_ALL=C tr '[:upper:]' '[:lower:]')
	network_context=0
	case "$surrounding" in
		*endpoint*|*hostname*|*url*|*dns*|*connect*|*address*|*contact*|*origin*|*server:*|*server\ =*|*server=*|*host:*|*host\ =*|*host=*) network_context=1 ;;
	esac
	filename_context=0
	case "$surrounding" in
		*file*|*path*|*config*|*source*|*output*|*archive*|*state*|*key*|*unit*|*systemd*|*artifact*|*install*|*write*|*read*|*stat*|*join*|*copy*|*remove*|*saved*|*mode*|*profile*|*credential*|*telegram*|*target*|*create*|*\`*|*'<code>'*|*'</code>'*) filename_context=1 ;;
	esac
	if [ -n "$tracked_names" ] && printf '%s\n' "$tracked_names" | grep -Fqx "$value"; then
		{ [ "$filename_context" -eq 1 ] || [ "$network_context" -eq 0 ]; } && return 0
	fi
	case "$value" in
		*.conf|*.yaml|*.yml|*.json|*.md|*.mdx|*.go|*.mjs|*.js|*.ts|*.astro|*.svg|*.css|*.txt|*.key|*.key.*|*.crt|*.csr|*.nft|*.service|*.target|*.sock|*.log|*.tfstate|*.tfvars|*.golden|*.link|*.hcl|*.sh|*.gz|*.binary|*.html|*.auth|*.ovpn)
			{ [ "$filename_context" -eq 1 ] || [ "$network_context" -eq 0 ]; } && return 0
			;;
	esac
	case "$evidence" in
		*"\`"*"$value"*"\`"*)
			case "$value" in *[A-Z]*) return 0 ;; esac
			;;
	esac
	case "$value" in
		*[A-Z]* )
			case "$value" in
				*[a-z]* )
					[ "$network_context" -eq 0 ] && return 0
					;;
			esac
			;;
	esac
	return 1
}

extract_address_candidates() {
	perl -ne '
		BEGIN {
			$state = "code";
			$current_path = "";
			$astro_frontmatter = 0;
			$astro_brace_depth = 0;
			$astro_expression = "";
			$astro_style = 0;
			$markdown_fence = 0;
			$markdown_code = 0;
		}

		sub code_text {
			my ($line, $single_is_string) = @_;
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
				if ($state eq "quoted" || $state eq "single") {
					if ($char eq "\\" && $offset + 1 < $length) {
						$text .= substr $line, $offset, 2;
						$offset += 2;
					} elsif (($state eq "quoted" && $char eq "\"") ||
						($state eq "single" && $char eq "\x27")) {
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
					$state = $single_is_string ? "single" : "rune";
				}
				$offset++;
			}

			$state = "code" if $state eq "quoted" || $state eq "single" || $state eq "rune";
			return $text;
		}

		sub astro_text {
			my ($line) = @_;
			if ($line eq "---" && $astro_frontmatter < 2) {
				$astro_frontmatter++;
				return "";
			}
			return code_text($line, 1) if $astro_frontmatter == 1;

			$astro_style = 1 if $line =~ /<style(?:\s|>)/;
			if ($astro_style) {
				$astro_style = 0 if $line =~ m{</style>};
				return $line;
			}

			my $text = "";
			for (my $offset = 0; $offset < length($line); $offset++) {
				my $char = substr($line, $offset, 1);
				if ($astro_brace_depth == 0) {
					if ($char eq "{") {
						$astro_brace_depth = 1;
						$astro_expression = "";
					} else {
						$text .= $char;
					}
					next;
				}
				if ($char eq "{") {
					$astro_brace_depth++;
					$astro_expression .= $char;
				} elsif ($char eq "}") {
					$astro_brace_depth--;
					if ($astro_brace_depth == 0) {
						$text .= code_text($astro_expression, 1);
						$astro_expression = "";
					} else {
						$astro_expression .= $char;
					}
				} else {
					$astro_expression .= $char;
				}
			}
			$astro_expression .= "\n" if $astro_brace_depth > 0;
			return $text;
		}

		sub markdown_text {
			my ($line) = @_;
			if ($line =~ /^```([A-Za-z0-9_-]*)\s*$/) {
				if ($markdown_fence) {
					$markdown_fence = 0;
					$markdown_code = 0;
					$state = "code";
				} else {
					my $language = lc $1;
					$markdown_fence = 1;
					$markdown_code = $language =~ /^(?:go|javascript|js|typescript|ts|hcl|terraform)$/;
				}
				return "";
			}
			return $markdown_code ? code_text($line, $path !~ /\.go$/) : $line;
		}

		chomp;
		next unless /^([^\0]+)\0([0-9]+)\0(.*)$/s;
		my ($path, $number, $content) = ($1, $2, $3);
		next if $path =~ m{(?:^|/)package-lock\.json$};
		if ($path ne $current_path) {
			$state = "code";
			$current_path = $path;
			$astro_frontmatter = 0;
			$astro_brace_depth = 0;
			$astro_expression = "";
			$astro_style = 0;
			$markdown_fence = 0;
			$markdown_code = 0;
		}
		my $text = $path =~ /\.go$/ ? code_text($content, 0)
			: $path =~ /\.(?:[cm]?js|ts|tf)$/ ? code_text($content, 1)
			: $path =~ /\.astro$/ ? astro_text($content)
			: $path =~ /\.mdx?$/ ? markdown_text($content)
			: $content;
		while ($text =~ /(?<![A-Za-z0-9_-])((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,})(?![A-Za-z0-9_-])/g) {
			my $value = $1;
			my $start = $-[1];
			my $before = substr($text, 0, $start);
			my $previous = $start > 0 ? substr($text, $start - 1, 1) : "";
			next if $previous eq "/" && $before !~ m{://\z};
			next if $previous eq "%";
			next if $before =~ /(?:├──|└──)\s*\z/;
			my $template_open = rindex($before, "\${");
			my $template_close = rindex($before, "}");
			next if $template_open > $template_close && $previous ne "\"" && $previous ne "\x27";
			print "$value|$path:$number:$content\n";
		}
	'
}

report_address_candidates() {
	scope=$1
	candidate_lines=$2
	skip_lines=$3
	tracked_names=$4
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
		is_non_network_literal "$value" "$line" "$tracked_names" && continue
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
		tracked_names=$(git ls-tree -r --name-only "$ref" | sed 's|.*/||' | sort -u)
		report_address_candidates '' "$candidates" '' "$tracked_names"
	else
		index_candidates=$(git grep --cached -n -I -z -e '' -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' 2>/dev/null | extract_address_candidates)
		worktree_candidates=$(git grep -n -I -z -e '' -- ':!scripts/check-publication_test.sh' ':!package-lock.json' ':!**/package-lock.json' 2>/dev/null | extract_address_candidates)
		tracked_names=$(git ls-files | sed 's|.*/||' | sort -u)
		address_failed=0
		report_address_candidates index "$index_candidates" '' "$tracked_names" || address_failed=1
		report_address_candidates worktree "$worktree_candidates" "$index_candidates" "$tracked_names" || address_failed=1
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
