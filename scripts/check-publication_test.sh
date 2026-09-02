#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
failed=0

new_repo() {
	name=$1
	repo="$tmp_dir/$name"
	mkdir -p "$repo/scripts"
	cp "$script_dir/check-publication.sh" "$repo/scripts/check-publication.sh" || exit 1
	cp "$script_dir/check-package-locks.mjs" "$repo/scripts/check-package-locks.mjs" || exit 1
	cp "$script_dir/validate-package-lock.mjs" "$repo/scripts/validate-package-lock.mjs" || exit 1
	cp "$script_dir/publication-allowlist.txt" "$repo/scripts/publication-allowlist.txt" || exit 1
	git -C "$repo" init -q
	git -C "$repo" config user.name PublicationTest
	git -C "$repo" config user.email publication-test@users.noreply.github.com
}

commit_fixture() {
	fixture=${1:-fixture.txt}
	git -C "$repo" add -- "$fixture"
	git -C "$repo" commit -qm "test: add fixture"
}

expect_pass() {
	name=$1
	shift
	new_repo "$name"
	"$@" >"$repo/fixture.txt"
	commit_fixture
	if ! (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected publication check to pass" >&2
		failed=1
	fi
}

expect_fail() {
	name=$1
	shift
	new_repo "$name"
	"$@" >"$repo/fixture.txt"
	commit_fixture
	if (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected publication check to fail" >&2
		failed=1
	fi
}

expect_fail_path() {
	name=$1
	path=$2
	shift 2
	new_repo "$name"
	"$@" >"$repo/$path"
	commit_fixture "$path"
	if (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected publication check to fail" >&2
		failed=1
	fi
}

expect_package_lock_pass() {
	name=$1
	shift
	new_repo "$name"
	mkdir -p "$repo/site"
	"$@" >"$repo/site/package-lock.json"
	commit_fixture site/package-lock.json
	if ! (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected package-lock check to pass" >&2
		failed=1
	fi
	if git -C "$repo" check-attr binary -- site/package-lock.json | grep -q ': set'; then
		echo "$name: package-lock must not be marked binary" >&2
		failed=1
	fi
}

expect_package_lock_fail() {
	name=$1
	shift
	new_repo "$name"
	mkdir -p "$repo/site"
	"$@" >"$repo/site/package-lock.json"
	commit_fixture site/package-lock.json
	if (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected package-lock check to fail" >&2
		failed=1
	fi
}

expect_two_package_locks_pass() {
	name=$1
	new_repo "$name"
	mkdir -p "$repo/site/nested"
	printf '%s\n' '{"packages":{"node_modules/one":{"resolved":"https://registry.npmjs.org/one/-/one-1.0.0.tgz"}}}' >"$repo/site/package-lock.json"
	printf '%s\n' '{"packages":{"node_modules/two":{"resolved":"https://registry.npmjs.org/two/-/two-1.0.0.tgz"}}}' >"$repo/site/nested/package-lock.json"
	git -C "$repo" add -- site/package-lock.json site/nested/package-lock.json
	git -C "$repo" commit -qm "test: add two locks"
	if ! (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected two package locks to pass" >&2
		failed=1
	fi
}

expect_nested_path_lock_pass() {
	name=$1
	new_repo "$name"
	path=$(printf 'site/локаль\tстрока\npackage-lock.json')
	mkdir -p "$(dirname "$repo/$path")"
	printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://registry.npmjs.org/example/-/example-1.0.0.tgz"}}}' >"$repo/$path"
	commit_fixture "$path"
	if ! (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected Unicode/tab/newline package-lock path to pass" >&2
		failed=1
	fi
}

expect_package_lock_symlink_fail() {
	name=$1
	new_repo "$name"
	mkdir -p "$repo/site"
	printf '%s\n' '{"packages":{}}' >"$repo/site/target-lock.json"
	if ! ln -s target-lock.json "$repo/site/package-lock.json"; then
		echo "$name: symlinks unsupported; skipped" >&2
		return
	fi
	commit_fixture site/package-lock.json
	if (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected tracked package-lock symlink to fail" >&2
		failed=1
	fi
}

expect_worktree_package_lock_symlink_fail() {
	name=$1
	new_repo "$name"
	mkdir -p "$repo/site"
	printf '%s\n' '{"packages":{}}' >"$repo/site/package-lock.json"
	commit_fixture site/package-lock.json
	mv "$repo/site/package-lock.json" "$repo/site/target-lock.json"
	if ! ln -s target-lock.json "$repo/site/package-lock.json"; then
		echo "$name: symlinks unsupported; skipped" >&2
		return
	fi
	if (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected unstaged package-lock symlink to fail" >&2
		failed=1
	fi
}

expect_unstaged_package_lock_fail() {
	name=$1
	new_repo "$name"
	mkdir -p "$repo/site"
	printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://registry.npmjs.org/example.tgz"}}}' >"$repo/site/package-lock.json"
	commit_fixture site/package-lock.json
	printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://evil.registry.example.dev/example.tgz"}}}' >"$repo/site/package-lock.json"
	output="$repo/check-output"
	if (cd "$repo" && sh scripts/check-publication.sh) >"$output" 2>&1; then
		echo "$name: expected unstaged package-lock content to fail" >&2
		failed=1
	fi
	if ! grep -Fq 'worktree:site/package-lock.json' "$output"; then
		echo "$name: expected worktree evidence label" >&2
		failed=1
	fi
}

expect_staged_package_lock_fail() {
	name=$1
	new_repo "$name"
	mkdir -p "$repo/site"
	printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://registry.npmjs.org/example.tgz"}}}' >"$repo/site/package-lock.json"
	commit_fixture site/package-lock.json
	printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://evil.registry.example.dev/example.tgz"}}}' >"$repo/site/package-lock.json"
	git -C "$repo" add -- site/package-lock.json
	printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://registry.npmjs.org/example.tgz"}}}' >"$repo/site/package-lock.json"
	output="$repo/check-output"
	if (cd "$repo" && sh scripts/check-publication.sh) >"$output" 2>&1; then
		echo "$name: expected staged package-lock content to fail" >&2
		failed=1
	fi
	if ! grep -Fq 'index:site/package-lock.json' "$output"; then
		echo "$name: expected index evidence label" >&2
		failed=1
	fi
}

expect_staged_secret_fail() {
	name=$1
	new_repo "$name"
	printf '%s\n' 'safe fixture' >"$repo/fixture.txt"
	commit_fixture
	printf '%s\n' 'private_key = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=' >"$repo/fixture.txt"
	git -C "$repo" add -- fixture.txt
	printf '%s\n' 'safe fixture' >"$repo/fixture.txt"
	output="$repo/check-output"
	if (cd "$repo" && sh scripts/check-publication.sh) >"$output" 2>&1; then
		echo "$name: expected staged private key to fail" >&2
		failed=1
	fi
	if ! grep -Fq '[index]' "$output"; then
		echo "$name: expected staged private key index evidence" >&2
		failed=1
	fi
}

expect_large_lock_blob_pass() {
	name=$1
	new_repo "$name"
	mkdir -p "$repo/site"
	node -e "process.stdout.write(JSON.stringify({note:'x'.repeat(1200000),packages:{}}))" >"$repo/site/package-lock.json"
	commit_fixture site/package-lock.json
	if ! (cd "$repo" && node scripts/check-package-locks.mjs --ref HEAD); then
		echo "$name: expected valid package-lock blob larger than 1.1 MiB to pass" >&2
		failed=1
	fi
}

expect_large_tree_listing_pass() {
	name=$1
	new_repo "$name"
	printf '%s\n' '{"packages":{}}' >"$repo/valid-lock.json"
	blob_oid=$(git -C "$repo" hash-object -w valid-lock.json)
	tree_oid=$(
		node - "$blob_oid" <<'NODE' | git -C "$repo" mktree -z
const oid = process.argv[2];
for (let index = 0; index < 8000; index += 1) {
  const suffix = String(index).padStart(5, '0');
  process.stdout.write(`100644 blob ${oid}\tentry-${suffix}-${'x'.repeat(120)}.txt\0`);
}
process.stdout.write(`100644 blob ${oid}\tpackage-lock.json\0`);
NODE
	)
	if ! (cd "$repo" && node scripts/check-package-locks.mjs --ref "$tree_oid"); then
		echo "$name: expected Git tree listing larger than 1.1 MiB to pass" >&2
		failed=1
	fi
}

expect_oversized_lock_blob_fail_clearly() {
	name=$1
	new_repo "$name"
	node -e "process.stdout.write(JSON.stringify({note:'x'.repeat(65 * 1024 * 1024),packages:{}}))" >"$repo/oversized-lock.json"
	blob_oid=$(git -C "$repo" hash-object -w oversized-lock.json)
	tree_oid=$(printf '100644 blob %s\tpackage-lock.json\0' "$blob_oid" | git -C "$repo" mktree -z)
	output="$repo/check-output"
	if (cd "$repo" && node scripts/check-package-locks.mjs --ref "$tree_oid") >"$output" 2>&1; then
		echo "$name: expected package-lock blob beyond the Git response cap to fail" >&2
		failed=1
	fi
	if ! grep -Fq 'exceeded 64 MiB Git output limit' "$output"; then
		echo "$name: expected explicit 64 MiB Git output limit diagnostic" >&2
		failed=1
	fi
}

expect_invalid_utf8_package_lock_path_fail() {
	name=$1
	new_repo "$name"
	path=$(printf 'site/\377/package-lock.json')
	if ! mkdir -p "$(dirname "$repo/$path")" 2>/dev/null; then
		echo "$name: invalid UTF-8 paths unsupported; skipped" >&2
		return
	fi
	printf '%s\n' '{"packages":{}}' >"$repo/$path"
	if ! commit_fixture "$path"; then
		echo "$name: invalid UTF-8 Git paths unsupported; skipped" >&2
		return
	fi
	if (cd "$repo" && sh scripts/check-publication.sh); then
		echo "$name: expected invalid UTF-8 package-lock path to fail" >&2
		failed=1
	fi
}

expect_pass clean printf '%s\n' 'endpoint: vpn.example.com:51820'
expect_fail awg-private printf '%s\n' 'private_key = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='
expect_fail telegram-token printf '%s\n' 'token: 123456789:AAExampleSecretValueThatMustFail'
expect_fail runtime-state printf '%s\n' '{"revision":"abc","hub":{"endpoint":"203.0.113.7:51820"}}'
expect_pass synthetic-public printf '%s\n' 'public_key: W/kKaUP1n48AgIzxs8po0HKV+UEk1vMcTuBW648atSE='
expect_fail unknown-host printf '%s\n' 'endpoint: vpn.personal-domain.net:51820'
expect_fail neighboring-dotted-literal printf '%s\n' 'message_id: confirm.other'
expect_fail unknown-server-host printf '%s\n' 'server: vpn.personal-domain.net:51820'
expect_fail unknown-vless-host printf '%s\n' 'vless://id@vpn.personal-domain.net:443'
expect_fail unknown-dev-host printf '%s\n' 'server: vpn.personal-domain.dev:51820'
expect_fail unknown-ru-host printf '%s\n' 'server: vpn.personal-domain.ru:51820'
expect_fail unknown-dns-name printf '%s\n' 'dns_name: vpn.personal-domain.dev'
expect_fail unknown-json-address printf '%s\n' '{"address":"edge.personal-domain.ru"}'
expect_fail unknown-prose-host printf '%s\n' 'Contact vpn.personal-domain.xyz for access.'
expect_fail unknown-prose-ip printf '%s\n' 'The temporary value is 93.184.216.35.'
expect_fail unknown-public-ip printf '%s\n' 'endpoint: 93.184.216.34:51820'
expect_fail unknown-no-hyphen-host printf '%s\n' 'endpoint: vpn.example.dev:51820'
expect_fail unknown-uppercase-host printf '%s\n' 'endpoint: VPN.EXAMPLE.DEV:51820'
expect_fail unknown-one-letter-label printf '%s\n' 'endpoint: a.b.dev:51820'
expect_fail unknown-inline-code-host printf '%s\n' 'Use `vpn.vendor.cloud` as the endpoint.'
expect_fail_path unknown-go-block-comment fixture.go printf '%s\n' 'package fixture' '' '/* block-comment.personal-domain.dev */'
expect_fail_path unknown-go-multiline-raw-string fixture.go printf '%s\n' 'package fixture' '' 'var endpoint = `' 'raw-string.personal-domain.cloud 93.184.216.36' '`'
expect_pass documentation-host printf '%s\n' 'endpoint: vpn.example.com:51820'
expect_pass uppercase-documentation-host printf '%s\n' 'endpoint: VPN.EXAMPLE.COM:51820'
expect_package_lock_pass npm-registry-lock printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://registry.npmjs.org/example/-/example-1.0.0.tgz"}}}'
expect_package_lock_fail evil-registry-lock printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://evil.registry.example.dev/example.tgz"}}}'
expect_package_lock_fail credentialed-lock printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://token@registry.npmjs.org/example.tgz"}}}'
expect_package_lock_fail query-lock printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://registry.npmjs.org/example.tgz?token=secret"}}}'
expect_package_lock_fail fragment-lock printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://registry.npmjs.org/example.tgz#fragment"}}}'
expect_package_lock_fail port-lock printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://registry.npmjs.org:444/example.tgz"}}}'
expect_package_lock_fail malformed-lock printf '%s\n' '{invalid'
expect_package_lock_fail lock-token printf '%s\n' '{"note":"token: 123456789:AAExampleSecretValueThatMustFail","packages":{"node_modules/example":{"resolved":"https://registry.npmjs.org/example.tgz"}}}'
expect_two_package_locks_pass two-locks
expect_nested_path_lock_pass nested-path-lock
expect_package_lock_symlink_fail lock-symlink
expect_worktree_package_lock_symlink_fail worktree-lock-symlink
expect_unstaged_package_lock_fail unstaged-lock-content
expect_staged_package_lock_fail staged-lock-content
expect_staged_secret_fail staged-secret
expect_invalid_utf8_package_lock_path_fail invalid-utf8-lock-path
expect_large_lock_blob_pass large-lock-blob
expect_large_tree_listing_pass large-tree-listing
expect_oversized_lock_blob_fail_clearly oversized-lock-blob

if [ -e "$script_dir/../site/.gitattributes" ]; then
	echo "package-lock must not use a binary attribute workaround" >&2
	failed=1
fi

new_repo history-secret
printf '%s\n' 'private_key = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=' >"$repo/fixture.txt"
commit_fixture
rm "$repo/fixture.txt"
git -C "$repo" add fixture.txt
git -C "$repo" commit -qm "test: remove fixture"
if (cd "$repo" && sh scripts/check-publication.sh --history); then
	echo "history-secret: expected history publication check to fail" >&2
	failed=1
fi

new_repo history-allowlist
printf '%s\n' 'value: retired.invalid' >"$repo/fixture.txt"
cp "$repo/scripts/publication-allowlist.txt" "$repo/scripts/publication-allowlist.before"
printf '%s\n' 'retired.invalid' >>"$repo/scripts/publication-allowlist.txt"
git -C "$repo" add -- fixture.txt scripts/publication-allowlist.txt
git -C "$repo" commit -qm "test: historical allowlist entry"
mv "$repo/scripts/publication-allowlist.before" "$repo/scripts/publication-allowlist.txt"
mv "$repo/fixture.txt" "$repo/fixture.before"
git -C "$repo" add -- fixture.txt scripts/publication-allowlist.txt
git -C "$repo" commit -qm "test: remove historical fixture"
if (cd "$repo" && sh scripts/check-publication.sh --history); then
	echo "history-allowlist: expected current allowlist to reject historical self-approval" >&2
	failed=1
fi

new_repo history-package-lock
mkdir -p "$repo/site"
printf '%s\n' '{"packages":{"node_modules/example":{"resolved":"https://evil.registry.example.dev/example.tgz"}}}' >"$repo/site/package-lock.json"
commit_fixture site/package-lock.json
rm "$repo/site/package-lock.json"
git -C "$repo" add -- site/package-lock.json
git -C "$repo" commit -qm "test: remove package lock"
if (cd "$repo" && sh scripts/check-publication.sh --history); then
	echo "history-package-lock: expected historical package-lock check to fail" >&2
	failed=1
fi

exit "$failed"
