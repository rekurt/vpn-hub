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
	cp "$script_dir/validate-package-lock.mjs" "$repo/scripts/validate-package-lock.mjs" || exit 1
	cp "$script_dir/publication-allowlist.txt" "$repo/scripts/publication-allowlist.txt" || exit 1
	git -C "$repo" init -q
	git -C "$repo" config user.name PublicationTest
	git -C "$repo" config user.email publication-test@users.noreply.github.com
}

commit_fixture() {
	fixture=${1:-fixture.txt}
	git -C "$repo" add "$fixture"
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
expect_package_lock_fail malformed-lock printf '%s\n' '{invalid'

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

exit "$failed"
