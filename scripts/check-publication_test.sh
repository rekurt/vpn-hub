#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

new_repo() {
	name=$1
	repo="$tmp_dir/$name"
	mkdir -p "$repo/scripts"
	cp "$script_dir/check-publication.sh" "$repo/scripts/check-publication.sh" || exit 1
	cp "$script_dir/publication-allowlist.txt" "$repo/scripts/publication-allowlist.txt" || exit 1
	git -C "$repo" init -q
	git -C "$repo" config user.name PublicationTest
	git -C "$repo" config user.email publication-test@users.noreply.github.com
}

commit_fixture() {
	git -C "$repo" add fixture.txt
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
		exit 1
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
		exit 1
	fi
}

expect_pass clean printf '%s\n' 'endpoint: vpn.example.com:51820'
expect_fail awg-private printf '%s\n' 'private_key = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='
expect_fail telegram-token printf '%s\n' 'token: 123456789:AAExampleSecretValueThatMustFail'
expect_fail runtime-state printf '%s\n' '{"revision":"abc","hub":{"endpoint":"203.0.113.7:51820"}}'
expect_pass synthetic-public printf '%s\n' 'public_key: W/kKaUP1n48AgIzxs8po0HKV+UEk1vMcTuBW648atSE='
expect_fail unknown-host printf '%s\n' 'endpoint: vpn.personal-domain.net:51820'
expect_fail unknown-server-host printf '%s\n' 'server: vpn.personal-domain.net:51820'
expect_fail unknown-vless-host printf '%s\n' 'vless://id@vpn.personal-domain.net:443'
expect_fail unknown-dev-host printf '%s\n' 'server: vpn.personal-domain.dev:51820'
expect_fail unknown-ru-host printf '%s\n' 'server: vpn.personal-domain.ru:51820'
expect_fail unknown-public-ip printf '%s\n' 'endpoint: 93.184.216.34:51820'
expect_pass documentation-host printf '%s\n' 'endpoint: vpn.example.com:51820'

new_repo history-secret
printf '%s\n' 'private_key = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=' >"$repo/fixture.txt"
commit_fixture
rm "$repo/fixture.txt"
git -C "$repo" add fixture.txt
git -C "$repo" commit -qm "test: remove fixture"
if (cd "$repo" && sh scripts/check-publication.sh --history); then
	echo "history-secret: expected history publication check to fail" >&2
	exit 1
fi
