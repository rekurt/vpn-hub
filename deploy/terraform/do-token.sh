#!/usr/bin/env sh
# Print the DigitalOcean API token, preferring the environment over the doctl config
# so CI can supply it without a doctl installation.
set -eu

if [ -n "${DIGITALOCEAN_TOKEN:-}" ]; then
	printf '%s' "$DIGITALOCEAN_TOKEN"
	exit 0
fi

for candidate in \
	"$HOME/Library/Application Support/doctl/config.yaml" \
	"$HOME/.config/doctl/config.yaml"; do
	if [ -f "$candidate" ]; then
		awk '/^access-token:/ { print $2; exit }' "$candidate"
		exit 0
	fi
done

echo "no DigitalOcean token: set DIGITALOCEAN_TOKEN or run 'doctl auth init'" >&2
exit 1
