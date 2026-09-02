# Support

## Documentation first

Start with the [documentation](https://rekurt.github.io/vpn-hub/docs/), especially the [cookbook](https://rekurt.github.io/vpn-hub/docs/cookbook/), [troubleshooting guide](https://rekurt.github.io/vpn-hub/docs/reference/troubleshooting/), and [incident response runbook](https://rekurt.github.io/vpn-hub/docs/operations/incident-response/).

## Bug reports

Open a GitHub issue for reproducible non-sensitive defects. Include the project revision, Ubuntu release, tunnel type, expected behavior, observed behavior, and the smallest sanitized configuration or command sequence that reproduces it.

Replace real addresses with RFC 5737 examples, replace domains with `example` names, and remove credentials and profile data before posting.

## Security reports

For vulnerabilities or potential secret exposure, follow [SECURITY.md](SECURITY.md). Do not use a public issue.

## Operational emergencies

This repository cannot operate a third-party hub. Preserve independent SSH or console access before a change, use `hubctl deploy --confirm-within`, and follow the documented rollback procedure when routing access is at risk.
