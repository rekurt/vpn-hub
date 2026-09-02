# Contributing to VPN Hub

Thank you for improving VPN Hub. The project changes network policy on a host that may carry its operator's traffic, so correctness, rollback behavior, and reviewability matter more than feature volume.

## Before opening a change

- Search existing issues and documentation first.
- Keep a change focused: avoid unrelated refactors in the same pull request.
- Never commit a real hub configuration, device profile, runtime state, provider URL, private key, IP address, hostname, or Telegram credential.
- Use RFC 5737 addresses and `example` domains in fixtures and documentation.

## Local checks

Run the checks appropriate to your change before opening a pull request:

```sh
make test
make site-check
make publication-check
```

`make publication-check` deliberately rejects likely credentials, runtime state, and unreviewed network identifiers. If it reports a value from a test or a documented local artifact, improve the classifier or fixture evidence; do not weaken the check with a broad allowlist entry.

## Code and documentation

- Keep domain and application behavior independent of delivery adapters where practical.
- Add or update tests for changed routing, validation, serialization, shell, or deployment behavior.
- Document user-visible behavior in the English documentation first. Keep Russian and Simplified Chinese pages aligned when the same page is localized.
- Commands in docs must be executable against the current CLI. Prefer a dry run or verification command when an example could affect traffic.
- Explain limitations and recovery steps, not only the happy path.

## Pull requests

Describe the motivation, behavior change, verification performed, operational risk, and rollback path. For routing, firewall, DNS, namespace, deployment, or secret-handling changes, call out the intended fail-closed invariant explicitly.

Use conventional commit messages. Maintainers may ask for a smaller change, additional integration coverage, or documentation corrections before merge.
