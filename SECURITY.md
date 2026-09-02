# Security policy

## Supported versions

Security fixes are made on the current default branch. This project has not published a stable tagged release yet; build from the current default branch only when you can test the deployment and retain recovery access.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose a hub, a device, a provider subscription, or a Telegram bot.

Use GitHub's private vulnerability-reporting flow for this repository when it is available. If private reporting is unavailable, contact the repository owner privately through GitHub and include only the minimum information needed to establish a secure reporting channel.

Do not include any of the following in an initial report:

- active hostnames, IP addresses, SSH host keys, or cloud credentials;
- WireGuard, AmneziaWG, Reality, age, or device private keys;
- VLESS subscription URLs, OpenVPN credentials, or rendered profiles;
- Telegram bot tokens, chat IDs, state files, or unredacted logs.

Include the affected revision, a minimal reproduction using synthetic addresses, impact, and a safe remediation idea if you have one. A report is acknowledged after a maintainer can assess it; public disclosure is coordinated after a fix or a documented mitigation exists.

## Operational security

Read the [threat model](https://rekurt.github.io/vpn-hub/docs/security/threat-model/) and [limitations](https://rekurt.github.io/vpn-hub/docs/security/limitations/) before running a hub. VPN Hub is designed to fail closed, but host access, secret storage, upstream trust, DNS-over-HTTPS policy, and an independent recovery path remain operator responsibilities.
