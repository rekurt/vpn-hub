# VPN Hub

**Explicit multi-VPN routing for a self-hosted Linux hub.** VPN Hub connects devices through AmneziaWG and sends every packet through one deliberately selected path: direct uplink, WireGuard, AmneziaWG, Xray/VLESS, or OpenVPN. It is for operators who want repeatable policy instead of silent fallback.

[Documentation](https://rekurt.github.io/vpn-hub/docs/) · [Cookbook](https://rekurt.github.io/vpn-hub/docs/cookbook/) · [Telegram bot](https://rekurt.github.io/vpn-hub/docs/telegram-bot/) · [Русский](README.ru.md) · [简体中文](README.zh-CN.md)

## What it does

- Routes each device through one chosen Internet egress and private destinations through their owning tunnel.
- Isolates provider tunnels in network namespaces with independent policy routing and kill switches.
- Applies declarative YAML as a hashed desired-state revision and detects runtime drift.
- Supports split DNS, directional client ACLs, per-egress SOCKS5, health probes, and bounded VLESS subscriptions.
- Provides an optional Telegram operator UI for devices, tunnels, deploy confirmation, status, logs, and subscriptions.
- Uses a confirmation window for risky deployments; an unconfirmed revision automatically rolls back.

## Supported environment

The supported host is Ubuntu 24.04 LTS. VPN Hub requires systemd, nftables, iproute2, conntrack, dnsmasq, and client tools for the tunnel types you enable. See [requirements](https://rekurt.github.io/vpn-hub/docs/start/requirements/) before provisioning.

It is a single-hub, IPv4-oriented deployment. High availability, multi-tenancy, overlapping-CIDR translation, and automatic fallback between egresses are intentionally out of scope.

## Quick evaluation

Use a disposable Linux host or the documented lab first. Do not redirect production traffic before you have independent recovery access.

```sh
git clone https://github.com/rekurt/vpn-hub.git
cd vpn-hub
make test
cp configs/example.yaml configs/hub.yaml
go run ./cmd/hubctl validate --config configs/hub.yaml
go run ./cmd/vpn-hub-agent reconcile --config configs/hub.yaml --state-dir ./state --dry-run
```

The example is for local validation. Continue with [First hub](https://rekurt.github.io/vpn-hub/docs/start/first-hub/), [First device](https://rekurt.github.io/vpn-hub/docs/start/first-device/), and [Verify](https://rekurt.github.io/vpn-hub/docs/start/verify/) before changing live traffic.

## Pick a workflow

| Need | Start here |
| --- | --- |
| Install one hub | [Install](https://rekurt.github.io/vpn-hub/docs/start/install/) |
| Route one application | [SOCKS5 app steering](https://rekurt.github.io/vpn-hub/docs/use-cases/socks-for-apps/) |
| Handle private networks and DNS | [Segmentation cookbook](https://rekurt.github.io/vpn-hub/docs/cookbook/segmentation/) |
| Test a provider subscription | [Subscription canary](https://rekurt.github.io/vpn-hub/docs/cookbook/subscription-canary/) |
| Apply a risky change | [Rolling deploy](https://rekurt.github.io/vpn-hub/docs/cookbook/rolling-deploy/) |
| Recover from a bad revision or drift | [Rollback runbook](https://rekurt.github.io/vpn-hub/docs/cookbook/rollback-runbook/) |
| Operate through Telegram | [Bot guide](https://rekurt.github.io/vpn-hub/docs/telegram-bot/) |

## Safety model

VPN Hub fails closed. A selected egress that is down does not become direct Internet access. Private DNS answers remain attached to the owning tunnel, and client-to-client traffic is denied until an explicit ACL permits it.

Read the [threat model](https://rekurt.github.io/vpn-hub/docs/security/threat-model/) and [limitations](https://rekurt.github.io/vpn-hub/docs/security/limitations/) before production use. DNS-over-HTTPS cannot be reliably intercepted, and TCP/443 fallback deliberately cannot reach private networks.

## Development and release

```sh
make test
make site-check
make publication-check
```

Never commit hub configuration, generated profiles, runtime state, provider links, or Telegram tokens. Tags beginning with `v` create Linux amd64 release artifacts. Hub deployment remains a manual GitHub Actions workflow with environment approval and a pinned host key.

See the [deployment reference](https://rekurt.github.io/vpn-hub/docs/reference/deployment/) and [incident response guide](https://rekurt.github.io/vpn-hub/docs/operations/incident-response/).
