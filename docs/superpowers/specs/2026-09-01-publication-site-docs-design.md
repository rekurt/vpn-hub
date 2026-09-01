# VPN Hub Public Release, Documentation, and Website Design

**Date:** 2026-09-01  
**Status:** Approved direction; implementation pending  
**Primary language:** English  
**Localizations:** Russian and Simplified Chinese

## 1. Purpose

Prepare VPN Hub for a credible open-source release. The result must let a new operator understand the product, evaluate its security model, deploy a hub, connect devices, route traffic through several provider types, operate the system through either CLI or Telegram, recover from mistakes, and verify a release without reading the source first.

The public presentation must be technically honest. It should explain both the useful properties and the operational limits of a privileged networking system. Marketing copy may be confident, but it must not claim guarantees the implementation does not provide.

## 2. Product Positioning

VPN Hub is a self-hosted Linux control plane for routing different devices and destinations through different VPN egresses from one AmneziaWG connection.

The core proposition is:

> One connection to your hub. Explicit routing for every device and private network. No silent fallback.

The product is aimed at engineers and advanced self-hosters who need:

- one stable client profile per device;
- independent WireGuard, AmneziaWG, Xray/VLESS, OpenVPN, direct, and SOCKS paths;
- device-specific Internet egress;
- private-network routes and split DNS;
- fail-closed routing when a selected egress is unavailable;
- safe desired-state changes with confirmation and rollback;
- optional Telegram administration without removing the SSH/CLI recovery path.

The project is not positioned as a commercial VPN provider, an anonymity guarantee, a multi-tenant SaaS control plane, or a replacement for host and cloud security controls.

## 3. Experience Principles

1. **English first.** English is the canonical language for the website, root README, CLI descriptions, and default Telegram interface.
2. **Human documentation.** Pages answer why, when, prerequisites, steps, verification, rollback, and failure modes instead of merely listing fields.
3. **Copy-pasteable, not magical.** Commands must correspond to real binaries, flags, configuration fields, and systemd units.
4. **Fail-closed is visible.** The landing page and documentation explain kill switches and do not imply automatic direct fallback.
5. **Operations are first-class.** Deployment confirmation, rollback, key rotation, revocation, logs, backups, and recovery receive the same attention as initial setup.
6. **One source of truth.** The site is versioned with the code. README files provide concise entry points and link to the complete docs.
7. **No template language.** Avoid generic claims such as “next-generation”, “seamless”, “revolutionary”, or unsourced performance and security superlatives.

## 4. Technical Architecture

### 4.1 Website stack

Use Astro with Starlight under `site/`:

- Astro renders a custom product landing page and shared marketing components.
- Starlight provides documentation navigation, search, code blocks, accessibility, responsive layout, and localization.
- All content is stored as Markdown/MDX in the repository.
- The output is a static site with no application backend, cookies, analytics, or runtime account system.
- GitHub Actions builds and deploys the static output to GitHub Pages.
- The initial canonical public URL is `https://rekurt.github.io/vpn-hub/`; a custom domain can replace it without changing the information architecture.

The site must work under the `/vpn-hub/` base path and preserve correct asset, canonical, sitemap, and locale URLs.

### 4.2 Repository structure

```text
README.md
README.ru.md
README.zh-CN.md
SECURITY.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
CHANGELOG.md
docs/
  architecture/
  publication/
site/
  astro.config.mjs
  package.json
  public/
  src/
    components/
    content/docs/
      en/
      ru/
      zh-cn/
    pages/
      index.astro
      ru/index.astro
      zh-cn/index.astro
    styles/
```

Canonical documentation lives in the site content tree. Repository Markdown files cover contribution, security reporting, release history, and a concise onboarding path without duplicating the complete manual.

### 4.3 Localization model

- `/` and all unprefixed canonical routes are English.
- `/ru/` contains Russian landing and documentation pages.
- `/zh-cn/` contains Simplified Chinese landing and documentation pages.
- Each page declares canonical and alternate `hreflang` links.
- Language switchers preserve the current page when a translation exists and fall back to the locale home otherwise.
- English is authored first. Russian and Chinese translations must retain the exact commands, identifiers, filenames, protocol names, and configuration keys.
- Missing translations are a release blocker for the promised public information architecture.

## 5. Visual Direction

The visual language should resemble a precise network operations console rather than a generic SaaS template.

### 5.1 Palette and typography

- Near-black navy background for hero and architecture sections.
- Warm off-white reading surface for long documentation.
- Electric cyan for healthy routes and primary actions.
- Amber for staged changes and confirmation windows.
- Coral red only for blocked paths, revocation, and rollback warnings.
- A restrained technical sans-serif for prose and a readable monospace for identifiers and commands.

Contrast must meet WCAG AA. Color is never the only carrier of status.

### 5.2 Landing composition

1. Compact navigation: Product, Use cases, Cookbook, Docs, Telegram bot, GitHub.
2. Hero with the core proposition, `Get started` and `View on GitHub` actions, plus an original route-map visual.
3. Immediate proof strip: supported ingress/egress types, safe rollback, private routing, Telegram operations.
4. “How traffic moves” architecture section showing device, hub, policy decision, selected egress, and fail-closed behavior.
5. Scenario cards built from real supported use cases.
6. Safety model with explicit invariants and limitations.
7. Telegram operations preview using a code-rendered interface mock based on actual bot screens rather than a fabricated screenshot.
8. Cookbook preview grouped by operator intent.
9. Deployment path from a fresh VPS to a verified device.
10. Final call to action and factual project metadata.

Animation is limited to subtle route drawing, state transitions, and reduced-motion-safe reveals. It must not delay reading or navigation.

## 6. Documentation Information Architecture

### 6.1 Start here

- Overview
- Requirements and supported environment
- Choose a deployment path
- Install from a release
- Provision with OpenTofu/Terraform
- Generate the hub key
- Create the first configuration
- Validate and dry-run
- Deploy with a confirmation window
- Add the first device
- Verify traffic, DNS, and kill-switch behavior

### 6.2 Concepts

- System architecture and trust boundaries
- Desired state, revisions, convergence, and drift
- AmneziaWG ingress
- Egress types and network namespaces
- Policy routing and packet marks
- Kill switches and the no-silent-fallback invariant
- Private networks, routes, and split DNS
- Client-to-client isolation and ACLs
- Subscription candidate selection and last-known-good state
- Health probes and tunnel status
- Secret lifecycle and generated device profiles
- CLI, agent, bot, and systemd responsibilities

### 6.3 Configuration reference

Document every accepted field and constraint from the actual configuration parser, grouped by:

- hub settings;
- AmneziaWG parameters;
- devices;
- tunnel definitions;
- WireGuard and AmneziaWG upstreams;
- Xray/VLESS/REALITY upstreams;
- OpenVPN upstreams;
- direct egress;
- SOCKS endpoints and allowed devices;
- routes and private DNS zones;
- health probes;
- subscription settings;
- client ACL rules.

Each field includes type, required/default status, validation rules, security implications, and one minimal example. Secret-bearing fields explain the preferred file or SOPS flow and must not use realistic reusable credentials.

### 6.4 Command reference

Generate and verify reference pages against the real Cobra command tree.

`hubctl` coverage:

- `validate`
- `deploy`
- `confirm`
- `rollback`
- `status`
- `keygen`
- `add`
- tunnel list/enable/disable/routes/DNS zones
- device list and `set-egress`
- client ACL list/add/remove
- `probe tunnel`
- subscription refresh/restore
- revoke/unrevoke
- route inspection

`vpn-hub-agent` coverage:

- `reconcile`
- `serve`
- `status`
- state, key, runtime, and configuration directory flags

`vpn-hub-bot` coverage:

- `serve`
- `check`
- Telegram, hub configuration, state, runtime, and server-key flags

Every command page includes examples, expected output shape, permissions, side effects, and recovery guidance.

### 6.5 Operations

- Systemd installation and hardening
- Service startup order
- Safe configuration deployment
- Confirmation and automatic rollback
- Immediate rollback
- Upgrading binaries and configuration
- Release checksum verification
- Backup and restore
- Key rotation
- Device revocation and reissue
- Provider credential rotation
- Logs and diagnostics
- Drift detection and reconciliation
- Incident response and emergency SSH recovery
- Full uninstallation

### 6.6 Security

- Threat model and trust boundaries
- Root privilege rationale
- Filesystem permissions
- Network namespace and nftables isolation
- Bot authorization model
- Secret handling with SOPS/age
- Provider input trust model
- Release provenance and checksums
- Security reporting policy
- Known limitations and safe deployment checklist

The documentation must explicitly state that bot-managed profiles can retain private client keys for re-delivery, while CLI-generated profiles follow a different lifecycle. It must also describe the actual cloud firewall ports rather than claiming only ports 22 and 51820 are opened.

## 7. Cookbook Coverage

Cookbook pages are task-oriented. Every recipe uses this structure:

1. Goal
2. When to use it
3. Prerequisites
4. Minimal configuration
5. Apply safely
6. Verify routing and DNS
7. Expected failure behavior
8. Roll back
9. Related recipes

### 7.1 Initial deployment

- Local dry-run without touching networking
- Install from a GitHub release
- Provision a DigitalOcean host
- Restrict the SSH management CIDR
- Configure SOPS with age
- Start without the Telegram bot
- Add the Telegram bot later

### 7.2 Internet egress

- Send a device directly through the hub uplink
- Route a device through WireGuard
- Route a device through AmneziaWG
- Route a device through Xray/VLESS/REALITY
- Route a device through OpenVPN
- Change a device's default egress
- Share one egress between several devices
- Restrict a tunnel with `allowed_devices`
- Disable and re-enable an egress
- Test one or all egresses
- Prove that a failed egress does not fall back to direct

### 7.3 Private networks and DNS

- Reach a remote private subnet through a tunnel
- Add and remove destination routes
- Configure split DNS for a private zone
- Use different private routes through different tunnels
- Diagnose an overlapping route
- Inspect the compiled route table
- Verify DNS from a client

### 7.4 Devices and ACLs

- Add a device with an automatic address
- Add a device with an explicit address
- Deliver a QR profile
- Re-download a bot-managed profile
- Reissue a compromised profile
- Revoke and unrevoke a device
- Allow one device to reach another on TCP/22
- Allow UDP access to a specific service
- Use `any` as an ACL source
- Remove an ACL and verify default isolation

### 7.5 Application-specific access

- Expose a SOCKS endpoint for one device
- Allow several devices to use the same SOCKS endpoint
- Route one application without changing the device's default egress
- Verify SOCKS access control and failure behavior

### 7.6 Provider subscriptions

- Configure a VLESS subscription
- Refresh and automatically choose a healthy candidate
- Inspect candidates before promotion
- Manually select a candidate
- Restore last-known-good
- Recover from a malformed or unavailable subscription
- Set safe health probes and timeouts

### 7.7 Restricted networks and fallback ingress

- Enable REALITY on TCP/443
- Enable UDP/443 fallback
- Understand which ports must be opened
- Validate fallback listener health
- Keep fallback traffic away from hub management services

### 7.8 Change safety and recovery

- Deploy with 1, 5, 15, or 30 minute confirmation windows
- Confirm a healthy revision
- Roll back before the timer expires
- Recover after losing VPN connectivity
- Recover after a bad DNS or route change
- Restore a previous upstream candidate
- Restart the agent safely
- Diagnose a stale or divergent revision

### 7.9 Maintenance and troubleshooting

- Inspect agent and bot logs
- Export a larger log bundle
- Check host resources and systemd units
- Back up configuration and state
- Restore onto a replacement host
- Upgrade to a new release
- Validate checksums
- Rotate hub and device keys
- Remove VPN Hub cleanly
- Run unit, golden, and Linux integration tests

## 8. Use-Case Catalog

The public site presents scenarios as workflows, with a linked cookbook path and stated limitations.

1. **Remote engineer:** laptop uses a private office tunnel for internal routes and another egress for Internet traffic.
2. **Several personal devices:** phone, laptop, and tablet keep stable profiles while using different geographic providers.
3. **Home and family:** selected devices share an egress; client-to-client traffic remains blocked unless explicitly allowed.
4. **Infrastructure administration:** one device receives a narrow TCP/22 ACL to another enrolled host.
5. **Private DNS:** internal zones resolve only through the tunnel that reaches their network.
6. **Censored or UDP-blocked network:** operator enables TCP/443 REALITY or UDP/443 fallback ingress.
7. **Application-only routing:** an application uses the controlled SOCKS endpoint without moving the whole device.
8. **Provider rotation:** a subscription is refreshed, probed, promoted, and recoverable through last-known-good.
9. **Provider outage:** traffic assigned to the failed tunnel stops instead of leaking through direct Internet access.
10. **Lost device:** operator revokes access immediately and later reissues a new profile.
11. **Risky remote change:** operator deploys with a confirmation window and lets automatic rollback protect management access.
12. **Emergency recovery:** Telegram is unavailable or busy, so the operator uses SSH and `hubctl` to inspect and roll back.

## 9. Telegram Bot Documentation and Product Localization

### 9.1 Product behavior

The default bot interface changes from Russian-only to English. Russian remains available through an explicit locale setting. English and Russian strings are maintained in code with stable callback identifiers. Simplified Chinese bot UI is not required for the first release, but the Chinese documentation explains the English button labels exactly.

Authorization remains an exact configured Telegram administrator ID check. The bot is an optional privileged operations surface, not the only recovery channel.

### 9.2 Dedicated documentation section

The bot section covers:

- creating a bot and finding the administrator ID;
- securing `telegram.yaml` and validating it with `vpn-hub-bot check`;
- starting and checking the systemd service;
- all slash commands: start/menu/help, status, devices, tunnels, deploy, subscriptions, routes, client ACLs, logs, host, hub, settings, and cancel;
- the complete main menu and navigation model;
- notification categories and out-of-band change notifications;
- operation serialization and the SSH/CLI fallback path.

### 9.3 Bot workflow examples

Document every user-visible mutation and confirmation path:

- inspect status and pending deployment insurance;
- add a device, accept a suggested address, select egress, and receive profile/QR;
- send a stored profile again;
- change device egress;
- reissue or revoke a device with confirmation;
- enable, disable, and probe tunnels;
- change tunnel access restrictions;
- add and remove routes and DNS zones;
- configure TCP, HTTPS, and DNS probes;
- inspect subscriptions, refresh automatically, select a candidate, and restore last-known-good;
- add and remove client ACL rules;
- stage and apply a revision immediately;
- deploy with confirmation insurance, confirm it, or roll it back;
- edit hub endpoint, DNS address, client CIDR, and AWG parameters;
- rotate the hub key and explain the resulting device-profile impact;
- export the current configuration safely;
- view or download logs;
- inspect host resources and restart the agent;
- enable and disable notification categories;
- cancel an unfinished dialog and recover from stale buttons.

Examples use rendered message/button mockups generated from actual labels and tested state transitions. They must not contain a real bot token, chat ID, host, endpoint, key, or provider URL.

## 10. README Design

The three README files share the same structure and facts:

1. Product name and one-sentence proposition
2. Language links
3. Focused badges: CI, latest release, license, Go version, documentation
4. Short architecture visual
5. Supported capability matrix
6. Safety properties and honest limitations
7. Five-minute evaluation path
8. Minimal redacted configuration
9. Links to installation, cookbook, bot guide, configuration reference, security policy, and contributing guide
10. Project status and support boundaries

The README is not a full manual. It should remain readable in several minutes and send detailed operational questions to the versioned site.

## 11. SEO and Repository Metadata

### 11.1 Website SEO

- Unique, factual title and description for every page
- Canonical URLs and locale alternates
- XML sitemap and `robots.txt`
- Open Graph and social preview image
- `SoftwareApplication` structured data on the landing page
- `TechArticle` and breadcrumb structured data for documentation
- Semantic headings, descriptive link text, image dimensions, and useful alt text
- Fast static delivery with no blocking third-party scripts
- Natural use of terms such as self-hosted VPN hub, AmneziaWG gateway, multi-VPN routing, WireGuard egress, split DNS, and Telegram VPN management

Keyword stuffing, hidden text, fabricated testimonials, fake usage metrics, comparison claims without evidence, and machine-generated filler are prohibited.

### 11.2 GitHub metadata

Populate:

- description: `Self-hosted multi-VPN hub with per-device routing, private networks, split DNS, fail-closed egress, and Telegram operations.`
- homepage: the deployed GitHub Pages URL
- topics: `vpn`, `wireguard`, `amneziawg`, `golang`, `self-hosted`, `linux`, `networking`, `policy-routing`, `split-dns`, `telegram-bot`, `openvpn`, `xray`
- release notes and changelog
- repository social preview
- issue and pull-request templates where useful

Apache-2.0 is the recommended license because it is permissive and includes an explicit patent grant. The final license addition is a publication checkpoint because the current repository has no declared license.

## 12. Publication and Security Gates

Public release is blocked until all validated medium-severity findings and publication-sensitive leaks are remediated or explicitly documented as unsupported configurations. Low-severity release-integrity issues should also be fixed because they directly affect trust in the first release.

Required gates include:

- replace the lab-derived AmneziaWG dump with synthetic data;
- rotate the exposed laboratory key outside the repository;
- remove the secret from the public Git history;
- reject unsafe OpenVPN file-reference directives;
- bound subscription candidates and total refresh time;
- prevent VLESS candidates from targeting special-use/internal destinations;
- make mixed-egress DNS source-aware or reject the unsafe configuration;
- require an explicit restricted SSH CIDR by default;
- use safe private temporary files in privileged integration tests;
- ignore local runtime state and reject accidental tracked runtime secrets;
- pin GitHub Actions by full commit SHA;
- bind release publication to successful CI for the exact commit;
- validate deployment artifact workflow, result, ref, SHA, and checksums;
- generate a directly usable flat checksum manifest;
- remove or update inaccurate README claims;
- scan current source and the intended public history for credentials, personal infrastructure, private email, and assistant-generated commit metadata.

The current private repository history contains publication-sensitive metadata and an earlier secret-shaped fixture. Creating a clean public history or rewriting and force-pushing the existing history is destructive and requires separate explicit operator approval.

## 13. Release and Deployment Design

The first public version is expected to be `v0.1.0` unless an existing version policy is discovered before implementation.

Release flow:

1. Run formatting, vet, unit, golden, integration-eligible, site, link, and secret checks.
2. Build all three Linux binaries with an observable version, commit, and build date.
3. Generate flat `SHA256SUMS` and verify it in CI.
4. Publish a GitHub Release only from a protected tag whose exact commit passed CI.
5. Build and deploy the documentation site from the same public revision.
6. Verify public URLs, metadata, assets, release downloads, and checksum commands.
7. Deploy the exact verified release artifact to the configured `hub` environment.
8. Verify service status, active revision, tunnel probes, and rollback readiness without exposing secrets in logs.

No push, tag, repository visibility change, history rewrite, GitHub Release, Pages deployment, or host deployment is considered successful until its resulting external state has been inspected.

## 14. Verification Strategy

### 14.1 Code and security

- `gofmt` check
- `go vet ./...`
- `go test ./...`
- existing race and integration targets where the environment supports them
- targeted tests for every security fix
- current-tree and history secret scans
- a final security diff review

### 14.2 Documentation

- compare every command page with generated `--help` output;
- compare configuration reference with parser structs and validation tests;
- execute or mechanically validate every copy-pasteable command where safe;
- check internal and external links;
- verify all promised pages exist in all three locales;
- review translations for preserved identifiers and protocol semantics;
- maintain a requirement-to-page coverage matrix for every recipe and bot workflow.

### 14.3 Website

- production build under the GitHub Pages base path;
- automated route and broken-link checks;
- desktop and mobile browser walkthroughs;
- keyboard navigation and visible focus;
- WCAG AA contrast and reduced-motion behavior;
- correct canonical, alternate, sitemap, robots, Open Graph, and structured data;
- Lighthouse-oriented performance checks without optimizing away necessary content.

### 14.4 Release and deployment

- download release assets as a user would;
- run the documented checksum verification command;
- compare embedded binary version to tag and commit;
- confirm GitHub Pages serves English at the root and localized routes correctly;
- inspect GitHub description, homepage, topics, license, and social preview;
- inspect deployment workflow provenance;
- verify the deployed services and health probes after rollout.

## 15. Success Criteria

The work is complete only when:

- a new user can deploy and verify the supported minimal configuration from the public docs;
- every accepted configuration family and public command is documented;
- the Cookbook covers initial setup, every egress type, private routing, DNS, devices, ACLs, SOCKS, subscriptions, fallback ingress, safety, recovery, and maintenance;
- every Telegram menu and user-visible operation has an accurate example;
- English, Russian, and Simplified Chinese README files and site content are complete and linked;
- the landing page communicates the real differentiators without unsupported claims;
- source, examples, fixtures, generated assets, and intended public history contain no live keys, tokens, personal hosts, or private infrastructure identifiers;
- the security and release gates in this design have evidence-backed verification;
- repository metadata is populated and the repository has an explicit license;
- the first public release is downloadable and verifiable;
- the documentation site and latest application version are deployed and inspected.

## 16. Deferred Scope

- A hosted commercial control plane
- Multi-user Telegram authorization and role-based access control
- A web administration dashboard
- Native mobile or desktop clients
- Full Chinese Telegram UI in the first release
- Performance or anonymity claims without reproducible benchmarks

These items may be considered later but are not substitutes for any success criterion above.
