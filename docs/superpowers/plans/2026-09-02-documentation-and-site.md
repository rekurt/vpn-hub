# Documentation and Public Website Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a fast, distinctive, English-first product site and complete EN/RU/ZH-CN documentation that covers every supported configuration, command, cookbook recipe, use case, and Telegram workflow.

**Architecture:** Build a static Astro/Starlight site under `site/`, with a custom landing page and shared product-specific components. Treat English content as canonical, enforce a locale/file parity manifest, derive command and bot examples from tested source artifacts, and keep repository README files concise entry points into the versioned site.

**Tech Stack:** Astro 7.2.10, Starlight 0.41.11, `@astrojs/sitemap` 3.7.4, Sharp 0.35.4, TypeScript, Markdown/MDX, Pagefind, npm, Playwright-based browser verification

**Spec:** `docs/superpowers/specs/2026-09-01-publication-site-docs-design.md`

## Global Constraints

- English is served at `/`; Russian at `/ru/`; Simplified Chinese at `/zh-cn/`.
- The project site must work at `https://rekurt.github.io/vpn-hub/` with Astro base `/vpn-hub`.
- Every promised content route must exist in all three locales; fallback content is not accepted as completion.
- Commands, flags, configuration keys, filenames, callbacks, unit names, and protocol identifiers are never translated.
- Marketing claims must be demonstrable from code or tests and must state operational limits.
- The site has no analytics, tracking, cookies, remote fonts, or runtime backend.
- All decorative motion respects `prefers-reduced-motion`.
- Examples use RFC 5737/RFC 3849 addresses, `example.com` domains, and synthetic keys only.
- Use conventional commits after each independently testable task.

---

### Task 1: Scaffold a Reproducible Multilingual Starlight Site

**Files:**
- Create: `site/package.json`
- Create: `site/package-lock.json`
- Create: `site/astro.config.mjs`
- Create: `site/tsconfig.json`
- Create: `site/src/content.config.ts`
- Create: `site/src/styles/global.css`
- Create: `site/src/content/docs/en/docs/index.mdx`
- Create: `site/src/content/docs/ru/docs/index.mdx`
- Create: `site/src/content/docs/zh-cn/docs/index.mdx`
- Create: `site/scripts/verify-content.mjs`
- Modify: `.gitignore`
- Modify: `Makefile`

**Interfaces:**
- Produces: npm scripts `dev`, `build`, `preview`, `check`, and `verify:content`.
- Produces: `make site`, `make site-check`, and a static output at `site/dist/`.

- [ ] **Step 1: Write the failing content verifier**

`verify-content.mjs` must enumerate Markdown/MDX paths below `en`, `ru`, and `zh-cn`; compare relative paths; reject missing locale peers; reject duplicate `slug`; and reject frontmatter without non-empty `title` and `description`. The initial test run must fail while only one locale page exists.

- [ ] **Step 2: Create the package manifest**

Use this dependency floor and pin exact versions in the lockfile:

```json
{
  "name": "vpn-hub-site",
  "private": true,
  "type": "module",
  "engines": {"node": ">=22.18.0"},
  "scripts": {
    "dev": "astro dev",
    "build": "astro build",
    "preview": "astro preview",
    "check": "astro check",
    "verify:content": "node scripts/verify-content.mjs"
  },
  "dependencies": {
    "@astrojs/sitemap": "3.7.4",
    "@astrojs/starlight": "0.41.11",
    "astro": "7.2.10",
    "sharp": "0.35.4"
  },
  "devDependencies": {
    "@astrojs/check": "0.9.10",
    "typescript": "6.0.3"
  }
}
```

Run `npm install` inside `site/` to produce the lockfile.

- [ ] **Step 3: Configure Astro and Starlight**

Set `site: 'https://rekurt.github.io'`, `base: '/vpn-hub'`, `trailingSlash: 'always'`, sitemap integration, and Starlight locales:

```js
locales: {
  root: { label: 'English', lang: 'en' },
  ru: { label: 'Русский', lang: 'ru' },
  'zh-cn': { label: '简体中文', lang: 'zh-CN' },
}
```

Enable Pagefind. Configure the same explicit sidebar groups for all locales: Start, Concepts, Configuration, CLI, Cookbook, Use cases, Telegram bot, Operations, Security, Reference.

- [ ] **Step 4: Add minimal locale home pages and global tokens**

Each index page must have locale-specific title/description and link to its quickstart. Define CSS custom properties for navy, warm white, cyan, amber, coral, muted text, grid lines, focus rings, prose width, and monospace stacks.

- [ ] **Step 5: Add build targets and ignores**

Ignore `site/node_modules/`, `site/dist/`, `.astro/`, and `.pagefind/`. Make targets run `npm ci`, content verification, `astro check`, and production build.

- [ ] **Step 6: Verify**

Run:

```bash
cd site && npm ci && npm run verify:content && npm run check && npm run build
cd .. && make site-check
```

Expected: PASS and the custom landing pages plus `site/dist/docs/index.html`, `site/dist/ru/docs/index.html`, and `site/dist/zh-cn/docs/index.html` exist.

- [ ] **Step 7: Commit**

```bash
git add .gitignore Makefile site
git commit -m "feat(site): scaffold multilingual documentation"
```

### Task 2: Build the Product-Specific Landing System

**Files:**
- Create: `site/src/pages/index.astro`
- Create: `site/src/pages/ru/index.astro`
- Create: `site/src/pages/zh-cn/index.astro`
- Create: `site/src/layouts/LandingLayout.astro`
- Create: `site/src/components/SiteHeader.astro`
- Create: `site/src/components/SiteFooter.astro`
- Create: `site/src/components/RouteMap.astro`
- Create: `site/src/components/ProtocolRail.astro`
- Create: `site/src/components/UseCaseGrid.astro`
- Create: `site/src/components/SafetyModel.astro`
- Create: `site/src/components/BotPreview.astro`
- Create: `site/src/components/CookbookPreview.astro`
- Create: `site/src/data/landing.ts`
- Create: `site/src/styles/landing.css`
- Create: `site/scripts/verify-landing.mjs`
- Modify: `site/package.json`

**Interfaces:**
- Produces: `LandingCopy` with identical typed sections for `en`, `ru`, and `zh-cn`.
- Produces: custom locale landing pages sharing structure and product visuals without duplicating markup.
- Consumes: `site/src/data/bot-screens.en.json` and `.ru.json` produced by Task 6 of the bot-localization plan. Complete that plan before this task.

- [ ] **Step 1: Write structural landing tests**

The verifier must parse built HTML for each locale and assert one `h1`, navigation landmarks, two primary CTAs, architecture section, protocol list, safety section, use cases, bot preview, cookbook preview, final CTA, footer, skip link, and locale switch links. It must reject the phrases `next-generation`, `revolutionary`, `seamless`, `military-grade`, and `AI-powered` case-insensitively.

- [ ] **Step 2: Run and verify failure**

Run: `cd site && npm run build && node scripts/verify-landing.mjs`

Expected: FAIL because the custom pages and sections do not exist.

- [ ] **Step 3: Implement layout, header, and route-map hero**

English hero copy:

```text
One connection. Every network. No silent fallback.
Route each device and private destination through the egress you chose—then fail closed when that path is unavailable.
```

Primary actions are `Deploy your hub` and `View on GitHub`. RouteMap visually connects devices to a policy node, then to Direct, WireGuard/AWG, Xray/VLESS, and OpenVPN outputs. Use semantic SVG lines and labels; the diagram remains understandable without animation.

- [ ] **Step 4: Implement proof, scenarios, safety, bot, and cookbook sections**

Populate copy from `landing.ts`, with all three locales required by TypeScript. SafetyModel explicitly states root operation, no direct fallback, provider input trust, profile-key retention by the bot, and SSH recovery. UseCaseGrid contains the 12 scenarios from the spec. BotPreview reads real fixture labels and shows the safe-deploy sequence.

- [ ] **Step 5: Implement responsive and accessible styles**

Use CSS grid/container queries, visible focus, 44px interactive targets on mobile, readable 65–75 character prose, no horizontal scrolling at 320px, and zero transition duration under reduced motion.

- [ ] **Step 6: Verify**

Run: `cd site && npm run check && npm run build && node scripts/verify-landing.mjs`

Expected: PASS for all locale pages.

- [ ] **Step 7: Commit**

```bash
git add site/src/pages site/src/layouts site/src/components site/src/data/landing.ts site/src/styles/landing.css site/scripts/verify-landing.mjs site/package.json site/package-lock.json
git commit -m "feat(site): add product landing experience"
```

### Task 3: Add Complete English Start, Concepts, and Configuration Reference

**Files:**
- Create: `site/src/content/docs/en/docs/start/{requirements,install,terraform,first-hub,first-device,verify}.mdx`
- Create: `site/src/content/docs/en/docs/concepts/{architecture,desired-state,routing,kill-switch,dns,private-networks,client-isolation,subscriptions,health,secrets}.mdx`
- Create: `site/src/content/docs/en/docs/configuration/{overview,hub,devices,tunnels,wireguard,amneziawg,xray-vless,openvpn,socks,private-networks,health,subscriptions,client-acls}.mdx`
- Create: `site/src/components/ArchitectureDiagram.astro`
- Create: `site/src/components/ConfigField.astro`
- Create: `site/src/components/VerifyBlock.astro`
- Create: `site/src/data/config-schema.json`
- Create: `site/scripts/extract-config-schema.mjs`

**Interfaces:**
- Produces: a versioned JSON inventory of every `mapstructure` configuration field and accepted enum value.
- Produces: documentation pages whose frontmatter `coverage` arrays account for every schema path.

- [ ] **Step 1: Build a failing schema coverage extractor**

Extract tags from `internal/domain/model.go`, `internal/domain/fallback.go`, `internal/domain/healthcheck.go`, and related embedded structs. Compare the resulting paths with frontmatter coverage entries and fail on undocumented or invented paths.

- [ ] **Step 2: Run and verify failure**

Run: `cd site && node scripts/extract-config-schema.mjs --check`

Expected: FAIL because `config-schema.json` and coverage pages do not exist.

- [ ] **Step 3: Write start and concept pages**

Every procedural page includes prerequisites, exact commands, expected result, verification, rollback, and next links. Architecture pages distinguish operator configuration, persisted redacted desired state, root agent reconciliation, Telegram mutations, namespaces, nftables, and external provider boundaries.

- [ ] **Step 4: Write field-level configuration reference**

For every field, document type, required/default behavior, validation, secret classification, side effects, and minimal synthetic example. Explicitly document:

- bot-managed private profile key retention at mode `0600`;
- CLI profile generation behavior;
- actual firewall ports 22/TCP, 51820/UDP, optional 443/TCP+UDP, and ICMP;
- inline SOPS-encrypted OpenVPN credentials;
- source-aware mixed-egress DNS;
- no in-place repair guarantee for an nft rule changed without fingerprint drift.

- [ ] **Step 5: Generate and verify schema inventory**

Run:

```bash
cd site
node scripts/extract-config-schema.mjs --write
node scripts/extract-config-schema.mjs --check
npm run verify:content
npm run build
```

Expected: every accepted field is covered exactly once or explicitly cross-referenced.

- [ ] **Step 6: Commit**

```bash
git add site/src/content/docs/en/docs/start site/src/content/docs/en/docs/concepts site/src/content/docs/en/docs/configuration site/src/components/ArchitectureDiagram.astro site/src/components/ConfigField.astro site/src/components/VerifyBlock.astro site/src/data/config-schema.json site/scripts/extract-config-schema.mjs
git commit -m "docs: add English setup and configuration guide"
```

### Task 4: Add Verified CLI, Agent, and Operations Reference

**Files:**
- Create: `site/src/content/docs/en/docs/cli/{hubctl,agent,bot}.mdx`
- Create: `site/src/content/docs/en/docs/operations/{systemd,deploy-confirm-rollback,upgrade,backup-restore,key-rotation,device-recovery,logs-diagnostics,drift,incident-response,uninstall}.mdx`
- Create: `scripts/export-cli-help.sh`
- Create: `site/src/data/cli-help/{hubctl,vpn-hub-agent,vpn-hub-bot}.txt`
- Create: `site/scripts/verify-cli-docs.mjs`
- Modify: `Makefile`

**Interfaces:**
- Produces: deterministic `--help` snapshots from all three binaries.
- Produces: docs frontmatter `commands` entries checked against the Cobra command tree text.

- [ ] **Step 1: Write the failing CLI coverage verifier**

Parse command headings from snapshots and compare them with page frontmatter. Require every command and flag listed in the spec, including nested tunnel/device/ACL/subscription operations.

- [ ] **Step 2: Export current command help**

The script builds binaries into a temporary directory and recursively invokes each command's `--help` without writing repository-local runtime state. Normalize absolute temporary paths before committing snapshots.

- [ ] **Step 3: Write reference and operations pages**

Each command documents permissions, inputs, output form, side effects, dry-run support, and recovery. Operations pages explain service ordering, safe deployment timers, checksums, exact backup inclusions/exclusions, SOPS age key handling, revocation, rollback over SSH, and clean uninstall.

- [ ] **Step 4: Wire and verify snapshots**

Add `cli-docs` and `cli-docs-check` Make targets. Run:

```bash
make cli-docs
make cli-docs-check
cd site && node scripts/verify-cli-docs.mjs && npm run build
```

Expected: PASS and no public Cobra command is undocumented.

- [ ] **Step 5: Commit**

```bash
git add Makefile scripts/export-cli-help.sh site/src/data/cli-help site/scripts/verify-cli-docs.mjs site/src/content/docs/en/docs/cli site/src/content/docs/en/docs/operations
git commit -m "docs: add verified command and operations reference"
```

### Task 5: Write the Complete English Cookbook and Use-Case Catalog

**Files:**
- Create: `site/src/content/docs/en/docs/cookbook/{local-dry-run,release-install,digitalocean,restrict-ssh,sops,bot-optional,direct-egress,wireguard-egress,amneziawg-egress,xray-vless-egress,openvpn-egress,change-egress,shared-egress,allowed-devices,tunnel-toggle,tunnel-probes,kill-switch,private-subnet,routes,split-dns,multiple-private-networks,route-conflicts,dns-verification,device-auto-address,device-explicit-address,device-qr,profile-redelivery,profile-reissue,device-revoke,client-acl-tcp,client-acl-udp,client-acl-any,client-acl-remove,socks-single-device,socks-shared,socks-application,subscription-setup,subscription-refresh,subscription-candidates,subscription-select,subscription-restore,subscription-failure,reality-fallback,udp443-fallback,fallback-ports,fallback-isolation,safe-deploy,confirm,rollback,connectivity-recovery,dns-route-recovery,agent-restart,revision-drift,logs,host-health,backup,restore,upgrade,checksums,hub-key-rotation,uninstall,integration-tests}.mdx`
- Create: `site/src/content/docs/en/docs/use-cases/{remote-engineer,personal-devices,family,infra-admin,private-dns,restricted-network,application-routing,provider-rotation,provider-outage,lost-device,risky-change,emergency-recovery}.mdx`
- Create: `site/src/data/cookbook-manifest.json`
- Create: `site/scripts/verify-cookbook.mjs`

**Interfaces:**
- Produces: one manifest record per recipe with `id`, `category`, `configurationFamilies`, `commands`, `verification`, and `rollback`.
- Produces: every use case linked to at least one start page and two concrete recipes where applicable.

- [ ] **Step 1: Write the manifest verifier**

Require all recipe files listed above, unique IDs, non-empty prerequisites/verification/rollback sections, no unsafe global SSH example, and coverage of configuration families `direct`, `wireguard`, `amneziawg`, `xray`, `openvpn`, `socks`, `private-network`, `subscription`, `fallback`, and `client-acl`.

- [ ] **Step 2: Run and verify failure**

Run: `cd site && node scripts/verify-cookbook.mjs`

Expected: FAIL because recipes and manifest are absent.

- [ ] **Step 3: Author task-oriented recipes**

Every recipe follows Goal, When to use, Prerequisites, Minimal configuration, Apply safely, Verify routing and DNS, Expected failure, Roll back, and Related recipes. Use the real command snapshots and configuration schema; do not duplicate unsupported flags.

- [ ] **Step 4: Author scenario narratives**

Each use case explains the operator problem, topology, policy choice, complete recipe path, security tradeoffs, and recovery path. Provider outage explicitly demonstrates that no traffic moves to direct.

- [ ] **Step 5: Build and verify**

Run: `cd site && node scripts/verify-cookbook.mjs && npm run verify:content && npm run build`

Expected: PASS with every cookbook category present in generated navigation.

- [ ] **Step 6: Commit**

```bash
git add site/src/content/docs/en/docs/cookbook site/src/content/docs/en/docs/use-cases site/src/data/cookbook-manifest.json site/scripts/verify-cookbook.mjs
git commit -m "docs: add complete VPN Hub cookbook"
```

### Task 6: Write the Dedicated Telegram Bot Guide and All Workflow Examples

**Files:**
- Create: `site/src/content/docs/en/docs/bot/{overview,setup,security,commands,menu,status,devices,tunnels,subscriptions,routes-acls,deploy-rollback,hub-settings,logs-host,notifications,recovery}.mdx`
- Create: `site/src/components/TelegramScreen.astro`
- Create: `site/src/components/BotFlow.astro`
- Create: `site/src/data/bot-use-cases.json`
- Create: `site/scripts/verify-bot-docs.mjs`

**Interfaces:**
- Consumes: `site/src/data/bot-screens.en.json` generated by the bot-localization plan.
- Produces: one documented workflow record for every bot command, menu item, mutation, confirmation, notification category, cancellation, stale-button response, and CLI fallback.

- [ ] **Step 1: Write the failing bot coverage verifier**

Read the generated screen JSON and `bot-use-cases.json`. Require every callback prefix `m`, `st`, `dev`, `tun`, `dep`, `sub`, `rt`, `acl`, `log`, `host`, `hub`, and `set`; all registered slash commands; and explicit dangerous-action confirmation sequences.

- [ ] **Step 2: Run and verify failure**

Run: `cd site && node scripts/verify-bot-docs.mjs`

Expected: FAIL because the guide and use-case mapping are absent.

- [ ] **Step 3: Build reusable Telegram components**

`TelegramScreen` renders tested text and button rows with accessible HTML. `BotFlow` links consecutive screen IDs and annotates operator action, state mutation, verification, and emergency CLI equivalent. Never imitate the Telegram brand as a screenshot or expose identifiers.

- [ ] **Step 4: Author all bot workflows**

Cover setup/check, authorization, status, devices, profile delivery/reissue/revoke, egress changes, tunnel lifecycle/access/routes/zones/probes, subscriptions and last-known-good, ACLs, insured/immediate deploy, confirm/rollback, hub edits/key rotation/export, logs/download, host/restart, settings/notifications, dialog cancel, busy operations, stale buttons, and SSH recovery.

- [ ] **Step 5: Verify**

Run: `make bot-docs-check && cd site && node scripts/verify-bot-docs.mjs && npm run build`

Expected: PASS and every example label matches generated bot output.

- [ ] **Step 6: Commit**

```bash
git add site/src/content/docs/en/docs/bot site/src/components/TelegramScreen.astro site/src/components/BotFlow.astro site/src/data/bot-use-cases.json site/scripts/verify-bot-docs.mjs
git commit -m "docs(bot): cover every Telegram workflow"
```

### Task 7: Add Security, Reference, and Project Governance Documentation

**Files:**
- Create: `site/src/content/docs/en/docs/security/{model,secrets,bot,provider-inputs,releases,limitations,checklist}.mdx`
- Create: `site/src/content/docs/en/docs/reference/{support-matrix,file-layout,systemd-units,firewall-ports,troubleshooting,glossary}.mdx`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `SUPPORT.md`
- Create: `CHANGELOG.md`
- Create: `.github/ISSUE_TEMPLATE/bug.yml`
- Create: `.github/ISSUE_TEMPLATE/feature.yml`
- Create: `.github/pull_request_template.md`

**Interfaces:**
- Produces: clear vulnerability reporting, contribution, support, behavior, changelog, issue, and review paths.
- Requires: operator license decision before adding `LICENSE`; the approved recommendation is Apache-2.0.

- [ ] **Step 1: Write security and reference content**

Base the threat model on the verified trust boundaries and assets. State root privilege, bot AdminID checks, provider distrust, SOPS/age path, profile-key retention, external firewall responsibility, DNS policy, fallback ports, and recovery limits without claiming anonymity.

- [ ] **Step 2: Write repository governance files**

Use concise project-specific text. `SECURITY.md` defines supported versions (`latest tagged release`), private reporting through GitHub Security Advisories, expected report fields, and 7-day acknowledgement target without promising a fix date. `CONTRIBUTING.md` lists Go/site prerequisites, local commands, integration-test isolation, conventional commits, and fixture rules.

- [ ] **Step 3: Obtain and apply the license checkpoint**

Ask the operator to choose Apache-2.0, MIT, or provide another license. If Apache-2.0 is approved, add the unmodified Apache License 2.0 text to `LICENSE` and name it in README/site metadata. Do not invent a copyright holder beyond the repository owner identity.

- [ ] **Step 4: Verify**

Run: `make publication-check && cd site && npm run verify:content && npm run build`

Expected: PASS; all governance links resolve and the selected license is present.

- [ ] **Step 5: Commit**

```bash
git add SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md SUPPORT.md CHANGELOG.md LICENSE .github/ISSUE_TEMPLATE .github/pull_request_template.md site/src/content/docs/en/docs/security site/src/content/docs/en/docs/reference
git commit -m "docs: add security and contributor guidance"
```

### Task 8: Create English, Russian, and Chinese Repository READMEs

**Files:**
- Replace: `README.md`
- Create: `README.ru.md`
- Create: `README.zh-CN.md`
- Create: `assets/architecture.svg`
- Create: `scripts/verify-readmes.sh`

**Interfaces:**
- Produces: concise locale-linked README files with the same facts, capability matrix, quick evaluation path, safety limits, and canonical documentation links.

- [ ] **Step 1: Write the README parity verifier**

Require all three files, reciprocal language links, headings for Features, Architecture, Safety, Quick start, Documentation, Project status, Contributing, Security, and License, plus links to the locale's quickstart/cookbook/bot/reference pages. Reject real-looking hosts and the banned marketing phrases from Task 2.

- [ ] **Step 2: Author the English canonical README**

Use the proposition, architecture SVG, supported-protocol matrix, fail-closed explanation, limitations, five-minute `validate --dry-run` path, minimal synthetic YAML, and links to the complete site. Keep it scannable and remove the current monolithic manual duplication.

- [ ] **Step 3: Translate to Russian and Simplified Chinese**

Preserve exact commands/configuration. Have each translation link to its locale site and to the other README languages. Do not translate product name, binaries, protocols, callback IDs, or YAML keys.

- [ ] **Step 4: Verify**

Run: `sh scripts/verify-readmes.sh && make publication-check && git diff --check`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md README.ru.md README.zh-CN.md assets/architecture.svg scripts/verify-readmes.sh
git commit -m "docs: publish multilingual repository guides"
```

### Task 9: Translate the Complete Site to Russian and Simplified Chinese

**Files:**
- Create: locale mirrors under `site/src/content/docs/ru/docs/`
- Create: locale mirrors under `site/src/content/docs/zh-cn/docs/`
- Modify: `site/scripts/verify-content.mjs`
- Create: `site/scripts/verify-translations.mjs`

**Interfaces:**
- Consumes: the complete English route tree.
- Produces: exact route parity and identifier parity for all three locales.

- [ ] **Step 1: Strengthen translation checks**

For every locale peer, compare fenced code blocks after normalizing prose comments, extract backticked identifiers and command invocations, and require all English config keys/flags/file paths to remain present. Reject Starlight fallback banners in built output.

- [ ] **Step 2: Translate Russian content section by section**

Translate title, description, prose, warnings, verification, failure, rollback, and link labels. Preserve bot English button labels in code formatting and add the tested Russian equivalent where the Russian bot locale applies.

- [ ] **Step 3: Translate Simplified Chinese content section by section**

Use natural technical Chinese, retain English bot labels exactly, and explain that the initial bot UI supports English and Russian. Preserve security qualifications and fail-closed semantics.

- [ ] **Step 4: Verify all locales**

Run:

```bash
cd site
npm run verify:content
node scripts/verify-translations.mjs
npm run check
npm run build
```

Expected: PASS with identical route counts and no fallback content.

- [ ] **Step 5: Commit**

```bash
git add site/src/content/docs/ru/docs site/src/content/docs/zh-cn/docs site/scripts/verify-content.mjs site/scripts/verify-translations.mjs
git commit -m "docs: add Russian and Chinese site translations"
```

### Task 10: Add SEO, Social Assets, and Browser-Level Quality Gates

**Files:**
- Create: `site/public/robots.txt`
- Create: `site/public/favicon.svg`
- Create: `site/public/social-card.svg`
- Create: `site/src/components/SEOHead.astro`
- Create: `site/src/components/StructuredData.astro`
- Create: `site/scripts/verify-seo.mjs`
- Create: `site/tests/site.spec.mjs`
- Create: `site/playwright.config.mjs`
- Modify: `site/package.json`
- Modify: `site/package-lock.json`
- Modify: `Makefile`

**Interfaces:**
- Produces: canonical/hreflang/Open Graph/Twitter metadata and JSON-LD for `SoftwareApplication`, `TechArticle`, and `BreadcrumbList`.
- Produces: `npm run test:site` against the production build at base `/vpn-hub/`.

- [ ] **Step 1: Add SEO verifier tests**

For every built HTML page, require a unique title/description, canonical URL, three alternates plus `x-default`, Open Graph image/title/description, one `h1`, and valid JSON-LD. Verify sitemap includes all locales and robots points at the base-aware sitemap URL.

- [ ] **Step 2: Implement metadata and original SVG assets**

The social card uses the route-map motif and proposition, no stock image. JSON-LD uses factual fields only: name, description, application category, operating system Linux, code repository, license URL, and current release only after it exists.

- [ ] **Step 3: Add browser tests**

Install `@playwright/test` version `1.62.1` and its matching Chromium build. Test desktop 1440×900 and mobile 390×844 for landing navigation, locale switching, docs search, cookbook route, bot flow, keyboard focus, no horizontal overflow, no console errors, and reduced-motion CSS.

- [ ] **Step 4: Verify production output**

Run:

```bash
cd site
npm run check
npm run build
node scripts/verify-seo.mjs
npx playwright test
```

Expected: PASS for all routes and viewports.

- [ ] **Step 5: Add complete site checks to Make**

`make site-check` must run content, translation, landing, CLI, cookbook, bot, SEO, Astro, build, and Playwright checks in that order.

- [ ] **Step 6: Commit**

```bash
git add Makefile site/public site/src/components/SEOHead.astro site/src/components/StructuredData.astro site/scripts/verify-seo.mjs site/tests site/playwright.config.mjs site/package.json site/package-lock.json
git commit -m "feat(site): add SEO and browser quality gates"
```
