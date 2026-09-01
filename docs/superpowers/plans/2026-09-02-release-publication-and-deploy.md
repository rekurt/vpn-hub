# Release, Publication, and Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a tested, attributable `v0.1.0` release, publish the documentation and repository metadata, clean sensitive history with explicit approval, and deploy the exact verified release.

**Architecture:** Reuse CI as the release gate, package binaries and installation files into one checksummed and attested archive, and make deployment consume only a GitHub Release. Deploy the static site through pinned GitHub Pages actions and verify every external result.

**Tech Stack:** GitHub Actions, GitHub CLI, Go 1.26, npm/Astro, SHA-256, GitHub attestations, SSH/systemd, GitHub Pages

**Spec:** `docs/superpowers/specs/2026-09-01-publication-site-docs-design.md`

## Global Constraints

- Every Action uses a full commit SHA with a version comment.
- A release tag's exact commit must pass the reusable CI workflow.
- Deployment never builds source and never mixes files from different revisions.
- Deployment remains manual behind the `hub` environment and a pinned SSH host key.
- Never print secret values, full private keys, hostnames, or deployed configuration.
- Force-pushing cleaned history and changing repository visibility require their explicit checkpoints.
- Use the configured Git identity and conventional commits.

## Reviewed Action Pins

```text
actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a # v9.3.0
opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4 # v2.0.2
gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e # v3.0.0
withastro/action@e84f40bd8d2caa9e768ec82ad30dd81f0b280853 # v6.1.2
actions/deploy-pages@cd2ce8fcbc39b97be8ca5fce6e763baed58fa128 # v5.0.0
actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
```

Re-resolve these tags before editing. A changed target requires review.

---

### Task 1: Add Observable Build Metadata

**Files:**
- Create: `internal/buildinfo/buildinfo.go`
- Create: `internal/buildinfo/buildinfo_test.go`
- Modify: `internal/delivery/cli/hubctl.go`
- Modify: `internal/delivery/cli/agent.go`
- Modify: `internal/delivery/cli/bot.go`
- Modify: `Makefile`

**Interfaces:**
- Produces: `buildinfo.Version`, `Commit`, and `Date`; defaults are `dev`, `unknown`, `unknown`.
- Produces: `buildinfo.String()` as `<version> (commit <commit>, built <date>)`.
- Produces: `version` command and Cobra `--version` for all three binaries.

- [ ] **Step 1: Write failing tests**

Assert defaults are non-empty and all three root commands expose the same build string and a child command writing exactly one line.

- [ ] **Step 2: Verify failure**

Run: `go test ./internal/buildinfo ./internal/delivery/cli -run Version`

Expected: FAIL because the package and commands do not exist.

- [ ] **Step 3: Implement and wire metadata**

Release builds set:

```text
-X vpn-hub/internal/buildinfo.Version=<tag>
-X vpn-hub/internal/buildinfo.Commit=<full-sha>
-X vpn-hub/internal/buildinfo.Date=<commit-time-in-UTC>
```

Add `VERSION`, `COMMIT`, `BUILD_DATE`, and one `GO_LDFLAGS` to Make. Remove the ineffective `main.version` linker target.

- [ ] **Step 4: Verify and commit**

Run `go test ./internal/buildinfo ./internal/delivery/cli` and build all Linux binaries with fixed values; assert every `version` output matches.

```bash
git add internal/buildinfo internal/delivery/cli Makefile
git commit -m "feat: expose release build metadata"
```

### Task 2: Make CI Reusable, Complete, and Immutable

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/dependabot.yml`
- Create: `scripts/verify-workflows.sh`
- Modify: `Makefile`

**Interfaces:**
- Produces: reusable CI with jobs `build`, `lint`, `integration`, `terraform`, `site`, and `publication`.

- [ ] **Step 1: Write failing workflow policy assertions**

Require `workflow_call`, `make site-check`, and `make publication-check`; reject every `uses: owner/action@vN` and `version: latest`.

- [ ] **Step 2: Pin and complete CI**

Use the reviewed SHAs, explicit minimum permissions, Node 24 for the site, a fixed golangci-lint version, and all existing race/vet/integration/OpenTofu checks. Add weekly grouped Dependabot updates for Go modules, `/site` npm, and Actions without auto-merge.

- [ ] **Step 3: Verify and commit**

Run: `sh scripts/verify-workflows.sh && make ci && make site-check && make publication-check`

```bash
git add .github/workflows/ci.yml .github/dependabot.yml scripts/verify-workflows.sh Makefile
git commit -m "ci: enforce complete immutable quality gates"
```

### Task 3: Package and Publish One Verified Release Bundle

**Files:**
- Replace: `.github/workflows/release.yml`
- Create: `scripts/package-release.sh`
- Create: `scripts/package-release_test.sh`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces: `dist/vpn-hub_<version>_linux_amd64.tar.gz` and flat `dist/SHA256SUMS`.
- Bundle includes three binaries, `install.sh`, both systemd units, `LICENSE`, `README.md`, and `RELEASE.json`.

- [ ] **Step 1: Write the failing package test**

Build with fixed version/commit/date and assert archive paths, required files, binary version output, release JSON, deterministic rebuild hash, and `(cd dist && sha256sum -c SHA256SUMS)`.

- [ ] **Step 2: Verify failure**

Run: `sh scripts/package-release_test.sh`

Expected: FAIL because packaging does not exist.

- [ ] **Step 3: Implement deterministic packaging**

Use commit `SOURCE_DATE_EPOCH`, sorted tar entries, numeric owner/group zero, gzip without original timestamp/name, and generate checksums from inside `dist/` so entries contain basenames.

- [ ] **Step 4: Replace the release workflow**

Trigger only `v*` tags. Call `./.github/workflows/ci.yml` as `quality`; make `release` depend on it. Build/package the exact tag, upload a short-retention artifact, attest the tarball, extract the matching changelog section, and run:

```sh
gh release create "$GITHUB_REF_NAME" dist/*.tar.gz dist/SHA256SUMS \
  --verify-tag --title "$GITHUB_REF_NAME" --notes-file release-notes.md
```

- [ ] **Step 5: Verify and commit**

Run: `sh scripts/package-release_test.sh && sh scripts/verify-workflows.sh`

```bash
git add .github/workflows/release.yml scripts/package-release.sh scripts/package-release_test.sh CHANGELOG.md
git commit -m "ci: publish verified release bundles"
```

### Task 4: Deploy Only a Verified GitHub Release

**Files:**
- Replace: `.github/workflows/deploy.yml`
- Modify: `deploy/install.sh`
- Create: `scripts/verify-deploy-workflow.sh`

**Interfaces:**
- Replaces: `run_id` with optional semver `version`; blank selects latest stable release.
- Consumes: release tarball, checksum, attestation, and bundled installer/units.

- [ ] **Step 1: Write failing policy assertions**

Reject `download-artifact`, `go build`, `run_id`, and checkout-sourced install files. Require `gh release download`, `sha256sum -c`, `gh attestation verify`, `RELEASE.json`, `environment: hub`, and pinned known hosts.

- [ ] **Step 2: Verify failure**

Run: `sh scripts/verify-deploy-workflow.sh`

Expected: FAIL against the current workflow.

- [ ] **Step 3: Implement release resolution and verification**

Validate `^v[0-9]+\.[0-9]+\.[0-9]+$`; when blank, query latest stable release. Reject draft/prerelease metadata. Download both assets, verify checksum and attestation, extract, and require `RELEASE.json.version` to equal the selected tag.

- [ ] **Step 4: Preserve secure provisioning and deploy the bundle**

Keep environment approval, secret presence checks, numeric AdminID, stdin/atomic `telegram.yaml`, and SSH host pin. Add optional `TELEGRAM_LOCALE`, default `en`, validate `en|ru`. Empty `/run/vpn-hub-stage`, copy only extracted bundle files, and run its `install.sh`.

- [ ] **Step 5: Verify the deployed version**

Over SSH, require active agent, `hubctl status`, and matching `version` output from hubctl/agent. If bot configured, run `vpn-hub-bot check`, require active unit, and match version. Logs expose only states, version, revision prefix, and probe summaries.

- [ ] **Step 6: Verify and commit**

Run: `sh scripts/verify-deploy-workflow.sh && sh scripts/verify-workflows.sh`

```bash
git add .github/workflows/deploy.yml deploy/install.sh scripts/verify-deploy-workflow.sh
git commit -m "ci: deploy attested release bundles"
```

### Task 5: Deploy Documentation Through GitHub Pages

**Files:**
- Create: `.github/workflows/docs.yml`
- Modify: `scripts/verify-workflows.sh`
- Modify: `site/astro.config.mjs`

**Interfaces:**
- Produces: Pages deployment from `site/` on public-content changes to `master` and manual dispatch.

- [ ] **Step 1: Add failing assertions**

Require `pages: write`, `id-token: write`, pinned `withastro/action`, pinned `deploy-pages`, `path: ./site`, `environment: github-pages`, and concurrency cancellation.

- [ ] **Step 2: Implement workflow**

Use the reviewed action pins, content path filters, `workflow_dispatch`, `concurrency.group: pages`, and `cancel-in-progress: true`.

- [ ] **Step 3: Verify and commit**

Run: `make site-check && sh scripts/verify-workflows.sh`

```bash
git add .github/workflows/docs.yml scripts/verify-workflows.sh site/astro.config.mjs
git commit -m "ci(site): deploy documentation to GitHub Pages"
```

### Task 6: Replace Sensitive History With a Clean Public Root

**Files:**
- Create: `docs/publication/history-cleanup.md`

**Interfaces:**
- Produces: a clean-root `master` and local recovery ref `refs/archive/pre-publication`.

- [ ] **Step 1: Prove current history fails publication checks**

Run: `sh scripts/check-publication.sh --history`

Expected: historical secret/metadata categories are reported without printing full values.

- [ ] **Step 2: Obtain explicit destructive approval**

Describe the exact one-root-commit replacement and `--force-with-lease`. Do not continue until the operator explicitly approves history rewrite and force-push.

- [ ] **Step 3: Create local recovery and root commit**

With a clean worktree:

```bash
old_sha=$(git rev-parse master)
git update-ref refs/archive/pre-publication "$old_sha"
tree=$(git write-tree)
clean_commit=$(printf '%s\n' 'feat: publish VPN Hub' | git commit-tree "$tree")
git update-ref refs/heads/feat/public-release "$clean_commit"
git switch feat/public-release
```

- [ ] **Step 4: Verify before pushing**

Run `git rev-list --count HEAD` and require one; run the history publication check; compare archived and clean trees with `git diff --exit-code refs/archive/pre-publication^{tree} HEAD^{tree}`.

- [ ] **Step 5: Force-push with lease and restore branch name**

```bash
git push --force-with-lease=master:"$old_sha" origin feat/public-release:master
git branch -D master
git branch -m master
```

Never push the archive ref. Fresh-clone the remote into a temporary directory and rerun the history check.

- [ ] **Step 6: Document recovery and commit**

```bash
git add docs/publication/history-cleanup.md
git commit -m "docs: record public history provenance"
git push origin master
```

### Task 7: Populate GitHub Metadata and Visibility

**Files:**
- Consume: `site/public/social-card.svg`
- External: GitHub repository settings

**Interfaces:**
- Produces: description, homepage, 12 topics, license detection, social preview, templates, security policy, and Pages source.

- [ ] **Step 1: Set metadata**

```bash
gh repo edit rekurt/vpn-hub \
  --description "Self-hosted multi-VPN hub with per-device routing, private networks, split DNS, fail-closed egress, and Telegram operations." \
  --homepage "https://rekurt.github.io/vpn-hub/" \
  --add-topic vpn --add-topic wireguard --add-topic amneziawg --add-topic golang \
  --add-topic self-hosted --add-topic linux --add-topic networking \
  --add-topic policy-routing --add-topic split-dns --add-topic telegram-bot \
  --add-topic openvpn --add-topic xray
```

- [ ] **Step 2: Configure Pages and social preview**

Set Pages build source to Actions. Render the SVG social card to 1280×640 PNG and upload it through authenticated repository settings because `gh repo edit` has no social-preview option.

- [ ] **Step 3: Inspect metadata while private**

Verify exact description/homepage/topics/license/Pages/social preview/security/templates with `gh repo view` plus settings UI.

- [ ] **Step 4: Obtain explicit visibility approval**

Ask approval to change `rekurt/vpn-hub` from private to public only after clean history and checks pass.

- [ ] **Step 5: Change and verify visibility**

```bash
gh repo edit rekurt/vpn-hub --visibility public --accept-visibility-change-consequences
gh repo view rekurt/vpn-hub --json isPrivate,url
```

Require `isPrivate: false` and unauthenticated access.

### Task 8: Publish `v0.1.0`, Deploy Pages, and Deploy the Hub

**Files:**
- Create: `docs/publication/v0.1.0-release-evidence.md`
- External: Git tag, GitHub Release, Pages, `hub` environment

**Interfaces:**
- Produces: verifiable `v0.1.0`, live locale site, and deployed binaries reporting `v0.1.0`.

- [ ] **Step 1: Preflight names without reading secret values**

Run `gh auth status`, inspect `repos/rekurt/vpn-hub/environments/hub`, and `gh secret list --env hub`. Require `HUB_SSH_KEY`, `HUB_HOST`, and `HUB_HOST_KEY`; Telegram secrets remain optional.

- [ ] **Step 2: Run release-candidate verification**

```bash
make publication-check
make ci
make site-check
make test-integration-box
sh scripts/package-release_test.sh
git diff --check
test -z "$(git status --short)"
```

- [ ] **Step 3: Tag and push**

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin master
git push origin v0.1.0
```

Wait for the release workflow. Never move a successful published tag.

- [ ] **Step 4: Verify release as a consumer**

Download into a new temporary directory, run `sha256sum -c SHA256SUMS`, run `gh attestation verify` on the tarball, extract, and compare each binary's version/full commit with the tag target.

- [ ] **Step 5: Deploy and verify Pages**

Wait for or dispatch `docs.yml`. Require unauthenticated HTTP 200 for root, `/ru/`, `/zh-cn/`, cookbook, bot guide, sitemap, robots, and social card; inspect canonical and hreflang.

- [ ] **Step 6: Deploy the exact release**

Run `gh workflow run deploy.yml --repo rekurt/vpn-hub -f version=v0.1.0`, wait through environment approval, and require successful version/unit/status checks.

- [ ] **Step 7: Record and commit final evidence**

Record non-sensitive URLs, run IDs, commit/tag, checksum, HTTP checks, service summaries, history scan, and goal-requirement coverage.

```bash
git add docs/publication/v0.1.0-release-evidence.md
git commit -m "docs: record v0.1.0 release evidence"
git push origin master
```
