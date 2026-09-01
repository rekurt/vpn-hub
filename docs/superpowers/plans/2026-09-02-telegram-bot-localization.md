# Telegram Bot English-First Localization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make English the Telegram bot's default interface, retain a complete Russian locale, and generate stable bot examples for the public documentation from real renderers.

**Architecture:** Introduce a small typed localization package inside the bot delivery layer. Keep callback data and operational behavior locale-neutral, inject one immutable localizer into renderers and handlers, and use dual-locale golden tests plus a generated documentation fixture to prevent untranslated or invented UI examples.

**Tech Stack:** Go 1.26, Telegram Bot API adapter, YAML configuration, golden tests, JSON documentation fixtures

**Spec:** `docs/superpowers/specs/2026-09-01-publication-site-docs-design.md`

## Global Constraints

- English is the default locale and Russian is selected only by `locale: ru` in `telegram.yaml`.
- Callback identifiers, command names, state transitions, and authorization behavior must not change.
- Every user-visible string, duration, age, plural, toast, alert, dialog prompt, and notification must come from the selected locale.
- Simplified Chinese bot UI is outside the first release; Chinese docs explain the English labels.
- No locale may weaken confirmation for deploy, rollback, revocation, reissue, key rotation, or agent restart.
- Existing test fakes and operation serialization remain authoritative.
- Use conventional commits after each independently reviewable task.

---

### Task 1: Add Locale Configuration and a Complete Catalog Contract

**Files:**
- Create: `internal/delivery/bot/locale.go`
- Create: `internal/delivery/bot/locale_en.go`
- Create: `internal/delivery/bot/locale_ru.go`
- Create: `internal/delivery/bot/locale_test.go`
- Modify: `internal/delivery/bot/config.go`
- Modify: `internal/delivery/bot/config_test.go`

**Interfaces:**
- Produces: `type Locale string` with `LocaleEnglish = "en"` and `LocaleRussian = "ru"`.
- Produces: `type MessageID string`, `type Catalog map[MessageID]string`, and `type Localizer struct { locale Locale; catalog Catalog }`.
- Produces: `func NewLocalizer(locale Locale) (Localizer, error)`, `func (l Localizer) Text(id MessageID, args ...any) string`, `func (l Localizer) Locale() Locale`.
- Extends: `bot.Config` with `Locale Locale`; omitted YAML defaults to `en`.

- [ ] **Step 1: Write failing configuration tests**

Add table cases:

```go
{"omitted defaults to English", "token: t\nadmin_id: 42\n", LocaleEnglish, ""},
{"Russian accepted", "token: t\nadmin_id: 42\nlocale: ru\n", LocaleRussian, ""},
{"unsupported rejected", "token: t\nadmin_id: 42\nlocale: de\n", "", `locale "de" is not supported; use en or ru`},
```

- [ ] **Step 2: Write catalog parity tests**

Assert the English and Russian maps contain exactly the same `MessageID` keys, values are non-empty, `fmt.Sprintf` placeholders match by verb and order, and no English entry contains Cyrillic outside protocol/identifier data supplied at runtime.

- [ ] **Step 3: Run and verify failure**

Run: `go test ./internal/delivery/bot -run 'Locale|Catalog|LoadConfig'`

Expected: FAIL because locale types and configuration do not exist.

- [ ] **Step 4: Implement locale primitives and config parsing**

Define stable IDs by feature prefix, for example:

```go
const (
	MsgMainTitle MessageID = "main.title"
	MsgMainIntro MessageID = "main.intro"
	MsgButtonStatus MessageID = "button.status"
	MsgButtonDevices MessageID = "button.devices"
	MsgConfirmYes MessageID = "confirm.yes"
	MsgConfirmNo MessageID = "confirm.no"
)
```

`Text` must panic in tests and return the ID in production only if a catalog key is missing; the parity test makes that state unreleasable. Add `locale` to the strict YAML wire struct and default it before validation.

- [ ] **Step 5: Verify**

Run: `go test -race ./internal/delivery/bot -run 'Locale|Catalog|LoadConfig'`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/delivery/bot/locale.go internal/delivery/bot/locale_en.go internal/delivery/bot/locale_ru.go internal/delivery/bot/locale_test.go internal/delivery/bot/config.go internal/delivery/bot/config_test.go
git commit -m "feat(bot): add English and Russian locales"
```

### Task 2: Localize Shared Formatting and Core Screens

**Files:**
- Modify: `internal/delivery/bot/render.go`
- Modify: `internal/delivery/bot/render_test.go`
- Rename: `internal/delivery/bot/testdata/*.golden` to `internal/delivery/bot/testdata/en/*.golden`
- Create: `internal/delivery/bot/testdata/ru/*.golden`

**Interfaces:**
- Produces: renderer signatures with `Localizer` as the first parameter, for example `renderMain(l Localizer)` and `renderStatus(l Localizer, view statusView)`.
- Produces: `formatDuration(l Localizer, d time.Duration)`, `formatAge(l Localizer, now, then time.Time)`, `formatBytes(l Localizer, bytes uint64)`, `onOff(l Localizer, enabled bool)`.

- [ ] **Step 1: Make golden tests locale-aware**

Change the golden helper to accept a locale and resolve `testdata/<locale>/<name>.golden`. Run every renderer subtest for both `en` and `ru` using the same view data.

- [ ] **Step 2: Run and verify the English failures**

Run: `go test ./internal/delivery/bot -run '^TestRender'`

Expected: FAIL because English goldens and localizer parameters are absent.

- [ ] **Step 3: Localize formatting helpers**

English examples must render `2d 5h`, `3m 20s`, `never`, `just now`, `5m ago`, `1.0 GiB`, and `on/off`. Russian output must remain `2д 5ч`, `3м 20с`, `никогда`, `только что`, `5м назад`, `1.0 ГиБ`, and `вкл/выкл`.

- [ ] **Step 4: Localize core renderers**

Move strings for main, status, devices, device card, egress choice, tunnel list/card/access/probes, routes, ACL list, deploy preview/countdown, subscriptions/candidates, logs, host, hub, and settings into the catalogs. Keep emoji and callback data stable.

- [ ] **Step 5: Generate and review both golden sets**

Run: `go test ./internal/delivery/bot -run '^TestRender' -update`

Then run without update: `go test ./internal/delivery/bot -run '^TestRender'`

Expected: PASS; `testdata/en/main.golden` starts with `Management hub`, and `testdata/ru/main.golden` retains the Russian equivalent.

- [ ] **Step 6: Commit**

```bash
git add internal/delivery/bot/render.go internal/delivery/bot/render_test.go internal/delivery/bot/testdata
git commit -m "feat(bot): localize rendered screens"
```

### Task 3: Localize Command Registration, Dialogs, and Device/Tunnel Workflows

**Files:**
- Modify: `internal/delivery/bot/bot.go`
- Modify: `internal/delivery/bot/dialog.go`
- Modify: `internal/delivery/bot/handlers_devices.go`
- Modify: `internal/delivery/bot/handlers_tunnels.go`
- Modify: `internal/delivery/bot/bot_test.go`
- Modify: `internal/delivery/bot/revert_test.go`

**Interfaces:**
- Extends: `Bot` with `L Localizer`, initialized from `Cfg.Locale` in `New` and `init`.
- Replaces: global `botCommands` with `func botCommands(l Localizer) []tg.BotCommand`.
- Produces: `func (b *Bot) text(id MessageID, args ...any) string`.

- [ ] **Step 1: Add behavior tests for English default and Russian selection**

Build two bots with otherwise identical fakes. Assert `/start`, `/cancel`, add-device prompts, revoke/reissue confirmations, tunnel enable/disable results, route/DNS-zone prompts, access changes, stale buttons, and operation-busy errors use the selected locale while callbacks remain byte-identical.

- [ ] **Step 2: Run and verify failure**

Run: `go test ./internal/delivery/bot -run 'English|Russian|Locale|CommandDescriptions'`

Expected: FAIL because handlers still contain direct Russian strings.

- [ ] **Step 3: Wire the localizer into the bot**

Initialize `L` once. Register English command descriptions by default and Russian descriptions for `locale: ru`. Convert startup, unknown command, empty cancel, dialog cancellation, authorization-neutral errors, and busy-operation messages to IDs.

- [ ] **Step 4: Convert device and tunnel workflows**

Replace direct strings in both handler files with `b.text(...)`. Pass `b.L` to renderers. Keep user data escaped at the existing boundary and never place localized strings into callback payloads.

- [ ] **Step 5: Add a source guard**

In `locale_test.go`, scan `*.go` in `internal/delivery/bot` and fail when Cyrillic appears outside `locale_ru.go` and test files. This prevents new Russian-only production strings.

- [ ] **Step 6: Verify**

Run: `go test -race ./internal/delivery/bot`

Expected: PASS for both locale paths and all existing operation/revert guarantees.

- [ ] **Step 7: Commit**

```bash
git add internal/delivery/bot/bot.go internal/delivery/bot/dialog.go internal/delivery/bot/handlers_devices.go internal/delivery/bot/handlers_tunnels.go internal/delivery/bot/bot_test.go internal/delivery/bot/revert_test.go internal/delivery/bot/locale_en.go internal/delivery/bot/locale_ru.go internal/delivery/bot/locale_test.go
git commit -m "feat(bot): localize device and tunnel operations"
```

### Task 4: Localize Deploy, Subscription, Hub, ACL, and Host Operations

**Files:**
- Modify: `internal/delivery/bot/handlers_client_acls.go`
- Modify: `internal/delivery/bot/handlers_deploy.go`
- Modify: `internal/delivery/bot/handlers_hub.go`
- Modify: `internal/delivery/bot/handlers_subs.go`
- Modify: `internal/delivery/bot/handlers_view.go`
- Modify: `internal/delivery/bot/ops.go`
- Modify: `internal/delivery/bot/ops_test.go`
- Modify: `internal/delivery/bot/bot_test.go`
- Modify: `internal/delivery/bot/locale_en.go`
- Modify: `internal/delivery/bot/locale_ru.go`

**Interfaces:**
- Consumes: `Bot.text`, localized renderers, stable callback payloads.
- Produces: complete localized mutation, validation, confirmation, success, refusal, and recovery messages for all remaining handlers.

- [ ] **Step 1: Add locale matrix tests for dangerous actions**

For both locales, assert the confirmation sequence and terminal message for immediate deploy, insured deploy, confirm, rollback, ACL removal, last-known-good restore, hub key rotation, configuration export, and agent restart. Assert the “yes” callback emitted in English equals the one emitted in Russian.

- [ ] **Step 2: Run and verify failure**

Run: `go test ./internal/delivery/bot -run 'DangerousActions|Deploy|Rollback|KeyRotation|ACL'`

Expected: FAIL on direct Russian text.

- [ ] **Step 3: Convert all remaining handler text**

Use catalog IDs for dialog prompts, parser errors presented to users, mutation results, warnings about inactive agents, rejected subscription candidates, log captions, host unit status, config exports, and confirmation labels. Keep raw Go errors in server logs when their wording is not a stable user contract; wrap them in a localized user-facing category.

- [ ] **Step 4: Verify behavior and source completeness**

Run:

```bash
go test -race ./internal/delivery/bot
grep -RIn '[А-Яа-яЁё]' internal/delivery/bot --include='*.go' | grep -v 'locale_ru.go' | grep -v '_test.go' && exit 1 || true
```

Expected: tests pass and the production source scan prints nothing.

- [ ] **Step 5: Commit**

```bash
git add internal/delivery/bot/handlers_client_acls.go internal/delivery/bot/handlers_deploy.go internal/delivery/bot/handlers_hub.go internal/delivery/bot/handlers_subs.go internal/delivery/bot/handlers_view.go internal/delivery/bot/ops.go internal/delivery/bot/ops_test.go internal/delivery/bot/bot_test.go internal/delivery/bot/locale_en.go internal/delivery/bot/locale_ru.go
git commit -m "feat(bot): localize privileged operations"
```

### Task 5: Localize Notifications and Out-of-Band Events

**Files:**
- Modify: `internal/delivery/bot/notify.go`
- Modify: `internal/delivery/bot/notify_test.go`
- Modify: `internal/delivery/bot/locale_en.go`
- Modify: `internal/delivery/bot/locale_ru.go`

**Interfaces:**
- Consumes: `Bot.text` and selected locale.
- Produces: localized health, drift, agent failure/recovery, rollback, revision, revocation, subscription, and out-of-band event notifications.

- [ ] **Step 1: Add dual-locale notification tests**

For each event category, feed identical state transitions to English and Russian bots. Assert category keys and action callbacks are identical while text differs. Include pending-deploy countdown and emergency buttons.

- [ ] **Step 2: Run and verify failure**

Run: `go test ./internal/delivery/bot -run 'Notify|Notification|OutOfBand'`

Expected: FAIL because notifications are Russian literals.

- [ ] **Step 3: Convert notification text**

Move event templates and reason prefixes into both catalogs. Preserve raw tunnel IDs, revision prefixes, unit names, and probe error details using escaped format arguments.

- [ ] **Step 4: Verify**

Run: `go test -race ./internal/delivery/bot`

Expected: PASS and no production Cyrillic remains outside the Russian catalog.

- [ ] **Step 5: Commit**

```bash
git add internal/delivery/bot/notify.go internal/delivery/bot/notify_test.go internal/delivery/bot/locale_en.go internal/delivery/bot/locale_ru.go
git commit -m "feat(bot): localize operational notifications"
```

### Task 6: Generate Documentation Examples from Tested Bot Screens

**Files:**
- Create: `internal/delivery/bot/doc_examples_test.go`
- Create: `site/src/data/bot-screens.en.json`
- Create: `site/src/data/bot-screens.ru.json`
- Modify: `Makefile`

**Interfaces:**
- Produces: `go test ./internal/delivery/bot -run TestDocumentationExamples -update-docs` to regenerate committed JSON.
- Produces: JSON records `{id, locale, title, text, rows:[[{label, callback}]]}` for the website's bot walkthrough components.

- [ ] **Step 1: Write a failing freshness test**

Add an `update-docs` flag. Render these IDs from deterministic view data: `main`, `status`, `devices`, `device-card`, `tunnels`, `tunnel-card`, `deploy-preview`, `deploy-countdown`, `subscriptions`, `subscription-card`, `candidates`, `client-acls`, `logs`, `host`, `hub`, and `settings`. Without the flag, compare generated bytes with the committed JSON and fail on drift.

- [ ] **Step 2: Run and verify failure**

Run: `go test ./internal/delivery/bot -run TestDocumentationExamples`

Expected: FAIL because the JSON files do not exist.

- [ ] **Step 3: Generate deterministic fixtures**

Sort records by ID, use two-space JSON indentation, end files with one newline, exclude tokens/IDs/keys/real endpoints, and preserve callback data so docs can describe exact state transitions.

Run: `go test ./internal/delivery/bot -run TestDocumentationExamples -update-docs`

- [ ] **Step 4: Add Make targets and verify freshness**

Add:

```make
## bot-docs: regenerate tested Telegram UI examples for the website
bot-docs:
	go test ./internal/delivery/bot -run TestDocumentationExamples -update-docs

## bot-docs-check: verify committed Telegram UI examples match the renderers
bot-docs-check:
	go test ./internal/delivery/bot -run TestDocumentationExamples
```

Run: `make bot-docs-check && go test -race ./internal/delivery/bot`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/delivery/bot/doc_examples_test.go site/src/data/bot-screens.en.json site/src/data/bot-screens.ru.json Makefile
git commit -m "docs(bot): generate verified interface examples"
```
