# Changelog

All notable user-facing changes are recorded here. The project follows conventional commits; release notes are generated from tagged releases.

## Unreleased

## [0.1.2] - 2026-09-03

### Changed

- Landing page was redesigned with a premium product interface and interactive routing controls.
- English, Russian, and Simplified Chinese repository entry points were restored and aligned with the public site.

### Security

- Publication checks distinguish local root-relative assets and package-lock files from external endpoints while preserving detection for explicit endpoint assignments.

## [0.1.1] - 2026-09-02

### Added

- Public documentation site with English as the default language, plus Russian and Simplified Chinese navigation.
- Cookbook runbooks for safe rollout, rollback, segmentation, subscription canaries, device lifecycle, and tunnel lifecycle.
- Telegram-bot operation guides and example screens for guarded device, deployment, subscription, routing, ACL, hub, host, notification, and incident workflows.
- GitHub Pages publication workflow for the static documentation site.

### Changed

- Repository README is available in English, Russian, and Simplified Chinese.
- Landing pages include canonical URLs, alternate-language links, social metadata, and structured software metadata.

### Security

- Publication checks scan tracked content for secrets, runtime state, and unreviewed network identifiers.
