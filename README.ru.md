# VPN Hub

**Явная маршрутизация через несколько VPN для собственного Linux-хаба.** VPN Hub подключает устройства по AmneziaWG и отправляет каждый пакет по выбранному пути: напрямую, через WireGuard, AmneziaWG, Xray/VLESS или OpenVPN. Молчаливого fallback нет.

[Документация](https://rekurt.github.io/vpn-hub/ru/docs/) · [Cookbook](https://rekurt.github.io/vpn-hub/ru/docs/cookbook/) · [Telegram-бот](https://rekurt.github.io/vpn-hub/ru/docs/telegram-bot/) · [English](README.md) · [简体中文](README.zh-CN.md)

## Возможности

- Явно выбранный egress для устройства и отдельный tunnel для приватных назначений.
- Изолированные network namespace, policy routing и kill switch для каждого провайдера.
- YAML-конфигурация, revision с content hash и коррекция drift.
- Split DNS, ACL между устройствами, SOCKS5 на egress, health-пробы и VLESS-подписки.
- Telegram-бот для устройств, туннелей, статуса, deploy и подписок с двухшаговым подтверждением.

## Первый запуск

Поддерживаемый хост — Ubuntu 24.04 LTS. Начните с [требований](https://rekurt.github.io/vpn-hub/ru/docs/start/requirements/), затем выполните [установку](https://rekurt.github.io/vpn-hub/ru/docs/start/install/) и создайте [первый хаб](https://rekurt.github.io/vpn-hub/ru/docs/start/first-hub/).

```sh
git clone https://github.com/rekurt/vpn-hub.git
cd vpn-hub
make test
cp configs/example.yaml configs/hub.yaml
go run ./cmd/hubctl validate --config configs/hub.yaml
go run ./cmd/vpn-hub-agent reconcile --config configs/hub.yaml --state-dir ./state --dry-run
```

Пример предназначен для локальной проверки. До изменения рабочего трафика пройдите [Verify](https://rekurt.github.io/vpn-hub/ru/docs/start/verify/) и оставьте независимый доступ к хосту.

## Cookbook и безопасность

- [Безопасный deploy и rollback](https://rekurt.github.io/vpn-hub/ru/docs/cookbook/rolling-deploy/)
- [Сегментация, приватные сети и DNS](https://rekurt.github.io/vpn-hub/ru/docs/cookbook/segmentation/)
- [Canary для подписки](https://rekurt.github.io/vpn-hub/ru/docs/cookbook/subscription-canary/)
- [Восстановление после инцидента](https://rekurt.github.io/vpn-hub/ru/docs/cookbook/rollback-runbook/)

Проект работает fail-closed: падение выбранного egress не превращает трафик в direct. DoH нельзя надёжно перехватить, а TCP/443 fallback намеренно не открывает приватные сети. Перед production изучите [модель угроз](https://rekurt.github.io/vpn-hub/ru/docs/security/threat-model/) и [ограничения](https://rekurt.github.io/vpn-hub/ru/docs/security/limitations/).

```sh
make test
make site-check
make publication-check
```

Не коммитьте конфигурацию хаба, профили устройств, state, provider links и Telegram-токены. Теги `v*` собирают release-артефакты; deploy на хост всегда ручной, с approval и pinned host key.
