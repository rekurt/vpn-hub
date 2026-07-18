# VPN Hub

Личный multi-VPN hub для Debian 12. Проект реализует Cobra CLI, Viper-конфигурацию и гексагональную архитектуру: доменная логика не зависит от Cobra, Viper, systemd, netlink или nftables.

## Что уже работает

- строгая YAML-конфигурация через Viper;
- валидация типов туннелей, ролей, egress ACL, CIDR и конфликтующих DNS-зон;
- сборка redacted desired state: приватные ключи клиентских профилей в него не попадают;
- генерация AmneziaWG-профилей;
- план namespace/veth/systemd/nftables операций;
- persisted desired state и agent reconciliation loop;
- безопасное скачивание Xray subscription по HTTPS с лимитом размера;
- health probes и device revocation registry.

## Быстрый старт

```sh
go test ./...
go run ./cmd/hubctl validate --config configs/example.yaml
go run ./cmd/hubctl deploy --config configs/example.yaml --state-dir ./state --dry-run=false
go run ./cmd/vpn-hub-agent reconcile --state-dir ./state --dry-run
```

Для выпуска локального клиентского профиля:

```sh
go run ./cmd/hubctl profile render \
  --config configs/example.yaml \
  --device macbook --egress xray-egress \
  --output ./macbook-xray.conf
```

## Важное ограничение MVP

Текущий runtime намеренно сохраняет desired state и печатает точный план системных операций, но не выполняет `ip`, `nft` и `systemctl` автоматически. Это исключает случайное отключение VPS во время первого развёртывания. Следующим этапом должен стать Linux-only `NetAdmin`/`Firewall` адаптер, выполняемый только после теста на отдельном Debian VPS.

`configs/example.yaml` содержит демонстрационные ключи и значения. Реальные upstream-конфиги и клиентские private keys храните только в SOPS + age, а не в Git в открытом виде.
