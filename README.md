# VPN Hub

Личный multi-VPN hub для Debian 12. Cobra CLI, Viper-конфигурация, гексагональная архитектура: доменная логика не зависит от Cobra, Viper, systemd, netlink и nftables.

## Состояние проекта

Data plane ещё не реализован. Сейчас работает control plane: конфигурация валидируется, из неё детерминированно собирается desired state, выпускаются клиентские профили. Системные операции (`ip`, `nft`, `systemctl`) не выполняются — см. «Чего пока нет».

Работает:

- YAML-конфигурация через Viper со строгим разбором: неизвестный ключ отвергается, а не игнорируется;
- валидация типов туннелей, ролей, egress ACL, уникальности адресов, пересечения CIDR и конфликтов DNS-зон;
- детерминированный desired state с revision в виде content hash; приватные ключи клиентских профилей в него не попадают;
- генерация AmneziaWG-профилей;
- атомарное сохранение состояния с fsync и блокировкой директории;
- скачивание Xray subscription по HTTPS с лимитом размера;
- TCP/HTTPS/DNS-пробы.

## Чего пока нет

- **Системные операции не выполняются.** `deploy` и `reconcile` печатают план и сохраняют состояние, но не создают namespace, veth, маршруты и правила nftables. Порты `NetAdmin`, `Firewall`, `DNSManager`, `TunnelDriver`, `NamespaceManager` объявлены и не реализованы.
- **Ни один тип туннеля не поднимается.** `wireguard`, `openvpn`, `xray`, `amneziawg` валидируются, но драйверов нет.
- **`serve` не сверяет фактическое состояние с желаемым** — шага observe пока нет, поэтому drift не обнаруживается.
- **Health-проверка неполна:** туннель без блока `health:` считается здоровым, а пробы выполняются в хостовом namespace.
- **Отзыв устройства не действует** на сохранённый desired state.
- **SOPS не подключён:** пути из `source.value` не расшифровываются.

Порядок работ описан в плане развития; ближайшая веха — AmneziaWG на входе, `direct` на выходе и kill switch.

## Быстрый старт

```sh
make test
cp configs/example.yaml configs/hub.yaml   # configs/hub.yaml не коммитится
go run ./cmd/hubctl validate
```

Полный цикл на примере конфигурации:

```sh
go run ./cmd/hubctl validate --config configs/example.yaml
go run ./cmd/hubctl deploy --config configs/example.yaml --state-dir ./state --dry-run=false
go run ./cmd/vpn-hub-agent reconcile --state-dir ./state --dry-run
```

Выпуск клиентского профиля:

```sh
go run ./cmd/hubctl profile render \
  --config configs/example.yaml \
  --device macbook --egress xray-egress \
  --output ./macbook-xray.conf
```

## Стенд

Разработка ведётся против одноразового дроплета DigitalOcean (≈$6/мес, удаляется в одну команду).

```sh
doctl auth init          # интерактивно, один раз
make stand-up            # создаёт Debian 12 s-1vcpu-1gb
make deploy-lab          # собирает под linux/amd64 и ставит юнит
make logs
make stand-down          # удаляет дроплет
```

Регион и размер переопределяются: `make stand-up REGION=ams3 SIZE=s-1vcpu-2gb`.

## Разработка

```sh
make lint    # gofmt + go vet
make test    # go test -race ./...
make build-linux
```

`configs/example.yaml` содержит демонстрационные значения. Реальные upstream-конфиги и клиентские private keys храните только в SOPS + age, а не в Git в открытом виде.
