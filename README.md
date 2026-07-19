# VPN Hub

Личный multi-VPN hub для Ubuntu 24.04 LTS. Cobra CLI, Viper-конфигурация, гексагональная архитектура: доменная логика не зависит от Cobra, Viper, systemd, netlink и nftables.

Изначально проект писался под Debian 12, но DigitalOcean его больше не предлагает, а на Debian 13 модуль AmneziaWG не собирается — пакеты Amnezia PPA собраны под Ubuntu. Поэтому база — Ubuntu 24.04 LTS.

## Состояние проекта

Хаб работает как VPN: устройство подключается по AmneziaWG, трафик выходит в интернет через хаб, при падении туннеля блокируется, IPv6 не течёт. Всё это настраивает агент из ревизии.

Работает:

- YAML-конфигурация через Viper со строгим разбором: неизвестный ключ отвергается, а не игнорируется;
- валидация типов туннелей, ролей, egress ACL, уникальности адресов, пересечения CIDR, конфликтов DNS-зон, ключей и длины идентификаторов;
- детерминированный desired state с revision в виде content hash; приватные ключи в него не попадают;
- **AmneziaWG на входе**: агент поднимает интерфейс, ставит ключ, порт и параметры обфускации, синхронизирует пиров;
- **nftables с kill switch**: трафик проходит только при явном совпадении с egress, fallback на `direct` невозможен по построению;
- **выход `direct`** с NAT через аплинк хоста;
- **WireGuard-egress**: каждый апстрим в отдельном network namespace со своей меткой, таблицей маршрутизации и вторым kill switch;
- **observe и коррекция drift**: отпечаток плана хранится в самой nft-таблице, сошедшийся хост молчит, разошедшийся объясняет расхождение;
- **health по свежести handshake**, пробы выполняются **внутри** namespace туннеля;
- **SOPS**: upstream-конфиги расшифровываются прозрачно, определение по содержимому файла;
- **отзыв устройства**: `device revoke` + `deploy` убирает пира, связь рвётся;
- **коррекция drift**: удалённый вручную ruleset восстанавливается на следующем такте;
- `hubctl keygen` и `device add` — ключи и профили без ручного редактирования YAML;
- генерация клиентских AmneziaWG-профилей;
- атомарное сохранение состояния с fsync и блокировкой директории.

## Чего пока нет

- **Только WireGuard на выход.** OpenVPN, Xray и AmneziaWG-egress валидируются, но драйверов нет: `BuildEgressSpecs` отказывается их собирать, а не делает вид.
- **Split-DNS.** `dns_zones` валидируются и никем не используются; DNS-сервер на хабе не запускается.
- **Xray, OpenVPN, SOCKS5.** Валидируются, драйверов нет.

Порядок дальнейших работ — в плане развития.

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

Заведение устройства и выпуск профиля:

```sh
hubctl keygen --output /etc/vpn-hub/server.key   # один раз на хаб
hubctl device add laptop --egress direct --address 10.80.0.2/32
# вставить напечатанный блок в devices, приватный ключ оставить устройству
hubctl profile render --device laptop --egress direct --output ./laptop.conf
```

`configs/example.yaml` намеренно не содержит приватных ключей: хабу нужна только публичная половина, а пример приватного ключа рано или поздно копируют в реальную установку.

## Стенд

Хост описан в `deploy/terraform/` (OpenTofu + cloud-init) и поднимается одноразово на DigitalOcean — ≈$6/мес, удаляется одной командой.

```sh
brew install opentofu doctl
doctl auth init          # интерактивно, один раз; токен читается из его конфига
make stand-init          # tofu init, один раз
make stand-up            # создаёт хост и ждёт завершения cloud-init
make deploy-lab          # собирает под linux/amd64 и ставит юнит
make logs
make stand-down          # удаляет хост
```

Terraform создаёт дроплет Ubuntu 24.04 без IPv6, SSH-ключ и cloud firewall (открыты только 22/tcp и 51820/udp). cloud-init готовит ОС: `ip_forward`, выключение IPv6, `/run/netns`, SSH без паролей, AmneziaWG через DKMS из Amnezia PPA. Отдельно отключаются `ufw` и `nftables.service` — ruleset принадлежит агенту, и они бы с ним конфликтовали.

**Хаб предполагает, что владеет форвардингом на своей машине.** Netfilter прогоняет все цепочки, зарегистрированные на хуке, поэтому чужой `DROP` в цепочке forward убивает пакет независимо от того, что разрешает таблица `inet vpn_hub`. Практически это значит: не ставьте на хаб Docker (он выставляет `iptables -P FORWARD DROP`) и не включайте `ufw`. Держите хаб выделенным.

Параметры переопределяются через `deploy/terraform/terraform.tfvars` (см. `terraform.tfvars.example`) — регион, размер, дополнительные SSH-ключи, сужение доступа к SSH.

cloud-init выполняется только при первой загрузке, поэтому правка `cloud-init.yaml` пересоздаёт хост — `make stand-plan` покажет это до применения.

State OpenTofu лежит локально и не коммитится: он содержит токен. Потеря `terraform.tfstate` означает, что дроплет придётся удалять руками через `doctl`.

## Разработка

```sh
make lint              # gofmt + go vet
make test              # go test -race ./...
make test-integration  # реальные интерфейсы и трафик; Linux, нужен root
make build-linux
```

`make test-integration` поднимает клиента в отдельном network namespace, применяет настоящий ruleset и проверяет, что трафик идёт, а kill switch блокирует. На стенде перед запуском остановите агента: он реконсилит по таймеру и вернёт свой ruleset поверх тестового.

## CI/CD

- **ci** — на каждый push и PR: gofmt, vet (включая `-tags=integration`), `test -race`, golangci-lint, кросс-сборка, `tofu fmt`/`validate` и интеграционные тесты на живом ядре раннера.
- **release** — на зелёный master собирает бинарники и публикует артефакт; на тег `v*` создаёт GitHub Release с контрольными суммами.
- **deploy** — **только вручную** (`workflow_dispatch`), в окружении `hub`.

Деплой намеренно не автоматический. Хаб — шлюз собственного трафика, поэтому push в master не должен его перенастраивать: автодеплой означал бы, что компрометация токена равна компрометации сетевого пути. Требуемые секреты окружения `hub`: `HUB_SSH_KEY` (отдельный ключ только для деплоя, чтобы его можно было отозвать независимо) и `HUB_HOST`.

Интеграционные тесты в CI используют обычный WireGuard: модуль AmneziaWG собирается через DKMS, чего эфемерный раннер сделать не может. Кроме параметров обфускации протокол тот же, а проверяется механика хаба — ruleset, NAT, синхронизация пиров, kill switch — которая от обфускации не зависит.

`configs/example.yaml` содержит демонстрационные значения. Реальные upstream-конфиги и клиентские private keys храните только в SOPS + age, а не в Git в открытом виде.
