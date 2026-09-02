# VPN Hub

**面向自托管 Linux Hub 的显式多 VPN 路由。** VPN Hub 通过 AmneziaWG 接入设备，并把每个数据包送往明确选择的路径：直连、WireGuard、AmneziaWG、Xray/VLESS 或 OpenVPN；不会静默切换出口。

[文档](https://rekurt.github.io/vpn-hub/zh-cn/docs/) · [Cookbook](https://rekurt.github.io/vpn-hub/zh-cn/docs/cookbook/) · [Telegram Bot](https://rekurt.github.io/vpn-hub/zh-cn/docs/telegram-bot/) · [English](README.md) · [Русский](README.ru.md)

## 功能

- 每台设备使用明确的互联网出口；私有目标由所属隧道路由。
- 每个提供商隧道有独立 network namespace、策略路由和 kill switch。
- 使用声明式 YAML、内容哈希 revision 与 drift 校正。
- 支持 split DNS、设备间 ACL、每出口 SOCKS5、健康检查和 VLESS 订阅。
- 可选 Telegram Bot 管理设备、隧道、deploy、状态与订阅，所有变更均需确认。

## 快速评估

支持 Ubuntu 24.04 LTS。请先阅读[环境要求](https://rekurt.github.io/vpn-hub/zh-cn/docs/start/requirements/)，然后在测试主机上执行：

```sh
git clone https://github.com/rekurt/vpn-hub.git
cd vpn-hub
make test
cp configs/example.yaml configs/hub.yaml
go run ./cmd/hubctl validate --config configs/hub.yaml
go run ./cmd/vpn-hub-agent reconcile --config configs/hub.yaml --state-dir ./state --dry-run
```

示例仅用于本地验证。生产环境请完成[安装](https://rekurt.github.io/vpn-hub/zh-cn/docs/start/install/)、[首个 Hub](https://rekurt.github.io/vpn-hub/zh-cn/docs/start/first-hub/)和[验证](https://rekurt.github.io/vpn-hub/zh-cn/docs/start/verify/)，并保留独立的主机恢复访问方式。

## Cookbook 与安全

- [安全 deploy 与回滚](https://rekurt.github.io/vpn-hub/zh-cn/docs/cookbook/rolling-deploy/)
- [网络隔离、私有网段与 DNS](https://rekurt.github.io/vpn-hub/zh-cn/docs/cookbook/segmentation/)
- [订阅 Canary 验证](https://rekurt.github.io/vpn-hub/zh-cn/docs/cookbook/subscription-canary/)
- [事件恢复手册](https://rekurt.github.io/vpn-hub/zh-cn/docs/cookbook/rollback-runbook/)

VPN Hub 采用 fail-closed 策略：选定出口失效时流量不会自动直连。DoH 无法可靠拦截，TCP/443 fallback 也刻意不能访问私有网络。生产使用前请阅读[威胁模型](https://rekurt.github.io/vpn-hub/zh-cn/docs/security/threat-model/)和[限制](https://rekurt.github.io/vpn-hub/zh-cn/docs/security/limitations/)。

```sh
make test
make site-check
make publication-check
```

不要提交 Hub 配置、设备 profile、运行状态、provider link 或 Telegram token。`v*` 标签构建 release 产物；Hub 部署始终是带审批和主机密钥固定的手动工作流。
