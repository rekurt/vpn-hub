import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

const sidebar = [
  {
    label: 'Start',
    items: [
      { label: 'Overview', slug: 'docs/index' },
      { label: 'Requirements', slug: 'docs/start/requirements' },
      { label: 'Install', slug: 'docs/start/install' },
      { label: 'Terraform lab', slug: 'docs/start/terraform' },
      { label: 'First hub', slug: 'docs/start/first-hub' },
      { label: 'First device', slug: 'docs/start/first-device' },
      { label: 'Verify', slug: 'docs/start/verify' },
    ],
  },
  {
    label: 'Concepts',
    items: [
      { label: 'Architecture', slug: 'docs/concepts/architecture' },
      { label: 'Desired state', slug: 'docs/concepts/desired-state' },
      { label: 'Routing', slug: 'docs/concepts/routing' },
      { label: 'DNS and private networks', slug: 'docs/concepts/dns' },
      { label: 'Kill switch', slug: 'docs/concepts/kill-switch' },
      { label: 'Client isolation', slug: 'docs/concepts/client-isolation' },
      { label: 'Subscriptions', slug: 'docs/concepts/subscriptions' },
      { label: 'Health', slug: 'docs/concepts/health' },
      { label: 'Secrets and storage', slug: 'docs/concepts/secrets' },
      { label: 'Private networks', slug: 'docs/concepts/private-networks' },
    ],
  },
  {
    label: 'Configuration',
    items: [
      { label: 'Overview', slug: 'docs/configuration/overview' },
      { label: 'Hub', slug: 'docs/configuration/hub' },
      { label: 'Devices', slug: 'docs/configuration/devices' },
      { label: 'Tunnels', slug: 'docs/configuration/tunnels' },
      { label: 'WireGuard', slug: 'docs/configuration/wireguard' },
      { label: 'AmneziaWG', slug: 'docs/configuration/amneziawg' },
      { label: 'Xray and VLESS', slug: 'docs/configuration/xray-vless' },
      { label: 'OpenVPN', slug: 'docs/configuration/openvpn' },
      { label: 'SOCKS5', slug: 'docs/configuration/socks' },
      { label: 'Private networks', slug: 'docs/configuration/private-networks' },
      { label: 'Health', slug: 'docs/configuration/health' },
      { label: 'Subscriptions', slug: 'docs/configuration/subscriptions' },
      { label: 'Client ACLs', slug: 'docs/configuration/client-acls' },
    ],
  },
  {
    label: 'CLI',
    items: [
      { label: 'Overview', slug: 'docs/cli/index' },
      { label: 'Commands', slug: 'docs/cli/command-reference' },
      { label: 'Best practices', slug: 'docs/cli/best-practices' },
    ],
  },
  {
    label: 'Cookbook',
    items: [
      { label: 'Overview', slug: 'docs/cookbook/index' },
      { label: 'Rolling deploy', slug: 'docs/cookbook/rolling-deploy' },
      { label: 'Rollback runbook', slug: 'docs/cookbook/rollback-runbook' },
      { label: 'Segmentation', slug: 'docs/cookbook/segmentation' },
      { label: 'Subscription canary', slug: 'docs/cookbook/subscription-canary' },
    ],
  },
  {
    label: 'Use cases',
    items: [
      { label: 'Overview', slug: 'docs/use-cases/index' },
      { label: 'Zero-trust routing', slug: 'docs/use-cases/zero-trust-routing' },
      { label: 'SOCKS5 app steering', slug: 'docs/use-cases/socks-for-apps' },
      { label: 'Subscription canary rollout', slug: 'docs/use-cases/subscription-canary-rollout' },
    ],
  },
  {
    label: 'Telegram bot',
    items: [
      { label: 'Overview', slug: 'docs/telegram-bot/index' },
      { label: 'Device management', slug: 'docs/telegram-bot/device-management' },
      { label: 'Deploy and status', slug: 'docs/telegram-bot/deploy-review' },
      { label: 'Subscriptions', slug: 'docs/telegram-bot/subscriptions' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { label: 'Overview', slug: 'docs/operations/index' },
      { label: 'Daily checks', slug: 'docs/operations/daily-routines' },
      { label: 'Incident response', slug: 'docs/operations/incident-response' },
    ],
  },
  {
    label: 'Security',
    items: [
      { label: 'Overview', slug: 'docs/security/index' },
      { label: 'Limitations', slug: 'docs/security/limitations' },
      { label: 'Threat model', slug: 'docs/security/threat-model' },
    ],
  },
  {
    label: 'Reference',
    items: [
      { label: 'Quick reference', slug: 'docs/reference/index' },
      { label: 'Deployment', slug: 'docs/reference/deployment' },
      { label: 'Troubleshooting', slug: 'docs/reference/troubleshooting' },
    ],
  },
];

export default defineConfig({
  site: 'https://rekurt.github.io',
  base: '/vpn-hub',
  trailingSlash: 'always',
  integrations: [
    sitemap(),
    starlight({
      title: 'VPN Hub',
      description: 'Documentation for VPN Hub.',
      locales: {
        root: { label: 'English', lang: 'en' },
        ru: { label: 'Русский', lang: 'ru' },
        'zh-cn': { label: '简体中文', lang: 'zh-CN' },
      },
      sidebar,
      pagefind: true,
      customCss: ['./src/styles/global.css'],
    }),
  ],
});
