import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

const sidebar = [
  { label: 'Start', items: [{ label: 'Overview', slug: 'docs/index' }] },
  { label: 'Concepts', items: [] },
  { label: 'Configuration', items: [] },
  { label: 'CLI', items: [] },
  { label: 'Cookbook', items: [] },
  { label: 'Use cases', items: [] },
  { label: 'Telegram bot', items: [] },
  { label: 'Operations', items: [] },
  { label: 'Security', items: [] },
  { label: 'Reference', items: [] },
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
