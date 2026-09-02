import { doesNotMatch, equal, match, ok } from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

const siteRoot = resolve(dirname(process['argv'][1]), '..');
const dist = join(siteRoot, 'dist');
const globalCss = await readFile(join(siteRoot, 'src/styles/global.css'), 'utf8');

match(globalCss, /:root,\s*:root\[data-theme=['"]light['"]\]/);
doesNotMatch(globalCss, /prefers-color-scheme/);

function themeToken(theme, token) {
  const rule = globalCss['match'](new RegExp(`:root\\[data-theme=['"]${theme}['"]\\]\\s*\\{([^}]*)\\}`));
  match(rule?.[1] ?? '', new RegExp(`--${token}:\\s*#[a-f\\d]{6};`, 'i'));
  return rule[1]['match'](new RegExp(`--${token}:\\s*(#[a-f\\d]{6});`, 'i'))[1];
}

function luminance(hex) {
  const channels = hex['match'](/[a-f\d]{2}/gi)['map']((part) => Number['parseInt'](part, 16) / 255)
    ['map']((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(foreground, background) {
  const first = luminance(foreground);
  const second = luminance(background);
  return (Math['max'](first, second) + 0.05) / (Math['min'](first, second) + 0.05);
}

const lightFocus = themeToken('light', 'vpn-focus-ring');
const lightSurface = themeToken('light', 'vpn-focus-surface');
const darkFocus = themeToken('dark', 'vpn-focus-ring');
const darkSurface = themeToken('dark', 'vpn-focus-surface');

equal(lightFocus, '#005fcc');
equal(darkFocus, '#71f6ff');
ok(contrast(lightFocus, lightSurface) >= 3, 'light focus ring meets 3:1 against the active surface');
ok(contrast(darkFocus, darkSurface) >= 3, 'dark focus ring meets 3:1 against the active surface');

async function html(route) {
  return readFile(join(dist, route), 'utf8');
}

function h1Count(source) {
  return (source['match'](/<h1(?:\s[^>]*)?>/gi) ?? [])['length'];
}

for (const route of ['docs/index.html', 'ru/docs/index.html', 'zh-cn/docs/index.html']) {
  equal(h1Count(await html(route)), 1, `${route} must have one h1`);
}

for (const { route, docs, languages } of [
  { route: 'index.html', docs: '/vpn-hub/docs/', languages: ['/vpn-hub/ru/', '/vpn-hub/zh-cn/'] },
  { route: 'ru/index.html', docs: '/vpn-hub/ru/docs/', languages: ['/vpn-hub/', '/vpn-hub/zh-cn/'] },
  { route: 'zh-cn/index.html', docs: '/vpn-hub/zh-cn/docs/', languages: ['/vpn-hub/', '/vpn-hub/ru/'] },
]) {
  const source = await html(route);
  equal(h1Count(source), 1, `${route} must have one h1`);
  match(source, new RegExp(`href=["']${docs}["']`), `${route} links to its docs`);
  for (const language of languages) {
    match(source, new RegExp(`href=["']${language}["']`), `${route} links to ${language}`);
  }
}

console['log']('Built site route and heading checks passed.');
