import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(siteRoot, 'dist');
const globalCss = await readFile(path.join(siteRoot, 'src/styles/global.css'), 'utf8');

assert.match(globalCss, /@media \(prefers-color-scheme: dark\)[\s\S]*--vpn-focus-ring:\s*#71f6ff;/);

async function html(route) {
  return readFile(path.join(dist, route), 'utf8');
}

function h1Count(source) {
  return (source.match(/<h1(?:\s[^>]*)?>/gi) ?? []).length;
}

for (const route of ['docs/index.html', 'ru/docs/index.html', 'zh-cn/docs/index.html']) {
  assert.equal(h1Count(await html(route)), 1, `${route} must have one h1`);
}

for (const { route, docs, languages } of [
  { route: 'index.html', docs: '/vpn-hub/docs/', languages: ['/vpn-hub/ru/', '/vpn-hub/zh-cn/'] },
  { route: 'ru/index.html', docs: '/vpn-hub/ru/docs/', languages: ['/vpn-hub/', '/vpn-hub/zh-cn/'] },
  { route: 'zh-cn/index.html', docs: '/vpn-hub/zh-cn/docs/', languages: ['/vpn-hub/', '/vpn-hub/ru/'] },
]) {
  const source = await html(route);
  assert.equal(h1Count(source), 1, `${route} must have one h1`);
  assert.match(source, new RegExp(`href=["']${docs}["']`), `${route} links to its docs`);
  for (const language of languages) {
    assert.match(source, new RegExp(`href=["']${language}["']`), `${route} links to ${language}`);
  }
}

console.log('Built site route and heading checks passed.');
