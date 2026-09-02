import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const localeRoutes = [
  { locale: 'en', path: 'index.html', docsPath: '/vpn-hub/docs/' },
  { locale: 'ru', path: 'ru/index.html', docsPath: '/vpn-hub/ru/docs/' },
  { locale: 'zh-cn', path: 'zh-cn/index.html', docsPath: '/vpn-hub/zh-cn/docs/' },
];

const requiredSections = [
  'architecture',
  'protocols',
  'safety',
  'use-cases',
  'bot-management',
  'cookbook',
  'next-steps',
  'landing-footer',
];

const requiredLangSwitches = ['/vpn-hub/', '/vpn-hub/ru/', '/vpn-hub/zh-cn/'];
const forbidden = [/\bnext-generation\b/i, /\brevolutionary\b/i, /\bseamless\b/i, /\bmilitary-grade\b/i, /\bAI-powered\b/i];

let failures = 0;
const failuresList = [];

function assert(condition, message) {
  if (!condition) {
    failures += 1;
    failuresList.push(message);
  }
}

function countH1(source) {
  return (source.match(/<h1[^>]*>/gi) ?? []).length;
}

async function checkRoute({ locale, path: route, docsPath }) {
  const html = await readFile(join('dist', route), 'utf8');
  assert(countH1(html) === 1, `${locale}: exactly one h1`);
  assert(/<nav[^>]*>[\s\S]*?<\/nav>/i.test(html), `${locale}: navigation landmark`);
  assert(/class=\"skip-link\"/i.test(html), `${locale}: skip link`);
  assert(new RegExp(`<a[^>]+href=\"${docsPath}\"`).test(html), `${locale}: docs CTA`);

  const langMatches = requiredLangSwitches.filter((href) => new RegExp(`href=\"${href.replace('/', '\\/')}(?:index\\.html)?\"`).test(html));
  assert(langMatches.length >= 2, `${locale}: at least two locale links`);

  assert(/primary-cta/.test(html), `${locale}: primary CTA`);
  assert(/secondary-cta/.test(html), `${locale}: secondary CTA`);
  assert((html.match(/class=\"landing-section\"/gi) ?? []).length >= 5, `${locale}: multiple sections`);

  for (const section of requiredSections) {
    assert(new RegExp(`id=\"${section}\"`).test(html), `${locale}: section ${section} exists`);
  }

  for (const phrase of forbidden) {
    assert(!phrase.test(html), `${locale}: forbidden phrase matched ${phrase}`);
  }

  assert(/id=\"bot-preview__screen\"/.test(html) && /id=\"bot-preview__panel\"/.test(html), `${locale}: bot preview has both panes`);
}

for (const route of localeRoutes) {
  await checkRoute(route);
}

if (failures > 0) {
  console.error('Landing verification failed:');
  for (const failure of failuresList) {
    console.error(`- ${failure}`);
  }
  process.exitCode = 1;
} else {
  console.log('Landing verification passed for en, ru, zh-cn landing pages.');
}

