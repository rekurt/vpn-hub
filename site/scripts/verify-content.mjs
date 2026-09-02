import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const locales = ['en', 'ru', 'zh-cn'];
const docsRootOption = process.argv.indexOf('--docs-root');
const docsRoot = docsRootOption === -1
  ? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/content/docs')
  : path.resolve(process.argv[docsRootOption + 1]);
const documentPattern = /\.(?:md|mdx)$/i;

async function findDocuments(directory) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  const documents = await Promise.all(entries.map(async (entry) => {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return findDocuments(entryPath);
    return entry.isFile() && documentPattern.test(entry.name) ? [entryPath] : [];
  }));
  return documents.flat();
}

function frontmatter(source, filename) {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
  if (!match) throw new Error(`${filename}: frontmatter is required`);

  const values = new Map();
  for (const line of match[1].split(/\r?\n/)) {
    const field = line.match(/^([A-Za-z][\w-]*):\s*(.*?)\s*$/);
    if (field) values.set(field[1], field[2].replace(/^(?:['"])(.*)(?:['"])$/, '$1').trim());
  }
  for (const required of ['title', 'description']) {
    if (!values.get(required)) throw new Error(`${filename}: non-empty ${required} is required`);
  }
  return values;
}

function defaultSlug(relativePath) {
  const withoutExtension = relativePath.replace(documentPattern, '');
  return withoutExtension.endsWith('/index')
    ? withoutExtension.slice(0, -'/index'.length)
    : withoutExtension;
}

function finalRoute(locale, slug) {
  const normalizedSlug = slug.replace(/^\/+|\/+$/g, '');
  const localePrefix = locale === 'en' ? '' : `/${locale}`;
  return `${localePrefix}/${normalizedSlug || 'docs'}/`;
}

const localeDocuments = new Map();
const routes = new Map();
const failures = [];

for (const locale of locales) {
  const localeRoot = path.join(docsRoot, locale);
  const documents = await findDocuments(localeRoot);
  const paths = new Set();
  for (const filename of documents) {
    const relativePath = path.relative(localeRoot, filename).split(path.sep).join('/');
    paths.add(relativePath);
    try {
      frontmatter(await readFile(filename, 'utf8'), relativePath);
      const slug = defaultSlug(relativePath);
      const route = finalRoute(locale, slug);
      const duplicate = routes.get(route);
      if (duplicate) failures.push(`duplicate final route ${route}: ${duplicate} and ${locale}/${relativePath}`);
      else routes.set(route, `${locale}/${relativePath}`);
    } catch (error) {
      failures.push(error.message);
    }
  }
  localeDocuments.set(locale, paths);
}

const expected = localeDocuments.get('en');
for (const locale of locales.slice(1)) {
  const actual = localeDocuments.get(locale);
  for (const relativePath of expected) {
    if (!actual.has(relativePath)) failures.push(`${locale}: missing locale peer for ${relativePath}`);
  }
  for (const relativePath of actual) {
    if (!expected.has(relativePath)) failures.push(`${locale}: no English peer for ${relativePath}`);
  }
}

if (failures.length > 0) {
  console.error(`Content verification failed:\n${failures.map((failure) => `- ${failure}`).join('\n')}`);
  process.exitCode = 1;
} else {
  console.log(`Content verification passed for ${expected.size} locale-relative document path(s).`);
}
