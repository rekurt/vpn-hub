import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';

const locales = ['en', 'ru', 'zh-cn'];
const docsRootOption = process.argv.indexOf('--docs-root');
const docsRoot = docsRootOption === -1
  ? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/content/docs')
  : path.resolve(process.argv[docsRootOption + 1]);
const documentPattern = /\.(?:md|mdx)$/i;

async function findDocuments(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
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

  const parsed = parseDocument(match[1], { prettyErrors: true, strict: true });
  if (parsed.errors.length > 0) throw new Error(`${filename}: malformed YAML frontmatter`);
  const values = parsed.toJS();
  for (const required of ['title', 'description']) {
    if (typeof values?.[required] !== 'string' || values[required].trim().length === 0) {
      throw new Error(`${filename}: non-empty ${required} is required`);
    }
  }
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

async function isDirectory(directory) {
  try {
    return (await stat(directory)).isDirectory();
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

if (!(await isDirectory(docsRoot))) {
  failures.push(`docs root is required: ${docsRoot}`);
} else {
  for (const locale of locales) {
    const localeRoot = path.join(docsRoot, locale);
    if (!(await isDirectory(localeRoot))) {
      failures.push(`${locale}: locale directory is required`);
      localeDocuments.set(locale, new Set());
      continue;
    }

    const documents = await findDocuments(localeRoot);
    const paths = new Set();
    const slugs = new Set();
    if (documents.length === 0) failures.push(`${locale}: at least one Markdown or MDX document is required`);
    for (const filename of documents) {
      const relativePath = path.relative(localeRoot, filename).split(path.sep).join('/');
      paths.add(relativePath);
      const slug = defaultSlug(relativePath);
      slugs.add(slug);
      try {
        frontmatter(await readFile(filename, 'utf8'), relativePath);
        const route = finalRoute(locale, slug);
        const duplicate = routes.get(route);
        if (duplicate) failures.push(`duplicate final route ${route}: ${duplicate} and ${locale}/${relativePath}`);
        else routes.set(route, `${locale}/${relativePath}`);
      } catch (error) {
        failures.push(error.message);
      }
    }
    if (!slugs.has('docs')) failures.push(`${locale}: normalized docs/index is required`);
    localeDocuments.set(locale, paths);
  }
}

const expected = localeDocuments.get('en');
if (expected) {
  for (const locale of locales.slice(1)) {
    const actual = localeDocuments.get(locale) ?? new Set();
    for (const relativePath of expected) {
      if (!actual.has(relativePath)) failures.push(`${locale}: missing locale peer for ${relativePath}`);
    }
    for (const relativePath of actual) {
      if (!expected.has(relativePath)) failures.push(`${locale}: no English peer for ${relativePath}`);
    }
  }
}

if (failures.length > 0) {
  console.error(`Content verification failed:\n${failures.map((failure) => `- ${failure}`).join('\n')}`);
  process.exitCode = 1;
} else {
  console.log(`Content verification passed for ${expected?.size ?? 0} locale-relative document path(s).`);
}
