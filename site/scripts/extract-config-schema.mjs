import { readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';

const siteRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = resolve(siteRoot, '..');
const schemaPath = join(siteRoot, 'src/data/config-schema.json');
const documentationRoot = join(siteRoot, 'src/content/docs/en/docs/configuration');
const sourceFiles = [
  'internal/domain/model.go',
  'internal/domain/fallback.go',
  'internal/domain/healthcheck.go',
];

function sourceLocation(filename, line) {
  return `${filename}:${line}`;
}

function lineNumber(source, offset) {
  return source.slice(0, offset).split('\n').length;
}

function parseStructs(sources) {
  const structs = new Map();
  for (const [filename, source] of sources) {
    const pattern = /^type\s+(\w+)\s+struct\s*\{([\s\S]*?)^\}/gm;
    for (const match of source.matchAll(pattern)) {
      const fields = [];
      const bodyOffset = match.index + match[0].indexOf(match[2]);
      let offset = 0;
      for (const rawLine of match[2].split('\n')) {
        const field = rawLine.match(/^\s*(\w+)\s+(.+?)\s+`[^`]*mapstructure:"([^",]+)(?:,[^"]*)?"[^`]*`/);
        if (field) {
          fields.push({
            name: field[1],
            goType: field[2].trim(),
            key: field[3],
            source: sourceLocation(filename, lineNumber(source, bodyOffset + offset)),
          });
        }
        offset += rawLine.length + 1;
      }
      structs.set(match[1], fields);
    }
  }
  return structs;
}

function parseEnums(sources) {
  const enums = new Map();
  for (const [, source] of sources) {
    for (const match of source.matchAll(/^\s*\w+\s+(\w+)\s*=\s*"([^"]+)"\s*$/gm)) {
      const values = enums.get(match[1]) ?? [];
      if (!values.includes(match[2])) values.push(match[2]);
      enums.set(match[1], values);
    }
  }
  return enums;
}

function typeShape(goType) {
  const withoutPointer = goType.replace(/^\*/, '');
  if (withoutPointer.startsWith('[]')) return { kind: 'array', element: withoutPointer.slice(2) };
  if (withoutPointer.startsWith('map[')) return { kind: 'map', element: withoutPointer };
  return { kind: 'scalar', element: withoutPointer };
}

function schemaFields(structs, enums) {
  const fields = [];
  const visiting = new Set();

  function visit(structName, prefix) {
    if (visiting.has(structName)) throw new Error(`recursive configuration struct ${structName}`);
    const structFields = structs.get(structName);
    if (!structFields) throw new Error(`configuration struct ${structName} was not found`);
    visiting.add(structName);
    for (const field of structFields) {
      const shape = typeShape(field.goType);
      const path = `${prefix}${field.key}${shape.kind === 'array' ? '[]' : ''}`;
      const acceptedValues = enums.get(shape.element);
      fields.push({
        path,
        goType: field.goType,
        ...(acceptedValues ? { acceptedValues: [...acceptedValues].sort((left, right) => left < right ? -1 : left > right ? 1 : 0) } : {}),
        source: field.source,
      });
      if (structs.has(shape.element)) visit(shape.element, `${path}.`);
    }
    visiting.delete(structName);
  }

  visit('Config', '');
  return fields.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
}

async function currentSchema() {
  const sources = new Map();
  for (const filename of sourceFiles) {
    sources.set(filename, await readFile(join(repositoryRoot, filename), 'utf8'));
  }
  return {
    version: 1,
    sourceFiles,
    fields: schemaFields(parseStructs(sources), parseEnums(sources)),
  };
}

async function documents(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await documents(path));
    else if (entry.isFile() && /\.mdx?$/.test(entry.name)) result.push(path);
  }
  return result;
}

function documentMetadata(source, filename) {
  const frontmatter = source.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
  if (!frontmatter) throw new Error(`${filename}: frontmatter is required`);
  const parsed = parseDocument(frontmatter[1], { prettyErrors: true, strict: true });
  if (parsed.errors.length > 0) throw new Error(`${filename}: malformed YAML frontmatter`);
  const values = parsed.toJS();
  if (values.coverage === undefined) return { coverage: [], components: [] };
  if (!Array.isArray(values.coverage) || values.coverage.some((path) => typeof path !== 'string')) {
    throw new Error(`${filename}: coverage must be an array of schema paths`);
  }

  const components = [];
  const componentPattern = /<ConfigField\s+([\s\S]*?)\/>/g;
  for (const match of source.matchAll(componentPattern)) {
    const attributes = Object.fromEntries(
      [...match[1].matchAll(/(\w+)="([^"]*)"/g)].map((attribute) => [attribute[1], attribute[2]]),
    );
    const required = ['path', 'type', 'required', 'defaultValue', 'validation', 'secret', 'sideEffects', 'example'];
    const missing = required.filter((attribute) => !(attribute in attributes));
    if (missing.length > 0) {
      throw new Error(`${filename}: ConfigField ${attributes.path ?? '(unknown)'} misses ${missing.join(', ')}`);
    }
    components.push(attributes.path);
  }
  return { coverage: values.coverage, components };
}

async function verifyCoverage(schema) {
  let filenames;
  try {
    filenames = await documents(documentationRoot);
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error(`configuration documentation is missing: ${documentationRoot}`);
    throw error;
  }

  const covered = new Map();
  const rendered = new Map();
  for (const filename of filenames) {
    const display = relative(siteRoot, filename);
    const metadata = documentMetadata(await readFile(filename, 'utf8'), display);
    for (const path of metadata.coverage) {
      const owners = covered.get(path) ?? [];
      owners.push(display);
      covered.set(path, owners);
    }
    for (const path of metadata.components) {
      const owners = rendered.get(path) ?? [];
      owners.push(display);
      rendered.set(path, owners);
    }
  }

  const known = new Set(schema.fields.map((field) => field.path));
  const failures = [];
  for (const field of schema.fields) {
    const owners = covered.get(field.path) ?? [];
    if (owners.length === 0) failures.push(`undocumented schema path ${field.path}`);
    if (owners.length > 1) failures.push(`schema path ${field.path} is covered more than once: ${owners.join(', ')}`);
    const components = rendered.get(field.path) ?? [];
    if (components.length !== 1 || components[0] !== owners[0]) {
      failures.push(`schema path ${field.path} needs exactly one ConfigField in its coverage page`);
    }
  }
  for (const [path, owners] of covered) {
    if (!known.has(path)) failures.push(`invented schema path ${path}: ${owners.join(', ')}`);
  }
  for (const [path, owners] of rendered) {
    if (!known.has(path)) failures.push(`ConfigField uses invented schema path ${path}: ${owners.join(', ')}`);
    if (!(covered.get(path) ?? []).includes(owners[0])) failures.push(`ConfigField ${path} is not listed in the page coverage`);
  }
  if (failures.length > 0) throw new Error(failures.join('\n'));
}

async function main() {
  const write = process.argv.includes('--write');
  const check = process.argv.includes('--check');
  if (write === check) throw new Error('choose exactly one of --write or --check');

  const schema = await currentSchema();
  if (write) {
    await writeFile(schemaPath, `${JSON.stringify(schema, null, 2)}\n`, 'utf8');
    console.log(`Wrote ${schema.fields.length} configuration paths to ${relative(repositoryRoot, schemaPath)}.`);
    return;
  }

  let committed;
  try {
    committed = JSON.parse(await readFile(schemaPath, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error(`schema inventory is missing: ${relative(repositoryRoot, schemaPath)}`);
    throw error;
  }
  if (JSON.stringify(committed) !== JSON.stringify(schema)) {
    throw new Error('config-schema.json is stale; run node scripts/extract-config-schema.mjs --write');
  }
  await verifyCoverage(schema);
  console.log(`Configuration schema coverage passed for ${schema.fields.length} paths.`);
}

main().catch((error) => {
  console.error(`Configuration schema verification failed:\n- ${error.message.replaceAll('\n', '\n- ')}`);
  process.exitCode = 1;
});
