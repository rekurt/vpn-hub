import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
const verifier = path.join(scriptsDir, 'verify-content.mjs');
const fixtures = path.join(scriptsDir, 'fixtures', 'content');

function verify(root) {
  return spawnSync(process.execPath, [verifier, '--docs-root', root], { encoding: 'utf8' });
}

assert.equal(verify(path.resolve(scriptsDir, '../src/content/docs')).status, 0, 'the checked-in docs pass');

for (const [fixture, expected] of [
  ['missing-root', 'docs root is required'],
  ['missing-locale', 'locale directory is required'],
  ['all-empty', 'at least one Markdown or MDX document is required'],
  ['missing-peer', 'missing locale peer'],
  ['duplicate-route', 'duplicate final route'],
  ['missing-frontmatter', 'non-empty description'],
  ['null-frontmatter', 'non-empty description'],
  ['comment-frontmatter', 'non-empty description'],
  ['non-string-frontmatter', 'non-empty description'],
]) {
  const result = verify(path.join(fixtures, fixture));
  assert.notEqual(result.status, 0, `${fixture} must fail verification`);
  assert.match(result.stderr, new RegExp(expected));
}

console.log('Content verifier fixtures passed.');
