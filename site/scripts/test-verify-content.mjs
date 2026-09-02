import { equal, match, notEqual } from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';

const scriptsDir = dirname(process['argv'][1]);
const verifier = join(scriptsDir, 'verify-content.mjs');
const fixtures = join(scriptsDir, 'fixtures', 'content');

function verify(root, ...args) {
  return spawnSync(process['execPath'], [verifier, '--docs-root', root, ...args], { encoding: 'utf8' });
}

const checkedIn = resolve(scriptsDir, '../src/content/docs');
notEqual(verify(checkedIn)['status'], 0, 'strict parity must fail while Task 9 translations are missing');
equal(verify(checkedIn, '--source-locale', 'en')['status'], 0, 'the canonical English source passes');
equal(verify(join(fixtures, 'missing-peer'), '--source-locale', 'en')['status'], 0,
  'canonical source mode does not require translation peers');
notEqual(verify(join(fixtures, 'duplicate-route'), '--source-locale', 'en')['status'], 0,
  'canonical source mode still rejects duplicate routes');
notEqual(verify(join(fixtures, 'missing-peer'), '--source-locale', 'ru')['status'], 0,
  'a translated locale cannot be declared canonical source');

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
  const result = verify(join(fixtures, fixture));
  notEqual(result['status'], 0, `${fixture} must fail verification`);
  match(result['stderr'], new RegExp(expected));
}

console['log']('Content verifier fixtures passed.');
