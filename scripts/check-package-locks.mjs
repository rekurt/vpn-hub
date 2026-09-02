import { lstatSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, sep } from 'node:path';
import { validatePackageLock } from './validate-package-lock.mjs';

const args = process['argv']['slice'](2);
const ref = args[0] === '--ref' ? args[1] : '';
const decoder = new TextDecoder('utf-8', { fatal: true });
const errors = [];

if (args['length'] !== 0 && (args['length'] !== 2 || args[0] !== '--ref' || !ref)) {
  process['stderr']['write']('usage: check-package-locks.mjs [--ref REF]\n');
  process['exitCode'] = 2;
} else {
  checkLocks();
}

if (errors['length'] > 0) {
  process['stderr']['write'](`package-lock validation failed:\n${errors['map']((error) => `- ${error}`)['join']('\n')}\n`);
  process['exitCode'] = 1;
}

function checkLocks() {
  if (ref) {
    checkHistoricalLocks(ref);
  } else {
    checkWorktreeLocks();
  }
}

function gitOutput(gitArgs, label) {
  const result = spawnSync('git', gitArgs, { cwd: process['cwd'](), encoding: null });
  if (result['error']) {
    errors['push'](`${label}: could not run git: ${result['error']['message']}`);
    return null;
  }
  if (result['status'] !== 0) {
    const details = result['stderr'] ? result['stderr']['toString']('utf8')['trim']() : '';
    errors['push'](`${label}: git command failed${details ? `: ${details}` : ''}`);
    return null;
  }
  return result['stdout'] || Buffer['alloc'](0);
}

function records(buffer, label) {
  const output = [];
  let start = 0;
  for (let index = 0; index < buffer['length']; index += 1) {
    if (buffer[index] === 0) {
      output['push'](buffer['subarray'](start, index));
      start = index + 1;
    }
  }
  if (start !== buffer['length']) errors['push'](`${label}: git output was not NUL-terminated`);
  return output;
}

function decodePath(bytes, label) {
  try {
    return decoder['decode'](bytes);
  } catch {
    errors['push'](`${label}: tracked path is not valid UTF-8`);
    return null;
  }
}

function splitRecord(record, label) {
  const tab = record['indexOf'](9);
  if (tab < 1) {
    errors['push'](`${label}: malformed NUL-delimited git record`);
    return null;
  }
  const path = decodePath(record['subarray'](tab + 1), label);
  if (path === null) return null;
  return { header: record['subarray'](0, tab)['toString']('ascii'), path };
}

function isLock(path) {
  return path === 'package-lock.json' || path['endsWith']('/package-lock.json');
}

function checkWorktreeLocks() {
  const output = gitOutput(['ls-files', '-z', '--stage'], 'worktree package-lock enumeration');
  if (output === null) return;
  for (const record of records(output, 'worktree package-lock enumeration')) {
    const entry = splitRecord(record, 'worktree package-lock enumeration');
    if (!entry || !isLock(entry['path'])) continue;
    const match = /^(\d{6}) ([0-9a-f]+) (\d+)$/['exec'](entry['header']);
    if (!match) {
      errors['push'](`${entry['path']}: malformed index metadata`);
      continue;
    }
    const path = resolve(process['cwd'](), entry['path']);
    const root = `${resolve(process['cwd']())}${sep}`;
    if (!path['startsWith'](root)) {
      errors['push'](`${entry['path']}: tracked path escapes the worktree`);
      continue;
    }
    let status;
    try {
      status = lstatSync(path);
    } catch {
      errors['push'](`${entry['path']}: tracked package-lock is missing from the worktree`);
      continue;
    }
    if (status['isSymbolicLink']() || !status['isFile']()) {
      errors['push'](`${entry['path']}: tracked package-lock must be a non-symlink regular file`);
      continue;
    }
    if (match[3] !== '0' || !match[1]['startsWith']('100')) {
      errors['push'](`${entry['path']}: tracked package-lock must be a stage-0 regular file`);
      continue;
    }
    let bytes;
    try {
      bytes = readFileSync(path);
    } catch {
      errors['push'](`${entry['path']}: could not read tracked package-lock from the worktree`);
      continue;
    }
    validateBytes(bytes, entry['path']);
  }
}

function checkHistoricalLocks(historyRef) {
  const output = gitOutput(['ls-tree', '-rz', '--full-tree', historyRef], `ref ${historyRef} package-lock enumeration`);
  if (output === null) return;
  for (const record of records(output, `ref ${historyRef} package-lock enumeration`)) {
    const entry = splitRecord(record, `ref ${historyRef} package-lock enumeration`);
    if (!entry || !isLock(entry['path'])) continue;
    const match = /^(\d{6}) ([a-z]+) ([0-9a-f]+)$/['exec'](entry['header']);
    const label = `${historyRef}:${entry['path']}`;
    if (!match) {
      errors['push'](`${label}: malformed tree metadata`);
      continue;
    }
    if (!match[1]['startsWith']('100') || match[2] !== 'blob') {
      errors['push'](`${label}: package-lock must be a regular blob`);
      continue;
    }
    const bytes = gitOutput(['cat-file', 'blob', match[3]], label);
    if (bytes !== null) validateBytes(bytes, label);
  }
}

function validateBytes(bytes, label) {
  let source;
  try {
    source = decoder['decode'](bytes);
  } catch {
    errors['push'](`${label}: package-lock is not valid UTF-8`);
    return;
  }
  for (const error of validatePackageLock(source, label)) errors['push'](error);
}
