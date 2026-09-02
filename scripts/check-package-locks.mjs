import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, sep } from 'node:path';
import { validatePackageLock } from './validate-package-lock.mjs';

const maxGitOutputBytes = 64 * 1024 * 1024;
const maxGitOutputLabel = '64 MiB Git output limit';
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
  const result = spawnSync('git', gitArgs, {
    cwd: process['cwd'](),
    encoding: null,
    maxBuffer: maxGitOutputBytes,
  });
  if (result['error']) {
    if (result['error']['code'] === 'ENOBUFS') {
      errors['push'](`${label}: exceeded ${maxGitOutputLabel}`);
      return null;
    }
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

function gitBlob(oid, label) {
  const sizeOutput = gitOutput(['cat-file', '-s', oid], `${label} size`);
  if (sizeOutput === null) return null;
  const sizeText = sizeOutput['toString']('ascii')['trim']();
  if (!/^\d+$/['test'](sizeText)) {
    errors['push'](`${label}: git returned an invalid blob size`);
    return null;
  }
  const size = Number(sizeText);
  if (!Number['isSafeInteger'](size)) {
    errors['push'](`${label}: blob size is not a safe integer`);
    return null;
  }
  if (size > maxGitOutputBytes) {
    errors['push'](`${label}: blob size ${size} bytes exceeded ${maxGitOutputLabel}`);
    return null;
  }
  return gitOutput(['cat-file', 'blob', oid], label);
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
    const label = entry['path'];
    if (match[3] !== '0' || !match[1]['startsWith']('100')) {
      errors['push'](`index:${label}: tracked package-lock must be a stage-0 regular file`);
      continue;
    }
    const indexBytes = gitBlob(match[2], `index:${label}`);
    if (indexBytes !== null) validateBytes(indexBytes, `index:${label}`);

    const path = resolve(process['cwd'](), label);
    const root = `${resolve(process['cwd']())}${sep}`;
    if (!path['startsWith'](root)) {
      errors['push'](`${entry['path']}: tracked path escapes the worktree`);
      continue;
    }
    let status;
    try {
      status = lstatSync(path);
    } catch {
      errors['push'](`worktree:${label}: tracked package-lock is missing from the worktree`);
      continue;
    }
    if (status['isSymbolicLink']() || !status['isFile']()) {
      errors['push'](`worktree:${label}: tracked package-lock must be a non-symlink regular file`);
      continue;
    }
    const worktreeBytes = readWorktreeFile(path, `worktree:${label}`);
    if (worktreeBytes !== null && (indexBytes === null || !worktreeBytes['equals'](indexBytes))) {
      validateBytes(worktreeBytes, `worktree:${label}`);
    }
  }
}

function readWorktreeFile(path, label) {
  let descriptor;
  try {
    descriptor = openSync(path, constants['O_RDONLY'] | (constants['O_NOFOLLOW'] || 0));
    const status = fstatSync(descriptor);
    if (!status['isFile']()) {
      errors['push'](`${label}: tracked package-lock must be a non-symlink regular file`);
      return null;
    }
    if (status['size'] > maxGitOutputBytes) {
      errors['push'](`${label}: file size ${status['size']} bytes exceeded 64 MiB package-lock limit`);
      return null;
    }
    const bytes = Buffer['allocUnsafe'](status['size']);
    let offset = 0;
    while (offset < bytes['length']) {
      const count = readSync(descriptor, bytes, offset, bytes['length'] - offset, null);
      if (count === 0) break;
      offset += count;
    }
    const extra = Buffer['allocUnsafe'](1);
    if (readSync(descriptor, extra, 0, 1, null) !== 0) {
      errors['push'](`${label}: tracked package-lock changed while it was read`);
      return null;
    }
    return offset === bytes['length'] ? bytes : bytes['subarray'](0, offset);
  } catch {
    errors['push'](`${label}: could not safely read tracked package-lock from the worktree`);
    return null;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
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
    const bytes = gitBlob(match[3], label);
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
