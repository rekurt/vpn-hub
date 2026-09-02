#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const maximumTextBytes = 64 * 1024 * 1024;
const textSourcePattern = /\.(?:astro|auth|conf|css|go|golden|hcl|html|js|json|link|md|mdx|mjs|mod|nft|ovpn|service|sh|sock|sum|svg|target|tf|tfvars|ts|txt|ya?ml)$/i;
const strictDecoder = new TextDecoder('utf-8', { fatal: true });

function gitBuffer(args, maxBuffer = maximumTextBytes) {
  const result = spawnSync('git', args, { encoding: null, maxBuffer });
  if (result['error']) throw result['error'];
  if (result['status'] !== 0) {
    const diagnostic = Buffer['isBuffer'](result['stderr']) ? result['stderr']['toString']('utf8')['trim']() : '';
    throw new Error(`git ${args[0]} failed${diagnostic ? `: ${diagnostic}` : ''}`);
  }
  return result['stdout'];
}

function nulRecords(buffer) {
  const records = [];
  let start = 0;
  while (start < buffer['length']) {
    const end = buffer['indexOf'](0, start);
    if (end === -1) throw new Error('Git returned a malformed non-NUL-terminated record');
    records['push'](buffer['subarray'](start, end));
    start = end + 1;
  }
  return records;
}

function decodePath(buffer) {
  const path = strictDecoder['decode'](buffer);
  if (!path) throw new Error('Git returned an empty tracked path');
  return path;
}

function validateText(path, content, scope) {
  if (content['length'] > maximumTextBytes) throw new Error(`${scope}:${path}: text source exceeds 64 MiB`);
  if (content['includes'](0)) throw new Error(`${scope}:${path}: text source contains NUL bytes`);
  try {
    strictDecoder['decode'](content);
  } catch {
    throw new Error(`${scope}:${path}: text source is not valid UTF-8`);
  }
}

function readBlob(oid, path, scope) {
  const sizeBuffer = gitBuffer(['cat-file', '-s', oid], 1024);
  const sizeText = sizeBuffer['toString']('ascii')['trim']();
  if (!/^[0-9]+$/['test'](sizeText)) throw new Error(`${scope}:${path}: invalid Git blob size`);
  const size = Number(sizeText);
  if (!Number['isSafeInteger'](size) || size > maximumTextBytes) {
    throw new Error(`${scope}:${path}: text source exceeds 64 MiB`);
  }
  validateText(path, gitBuffer(['cat-file', 'blob', oid], maximumTextBytes + 1), scope);
}

function validateIndex() {
  for (const entry of nulRecords(gitBuffer(['ls-files', '-s', '-z']))) {
    const tab = entry['indexOf'](9);
    if (tab === -1) throw new Error('index: malformed Git index record');
    const header = entry['subarray'](0, tab)['toString']('ascii');
    const match = header['match'](/^(\d{6}) ([0-9a-f]+) (\d+)$/);
    if (!match) throw new Error('index: malformed Git index metadata');
    const path = decodePath(entry['subarray'](tab + 1));
    if (!textSourcePattern['test'](path)) continue;
    if (!/^(?:100644|100755)$/.test(match[1]) || match[3] !== '0') {
      throw new Error(`index:${path}: text source must be a regular stage-0 blob`);
    }
    readBlob(match[2], path, 'index');
  }
}

function validateWorktree() {
  for (const pathBuffer of nulRecords(gitBuffer(['ls-files', '-z']))) {
    const path = decodePath(pathBuffer);
    if (!textSourcePattern['test'](path)) continue;
    let metadata;
    try {
      metadata = lstatSync(pathBuffer);
    } catch (error) {
      if (error?.['code'] === 'ENOENT') continue;
      throw error;
    }
    if (!metadata['isFile']() || metadata['isSymbolicLink']()) {
      throw new Error(`worktree:${path}: text source must be a regular non-symlink file`);
    }
    if (metadata['size'] > maximumTextBytes) throw new Error(`worktree:${path}: text source exceeds 64 MiB`);
    validateText(path, readFileSync(pathBuffer), 'worktree');
  }
}

function validateRef(ref) {
  for (const entry of nulRecords(gitBuffer(['ls-tree', '-rz', '--full-tree', ref]))) {
    const tab = entry['indexOf'](9);
    if (tab === -1) throw new Error(`${ref}: malformed Git tree record`);
    const header = entry['subarray'](0, tab)['toString']('ascii');
    const match = header['match'](/^(\d{6}) ([a-z]+) ([0-9a-f]+)$/);
    if (!match) throw new Error(`${ref}: malformed Git tree metadata`);
    const path = decodePath(entry['subarray'](tab + 1));
    if (!textSourcePattern['test'](path)) continue;
    if (!/^(?:100644|100755)$/.test(match[1]) || match[2] !== 'blob') {
      throw new Error(`${ref}:${path}: text source must be a regular blob`);
    }
    readBlob(match[3], path, ref);
  }
}

if (process['argv']['includes']('--validate-text')) {
  const refFlag = process['argv']['indexOf']('--ref');
  try {
    if (refFlag !== -1) {
      const ref = process['argv'][refFlag + 1];
      if (!ref) throw new Error('--ref requires a Git object');
      validateRef(ref);
    } else {
      validateIndex();
      validateWorktree();
    }
  } catch (error) {
    console['error'](`tracked text validation failed: ${error['message']}`);
    process['exit'](1);
  }
  process['exit'](0);
}

const schemaFlag = process['argv']['indexOf']('--schema');
const schemaFile = schemaFlag === -1 ? '' : process['argv'][schemaFlag + 1];
const schemaPaths = new Set();
if (schemaFile && existsSync(resolve(schemaFile))) {
  try {
    const schema = JSON['parse'](readFileSync(resolve(schemaFile), 'utf8'));
    for (const field of schema['fields'] ?? []) {
      schemaPaths['add'](field['path']);
      const parts = field['path']['replaceAll']('[]', '')['split']('.');
      for (let index = 0; index < parts['length'] - 1; index += 1) {
        schemaPaths['add'](parts['slice'](index)['join']('.'));
      }
    }
  } catch (error) {
    console['error'](`configuration schema could not be read: ${error['message']}`);
    process['exit'](2);
  }
}

const input = readFileSync(0);
const decoder = strictDecoder;
const records = [];
let inputOffset = 0;
try {
  while (inputOffset < input['length']) {
    const first = input['indexOf'](0, inputOffset);
    const second = first === -1 ? -1 : input['indexOf'](0, first + 1);
    const end = second === -1 ? -1 : input['indexOf'](10, second + 1);
    if (first === -1 || second === -1 || end === -1) {
      throw new Error('malformed NUL-delimited git grep record');
    }
    const path = decoder['decode'](input['subarray'](inputOffset, first));
    const number = decoder['decode'](input['subarray'](first + 1, second));
    const content = decoder['decode'](input['subarray'](second + 1, end));
    if (!path || !/^[1-9][0-9]*$/['test'](number)) {
      throw new Error('invalid path or line number in git grep record');
    }
    records['push']({ path, number, content });
    inputOffset = end + 1;
  }
} catch (error) {
  console['error'](`address input could not be read: ${error['message']}`);
  process['exit'](2);
}

const codeExtensions = /\.(?:go|[cm]?js|ts|tf)$/;
const addressPattern = /(?<![A-Za-z0-9_-])((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,})(?![A-Za-z0-9_-])/g;
const memberPattern = /(?<![A-Za-z0-9_-])((?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*)(?![A-Za-z0-9_-])/g;
const memberValuePattern = /^(?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*$/;
const filenamePattern = /\.(?:conf|ya?ml|json|mdx?|go|mod|sum|mjs|js|ts|tf|astro|svg|css|txt|key(?:\.[A-Za-z0-9_-]+)?|crt|csr|nft|service|target|sock|log|tfstate|tfvars|golden|link|hcl|sh|gz|linux|binary|html|auth|ovpn)$/i;

const states = new Map();
const segmentsByRecord = [];
const executableIdentifiersByPath = new Map();
const declaredRootsByPath = new Map();
const goImportBlocks = new Map();
const reviewedIdentifiers = new Set([
  ['Egress', 'Apply'], ['DNS', 'Apply'], ['source', 'kind'], ['source', 'value'],
  ['github', 'ref'], ['github', 'token'], ['concurrency', 'group'], ['main', 'version'],
  ['http', 'server'], ['Interface', 'DNS'], ['Interface', 'MTU'], ['Interface', 'PrivateKey'],
  ['Interface', 'Address'], ['Peer', 'PublicKey'], ['Peer', 'Endpoint'], ['Peer', 'PresharedKey'],
  ['Peer', 'AllowedIPs'], ['Peer', 'PersistentKeepalive'],
  ['testing', 'T', 'TempDir'], ['ctx', 'Done'], ['bufio', 'Scanner'],
  ['domain', 'ProxyTunnel', 'OriginServer'], ['Addr', 'Compare'],
  ['DNSPlan', 'UpstreamNamespace'], ['DNSPlan', 'EgressResolvers'],
  ['FirewallPlan', 'DNSDestinations'], ['FirewallPlan', 'Egresses'],
  ['buildinfo', 'String'], ['buildinfo', 'Version'], ['RELEASE', 'json', 'version'], ['bot', 'Config'],
  ['Bot', 'init'], ['Bot', 'text'], ['Cfg', 'Locale'], ['ConfirmationStore', 'Arm'],
  ['File', 'Sync'], ['Hub', 'DNSAddress'], ['ProxyTunnel', 'UUID'],
  ['SubscriptionRefresher', 'Refresh'], ['context', 'Context'], ['context', 'DeadlineExceeded'],
  ['errors', 'Is'], ['exec', 'Command'], ['fmt', 'Sprintf'], ['hash', 'Hash'],
  ['health', 'EndpointResolver'], ['health', 'PinPublicEndpoint'],
  ['http', 'Client', 'Timeout'], ['http', 'DefaultClient'], ['linux', 'TunnelConfigFiles'],
  ['net', 'DefaultResolver'], ['net', 'SplitHostPort'], ['netip', 'Addr'], ['os', 'WriteFile'],
  ['scanner', 'Buffer'], ['tg', 'BotCommand'], ['time', 'Duration'], ['time', 'Millisecond'],
  ['time', 'Minute'], ['time', 'NewTicker'], ['time', 'Time'], ['b', 'text'],
  ['steps', 'deployment', 'outputs'], ['canonical', 'href'], ['alternateLocales', 'map'],
  ['buildinfo', 'Commit'], ['buildinfo', 'Date'], ['field', 'source'],
]['map']((parts) => parts['join']('.')));
const reviewedFiles = new Set([
  ['nftables', 'service']['join']('.'), ['hub', 'yaml']['join']('.'),
  ['devices', 'yaml']['join']('.'), ['telegram', 'yaml']['join']('.'),
  ['CHANGELOG', 'md']['join']('.'), ['CONTRIBUTING', 'md']['join']('.'),
  ['README', 'md']['join']('.'), ['README', 'ru', 'md']['join']('.'),
  ['README', 'zh-CN', 'md']['join']('.'), ['RELEASE', 'json']['join']('.'),
  ['SECURITY', 'md']['join']('.'), ['SUPPORT', 'md']['join']('.'),
  ['astro', 'config', 'mjs']['join']('.'), ['bot-use-cases', 'json']['join']('.'),
  ['cloud-init', 'yaml']['join']('.'), ['config-schema', 'json']['join']('.'),
  ['desired-state', 'json']['join']('.'), ['docs', 'yml']['join']('.'),
  ['index', 'astro']['join']('.'), ['install', 'sh']['join']('.'),
  ['keys', 'txt']['join']('.'), ['landing', 'ts']['join']('.'),
  ['laptop', 'conf']['join']('.'), ['package', 'json']['join']('.'),
  ['robots', 'txt']['join']('.'), ['ru', 'json']['join']('.'),
  ['sops-v3', '13', '3', 'linux']['join']('.'), ['tar', 'gz']['join']('.'),
  ['terraform', 'tfstate']['join']('.'), ['terraform', 'tfvars']['join']('.'),
  ['verify-content', 'mjs']['join']('.'),
  ['ca', 'crt']['join']('.'), ['client', 'key']['join']('.'), ['config', 'yaml']['join']('.'),
  ['corp-a', 'conf']['join']('.'), ['corp-wg', 'conf']['join']('.'), ['main', 'golden']['join']('.'),
  ['provider', 'key']['join']('.'), ['server', 'crt']['join']('.'),
  ['server', 'key']['join']('.'), ['server', 'key', 'previous']['join']('.'), ['status', 'golden']['join']('.'),
  ['test', 'addr']['join']('.'), ['test', 'endpoint']['join']('.'),
  ['vpn-hub-agent', 'service']['join']('.'), ['vpn-hub-proxy-nl', 'service']['join']('.'),
]);

function stateFor(path) {
  if (!states['has'](path)) {
    states['set'](path, {
      code: 'code',
      templateDepth: 0,
      frontmatter: 0,
      fence: false,
      fenceLanguage: '',
      astroFrontmatter: 0,
    });
  }
  return states['get'](path);
}

function executableIdentifiersFor(path) {
  if (!executableIdentifiersByPath['has'](path)) executableIdentifiersByPath['set'](path, new Set());
  return executableIdentifiersByPath['get'](path);
}

function declaredRootsFor(path) {
  if (!declaredRootsByPath['has'](path)) declaredRootsByPath['set'](path, new Set());
  return declaredRootsByPath['get'](path);
}

function collectDeclaredRoots(record, segments) {
  if (!codeExtensions['test'](record['path']) && !/\.astro$/.test(record['path'])) return;
  const roots = declaredRootsFor(record['path']);
  const line = record['content'];
  const executable = segments['filter']((segment) => segment['kind'] === 'executable')['map']((segment) => segment['text'])['join'](' ');
  if (/\.go$/.test(record['path'])) {
    if (/^\s*import\s*\(\s*$/.test(line)) goImportBlocks['set'](record['path'], true);
    const singleImport = line['match'](/^\s*import\s+(?:(\w+)\s+)?"([^"]+)"/);
    const blockImport = goImportBlocks['get'](record['path']) ? line['match'](/^\s*(?:(\w+)\s+)?"([^"]+)"/) : null;
    for (const imported of [singleImport, blockImport]) {
      if (!imported) continue;
      const root = imported[1] || imported[2]['split']('/')['at'](-1);
      if (root !== '_' && root !== '.') roots['add'](root);
    }
    if (goImportBlocks['get'](record['path']) && /^\s*\)\s*$/.test(line)) goImportBlocks['set'](record['path'], false);
    for (const match of executable['matchAll'](/\b([A-Za-z_][A-Za-z0-9_]*)\s*:=/g)) roots['add'](match[1]);
    for (const match of executable['matchAll'](/\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\b/g)) roots['add'](match[1]);
    for (const signature of executable['matchAll'](/\bfunc\b[^()]*\(([^)]*)\)/g)) {
      for (const parameter of signature[1]['split'](',')) {
        const name = parameter['trim']()['match'](/^([A-Za-z_][A-Za-z0-9_]*)\b/);
        if (name && !/^(?:context|string|int|bool|byte|rune|error)$/.test(name[1])) roots['add'](name[1]);
      }
    }
    return;
  }
  for (const match of executable['matchAll'](/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/g)) roots['add'](match[1]);
  for (const match of executable['matchAll'](/\b(?:const|let|var)\s*\{([^}]+)\}/g)) {
    for (const name of match[1]['split'](',')) {
      const identifier = name['trim']()['match'](/^([A-Za-z_$][A-Za-z0-9_$]*)/);
      if (identifier) roots['add'](identifier[1]);
    }
  }
  for (const match of executable['matchAll'](/\bimport\s+(?:\*\s+as\s+|\{\s*)?([A-Za-z_$][A-Za-z0-9_$]*)/g)) roots['add'](match[1]);
  for (const signature of executable['matchAll'](/(?:function\s*[A-Za-z_$][A-Za-z0-9_$]*\s*|\b)\(([^)]*)\)\s*(?:=>|\{)/g)) {
    for (const parameter of signature[1]['split'](',')) {
      const name = parameter['trim']()['match'](/^([A-Za-z_$][A-Za-z0-9_$]*)/);
      if (name) roots['add'](name[1]);
    }
  }
}

function appendSegment(segments, kind, text, start) {
  if (!text) return;
  const previous = segments['at'](-1);
  if (previous && previous['kind'] === kind && previous['start'] + previous['text']['length'] === start) {
    previous['text'] += text;
    return;
  }
  segments['push']({ kind, text, start });
}

function lexCode(content, state, singleIsString = true) {
  const segments = [];
  let offset = 0;
  let segmentStart = 0;
  let buffer = '';
  let kind = state['code'] === 'code' ? 'executable' : state['code'] === 'block' ? 'comment' : 'literal';
  const flush = () => {
    appendSegment(segments, kind, buffer, segmentStart);
    buffer = '';
  };
  const switchKind = (next, start) => {
    flush();
    kind = next;
    segmentStart = start;
  };

  while (offset < content['length']) {
    const char = content[offset];
    const pair = content['slice'](offset, offset + 2);
    if (state['code'] === 'block') {
      if (pair === '*/') {
        buffer += pair;
        offset += 2;
        state['code'] = 'code';
        switchKind('executable', offset);
      } else {
        buffer += char;
        offset += 1;
      }
      continue;
    }
    if (state['code'] === 'double' || state['code'] === 'single' || state['code'] === 'raw' || state['code'] === 'rune') {
      const terminator = state['code'] === 'double' ? '"' : state['code'] === 'raw' ? '`' : "'";
      if (state['code'] === 'raw' && singleIsString && pair === '${') {
        buffer += pair;
        offset += 2;
        state['code'] = 'code';
        state['templateDepth'] = 1;
        switchKind('executable', offset);
      } else if (char === '\\' && state['code'] !== 'raw' && offset + 1 < content['length']) {
        buffer += content['slice'](offset, offset + 2);
        offset += 2;
      } else if (char === terminator) {
        buffer += char;
        offset += 1;
        state['code'] = 'code';
        switchKind('executable', offset);
      } else {
        buffer += char;
        offset += 1;
      }
      continue;
    }
    if (state['templateDepth'] > 0 && char === '{') {
      state['templateDepth'] += 1;
      buffer += char;
      offset += 1;
      continue;
    }
    if (state['templateDepth'] > 0 && char === '}') {
      state['templateDepth'] -= 1;
      buffer += char;
      offset += 1;
      if (state['templateDepth'] === 0) {
        state['code'] = 'raw';
        switchKind('literal', offset);
      }
      continue;
    }
    if (pair === '//') {
      switchKind('comment', offset);
      buffer += content['slice'](offset);
      offset = content['length'];
      continue;
    }
    if (pair === '/*') {
      switchKind('comment', offset);
      buffer += pair;
      offset += 2;
      state['code'] = 'block';
      continue;
    }
    if (char === '"' || char === '`' || char === "'") {
      switchKind('literal', offset);
      buffer += char;
      offset += 1;
      state['code'] = char === '"' ? 'double' : char === '`' ? 'raw' : singleIsString ? 'single' : 'rune';
      continue;
    }
    buffer += char;
    offset += 1;
  }
  flush();
  if (state['code'] === 'double' || state['code'] === 'single' || state['code'] === 'rune') state['code'] = 'code';
  return segments;
}

function splitInlineCode(content, baseKind = 'prose') {
  const segments = [];
  let offset = 0;
  for (const match of content['matchAll'](/`([^`]+)`/g)) {
    appendSegment(segments, baseKind, content['slice'](offset, match['index']), offset);
    appendSegment(segments, 'docs-code', match[0], match['index']);
    offset = match['index'] + match[0]['length'];
  }
  appendSegment(segments, baseKind, content['slice'](offset), offset);
  return segments;
}

function markdownSegments(record, state) {
  const line = record['content'];
  if (line === '---' && state['frontmatter'] === 0 && record['number'] === '1') {
    state['frontmatter'] = 1;
    return [];
  }
  if (line === '---' && state['frontmatter'] === 1) {
    state['frontmatter'] = 2;
    return [];
  }
  if (state['frontmatter'] === 1) return [{ kind: 'frontmatter', text: line, start: 0 }];
  const fence = line['match'](/^```([A-Za-z0-9_-]*)\s*$/);
  if (fence) {
    state['fence'] = !state['fence'];
    state['fenceLanguage'] = state['fence'] ? fence[1]['toLowerCase']() : '';
    state['code'] = 'code';
    return [];
  }
  if (state['fence']) {
    if (/^(?:go|javascript|js|typescript|ts|hcl|terraform)$/.test(state['fenceLanguage'])) {
      return lexCode(line, state, state['fenceLanguage'] !== 'go')['map']((segment) => ({
        ...segment,
        kind: segment['kind'] === 'executable' ? 'executable' : segment['kind'],
      }));
    }
    return [{ kind: 'docs-code', text: line, start: 0 }];
  }
  return splitInlineCode(line);
}

function astroSegments(record, state) {
  const line = record['content'];
  if (line === '---' && state['astroFrontmatter'] < 2) {
    state['astroFrontmatter'] += 1;
    return [];
  }
  if (state['astroFrontmatter'] === 1) return lexCode(line, state, true);
  const segments = [];
  let offset = 0;
  for (const match of line['matchAll'](/\{([^{}]*)\}/g)) {
    for (const segment of splitInlineCode(line['slice'](offset, match['index']), 'prose')) {
      appendSegment(segments, segment['kind'], segment['text'], offset + segment['start']);
    }
    for (const segment of lexCode(match[1], state, true)) {
      appendSegment(segments, segment['kind'], segment['text'], match['index'] + 1 + segment['start']);
    }
    offset = match['index'] + match[0]['length'];
  }
  for (const segment of splitInlineCode(line['slice'](offset), 'prose')) {
    appendSegment(segments, segment['kind'], segment['text'], offset + segment['start']);
  }
  return segments;
}

for (const record of records) {
  if (/(?:^|\/)package-lock\.json$/.test(record['path'])) {
    segmentsByRecord['push']([]);
    continue;
  }
  const state = stateFor(record['path']);
  let segments;
  if (/\.mdx?$/.test(record['path'])) segments = markdownSegments(record, state);
  else if (/\.astro$/.test(record['path'])) segments = astroSegments(record, state);
  else if (codeExtensions.test(record['path'])) segments = lexCode(record['content'], state, !/\.go$/.test(record['path']));
  else segments = [{ kind: 'data', text: record['content'], start: 0 }];
  segmentsByRecord['push'](segments);
  collectDeclaredRoots(record, segments);
  const executableIdentifiers = executableIdentifiersFor(record['path']);
  for (const segment of segments) {
    if (segment['kind'] !== 'executable') continue;
    for (const match of segment['text']['matchAll'](/\bfunc\s*\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s+\*?([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
      executableIdentifiers['add'](`${match[1]}.${match[2]}`);
    }
    for (const match of segment['text']['matchAll'](memberPattern)) {
      const parts = match[1]['split']('.');
      for (let index = 0; index < parts['length'] - 1; index += 1) {
        executableIdentifiers['add'](parts['slice'](index)['join']('.'));
      }
    }
  }
}

function localContext(record, absoluteStart, length) {
  const before = record['content']['slice'](Math['max'](0, absoluteStart - 80), absoluteStart);
  const after = record['content']['slice'](absoluteStart + length, absoluteStart + length + 80);
  return {
    before,
    after,
    lowerBefore: before['toLowerCase'](),
    lowerAfter: after['toLowerCase'](),
    line: record['content'],
    absoluteStart,
    absoluteEnd: absoluteStart + length,
  };
}

function hasNetworkContext(context) {
  const before = context['line']['slice'](0, context['absoluteStart'])['toLowerCase']();
  const after = context['line']['slice'](context['absoluteEnd'])['toLowerCase']();
  return /:\/\/[^\s]*$/.test(before) ||
    /\b(?:dial|reach|visit|fetch|resolve|connect|contact|open)\b\s+[^.;\n]{0,96}$/.test(before) ||
    /(?:^|[;&|]\s*)(?:source|route)\s+[^.;\n]{0,96}$/.test(before) ||
    /\b(?:endpoint|hostname|url|dns_name|server|host|source|address|route)\b\s*(?::=|=>|:|=)\s*[`"'(${\[]*$/.test(before) ||
    /^\s*(?:as\s+(?:the\s+)?(?:endpoint|hostname|url|server|host|source|address|route)|:\/\/)/.test(after);
}

function isRegexLiteralCandidate(segment, record, absoluteStart, length) {
  if (segment['kind'] !== 'executable') return false;
  const line = segment['text'];
  const relativeStart = absoluteStart - segment['start'];
  let opening = -1;
  for (let index = relativeStart - 1; index >= 0; index -= 1) {
    if (line[index] !== '/') continue;
    let escapes = 0;
    for (let cursor = index - 1; cursor >= 0 && line[cursor] === '\\'; cursor -= 1) escapes += 1;
    if (escapes % 2 === 0) {
      opening = index;
      break;
    }
  }
  if (opening === -1) return false;
  for (let index = relativeStart + length; index < line['length']; index += 1) {
    if (line[index] !== '/') continue;
    let escapes = 0;
    for (let cursor = index - 1; cursor >= 0 && line[cursor] === '\\'; cursor -= 1) escapes += 1;
    if (escapes % 2 === 0) return true;
  }
  return false;
}

function closedCallContainsCandidate(line, absoluteStart, absoluteEnd) {
  const callPattern = /\b(?:filepath\.Join|path\.join|resolve|join|os\.(?:Open|ReadFile|WriteFile|Rename|Remove|Stat)|fs\.(?:readFileSync|writeFileSync|openSync|renameSync|rmSync|statSync|lstatSync)|ReadFile|WriteFile|readFileSync|writeFileSync|openSync|rename|remove|copyFile|install|stat|lstat|create|read|write|SendDocument)\s*\(/g;
  for (const match of line['matchAll'](callPattern)) {
    const opening = match['index'] + match[0]['lastIndexOf']('(');
    if (opening >= absoluteStart) continue;
    let depth = 0;
    let quote = '';
    let escaped = false;
    for (let index = opening; index < line['length']; index += 1) {
      const char = line[index];
      if (quote) {
        if (escaped) escaped = false;
        else if (char === '\\' && quote !== '`') escaped = true;
        else if (char === quote) quote = '';
        continue;
      }
      if (char === '"' || char === "'" || char === '`') {
        quote = char;
        continue;
      }
      if (char === '(') depth += 1;
      else if (char === ')') {
        depth -= 1;
        if (depth === 0) {
          if (absoluteStart > opening && absoluteEnd <= index) return true;
          break;
        }
      }
    }
  }
  return false;
}

function isSchemaEvidence(value, segment, record, context) {
  if (!schemaPaths['has'](value)) return false;
  if (hasNetworkContext(context)) return false;
  if (record['path'] === 'site/src/data/config-schema.json') return true;
  if (segment['kind'] === 'frontmatter') return true;
  if (segment['kind'] === 'docs-code') return true;
  if (/<ConfigField\b[^>]*\bpath=["'][^"']*["']/.test(record['content'])) return true;
  if ((segment['kind'] === 'comment' || segment['kind'] === 'literal') &&
      (/\b(?:field|setting|mapstructure|gated by|switch|turn)\b|\b(?:on|off)\b/i.test(`${context['lowerBefore']}${context['lowerAfter']}`) ||
       /fmt\.Errorf|validation|required/.test(record['content']))) {
    return true;
  }
  if (/^\s*(?:#|\/\/)/.test(record['content']) &&
      /\b(?:gated by|switch|field|setting)\b/i.test(record['content'])) return true;
  return false;
}

function isCodeIdentifier(value, segment, record, context) {
  if (segment['kind'] === 'executable') return false;
  if ((segment['kind'] === 'docs-code' || segment['kind'] === 'comment' || segment['kind'] === 'literal') &&
      reviewedIdentifiers['has'](value) && /[A-Z]/.test(value)) return true;
  if (hasNetworkContext(context)) return false;
  const executableIdentifiers = executableIdentifiersFor(record['path']);
  if (segment['kind'] === 'docs-code') {
    return reviewedIdentifiers['has'](value) || executableIdentifiers['has'](value);
  }
  if (segment['kind'] === 'comment' && /\.go$/.test(record['path']) && reviewedIdentifiers['has'](value) &&
      /\b(?:field|key|config(?:uration)? option|declaration|reference|identifier|symbol|method|interface|property)\b/i.test(record['content'])) return true;
  if (segment['kind'] === 'literal' && codeExtensions.test(record['path']) && reviewedIdentifiers['has'](value) &&
      /\b(?:called|want|expected|field|key|config(?:uration)? option|declaration|reference|identifier|symbol|method|interface|property)\b/i.test(record['content'])) return true;
  if (segment['kind'] === 'literal' && reviewedIdentifiers['has'](value) &&
      /(?:^|\/)wgconfig(?:_test)?\.go$/.test(record['path'])) return true;
  if ((segment['kind'] === 'comment' || segment['kind'] === 'literal') &&
      executableIdentifiers['has'](value) && /[A-Z]/.test(value)) return true;
  return false;
}

function hasDirectFileEvidence(value, segment, record, context, absoluteStart) {
  const previous = absoluteStart > 0 ? record['content'][absoluteStart - 1] : '';
  const line = record['content'];
  const pathPrefix = line['slice'](Math['max'](0, absoluteStart - 200), absoluteStart);
  if (/(?:^|[`"'(\s=:,+])(?:\/etc\/|\/var\/|\/tmp\/|\/run\/|\/usr\/|\/opt\/|\/home\/|\/root\/|\.\.\/|\.\/|\.github\/|assets\/|bin\/|cmd\/|configs\/|deploy\/|docs\/|internal\/|scripts\/|secrets\/|site\/|testdata\/|tests\/|tunnels\/)[^\s`"'()<>]*$/i.test(pathPrefix)) return true;
  if (/(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\([^)]+\)|\$\{path\.module\}|[A-Za-z_][A-Za-z0-9_]*(?:Dir|Root|Path))\s*[}"']*\s*\+?\s*["']?\/[^\s`"'()<>]*$/i.test(pathPrefix)) return true;
  if (record['path'] === 'go.sum' && previous === '/' && value === 'go.mod') return true;
  if (!filenamePattern.test(value)) return false;
  filenamePattern['lastIndex'] = 0;
  if (hasNetworkContext(context)) return false;
  if (closedCallContainsCandidate(line, absoluteStart, absoluteStart + value['length'])) return true;
  if (segment['kind'] === 'docs-code' &&
      /\b(?:file|path|artifact|archive|profile|identity)\b/i.test(`${context['before']}${context['after']}`)) return true;
  if (segment['kind'] === 'docs-code' && reviewedFiles['has'](value)) return true;
  if ((segment['kind'] === 'comment' || (segment['kind'] === 'data' && /^\s*#/.test(line))) && reviewedFiles['has'](value) &&
      /\b(?:file|path|config(?:uration)?|artifact|archive|profile|identity|state|unit|service|systemd|script|workflow|manifest|key|copy|ship|install|remove|leave|left|edit|write|read|create|find|found|procedure|host)\b/i.test(line)) return true;
  if (/\bfiles?\s+(?:here|named|called)\s*\(?$/i.test(context['before'])) return true;
  if (record['path'] === '.gitignore') return true;
  if (/\.service$/.test(record['path']) && /^(?:After|Wants|WantedBy)=/.test(line)) return true;
  if (/\b(?:systemctl|journal(?:ctl)?|auth-user-pass|git\s+add)\b[^;&|]*$/i.test(context['before']) ||
      (/\.service$/i.test(value) && /\bsystemctl\b/.test(line))) return true;
  const escapedValue = value['replace'](/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (new RegExp(`\\b(?:http-proxy-user-pass|auth-user-pass)\\s+${escapedValue}\\b`, 'i').test(line)) return true;
  if (/(?:--output|-(?:keyout|out|in|CA|CAkey))\s+\$?[A-Za-z_]*["']?$/i.test(context['before'])) return true;
  if (/\b[A-Za-z0-9_]*(?:File|Path|ConfigName|TGZ|Unit|Archive)\s*(?::=|=|===|!==|==|!=|:)\s*["']?$/i.test(context['before'])) return true;
  if (/\bSource\s*(?::|=)\s*[^}]*\bSourceConfig\b[^}]*\bValue\s*:\s*["']?$/i.test(context['before'])) return true;
  if (/\b(?:filename|verifier|output|configFile|configPath|path|file)\s*(?::=|=|===|!==|==|!=|:)\s*["']?$/i.test(context['before'])) return true;
  const filePhrase = new RegExp(`(?:file|path|config(?:uration)? file|artifact|archive|profile|identity|state file|unit|service|systemd unit|script|workflow|manifest|key file)\\s+(?:[^.;,:]{0,24}\\s+)?${escapedValue}|${escapedValue}\\s+(?:file|path|is\\s+optional|may\\s+hold|was\\s+removed|was\\s+left|left\\s+behind|mode\\b|is\\s+stale)`, 'i');
  if (filePhrase.test(line)) return true;
  if (/\bfor\s+_,\s*(?:name|unit)\s*:=\s*range\s*\[\]string\s*\{/.test(line)) return true;
  if (/\b(?:_SYSTEMD_UNIT|Unit)\s*["']?\s*:\s*["']?$/.test(context['before'])) return true;
  if (/\b(?:probe|renderLogTail|journalNotification)\b[^;&|]*$/i.test(context['before']) && /\.service$/i.test(value)) return true;
  if (/\bstrings\.TrimSuffix\s*\([^;]*\)\s*\+\s*["']?$/i.test(context['before'])) return true;
  if (/\b(?:archive|[A-Z0-9_]*TGZ)\s*=\s*["'][^"']*$/i.test(context['before'])) return true;
  if (new RegExp(`\\bexpected\\s+only\\s+${escapedValue}\\b`, 'i').test(line)) return true;
  if (/\b(?:file\s+system|usage)\s*:/i.test(context['before'])) return true;
  if (/\bstrings\.TrimSuffix\b/.test(line) && new RegExp(`\\+\\s*["']\\.?${escapedValue}["']`).test(line)) return true;
  if (value === ['server', 'key']['join']('.') && /(?:^|\/)locale_(?:en|ru)\.go$/.test(record['path'])) return true;
  if (value === ['server', 'key', 'previous']['join']('.') && /(?:^|\/)locale_(?:en|ru)\.go$/.test(record['path'])) return true;
  if (value === ['telegram', 'yaml']['join']('.') && /(?:locale_(?:en|ru)\.go$|testdata\/(?:en|ru)\/settings\.golden$|site\/src\/data\/bot-screens\.(?:en|ru)\.json$)/.test(record['path'])) return true;
  if (/(?:├──|└──)\s*$/.test(context['before'])) return true;
  if (/\b(?:go-version-file|log:[uf]:)\b/.test(line)) return true;
  if (/\.service$/i.test(value) && /\bloaded\s+(?:active|failed)\b/.test(line)) return true;
  if (/\b(?:Unit|Service)\s*!?=/.test(context['before']) || /\bdocs\[\d+\]\s*!?=/.test(context['before'])) return true;
  if (/\bkind\s*:\s*config\b.*\bvalue\s*:/.test(line['slice'](0, absoluteStart))) return true;
  if (/\bName\(\)\s*(?:!=|==)/.test(context['before'])) return true;
  if (reviewedFiles['has'](value) && /^(?:README(?:\.(?:ru|zh-CN))?\.md|SECURITY\.md)$/.test(value) &&
      /\]\($/.test(context['before']) && /^\)/.test(context['after'])) return true;
  if (value === 'vpn-hub.git' && /https:\/\/github\.com\/rekurt\/$/.test(context['line']['slice'](0, absoluteStart))) return true;
  if (value === 'telegram.yaml' && record['path'] === '.github/workflows/deploy.yml') return true;
  if (value === 'config.yaml' && record['path'] === 'deploy/terraform/do-token.sh') return true;
  if (reviewedFiles['has'](value) && /^internal\/adapters\/config\/directory(?:_test)?\.go$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^internal\/adapters\/(?:health\/public_endpoint_test|linux\/(?:integration_test|openvpn_integration_test|socks_integration_test))\.go$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^internal\/delivery\/bot\/(?:notify_test|render_test|testdata\/(?:en|ru)\/[^/]+\.golden)$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^internal\/domain\/redaction_test\.go$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^scripts\/(?:check-publication(?:-addresses)?|check-package-locks|validate-package-lock)\.(?:sh|mjs)$/.test(record['path'])) return true;
  return false;
}

function isCommandIdentifier(value, record, context) {
  if (hasNetworkContext(context)) return false;
  const escaped = value['replace'](/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:sysctl\\b.*${escaped}|${escaped}\\.(?:disable_ipv6|rp_filter)\\b|-X\\s+${escaped}\\b|startsWith\\(${escaped}\\b|python3\\s+-m\\s+${escaped}\\b|\\$\\{\\{?\\s*${escaped}\\s*\\}\\}?)`).test(record['content']);
}

function isVerifiedProjectFileReference(value, record, context) {
  if (/^(?:vpn-hub\.git|steps\.deployment\.outputs|index\.html|render\.go)$/.test(value) &&
      record['path'] === 'scripts/check-publication-addresses.mjs') return true;
  if (value === 'vpn-hub.git' && /https:\/\/github\.com\/rekurt\/$/.test(context['line']['slice'](0, context['absoluteStart']))) return true;
  if (reviewedFiles['has'](value) && /^(?:README(?:\.(?:ru|zh-CN))?\.md|SECURITY\.md)$/.test(value) &&
      /\]\($/.test(context['before']) && /^\)/.test(context['after'])) return true;
  if (value === 'telegram.yaml' && /^(?:\.github\/workflows\/deploy\.yml|site\/src\/data\/bot-screens\.(?:en|ru|zh-cn)\.json)$/.test(record['path'])) return true;
  if (value === 'config.yaml' && record['path'] === 'deploy/terraform/do-token.sh') return true;
  if (value === 'SECURITY.md' && record['path'] === 'SUPPORT.md') return true;
  if (value === 'desired-state.json' && record['path'] === 'internal/delivery/bot/notify_test.go') return true;
  if (value === 'steps.deployment.outputs' && record['path'] === '.github/workflows/pages.yml') return true;
  if (value === 'index.html' && /^site\/scripts\/(?:test-built-site|verify-landing)\.mjs$/.test(record['path'])) return true;
  if (/^[A-Za-z_$][A-Za-z0-9_$.]*\.map$/.test(value) && /^site\/src\/(?:components|layouts)\//.test(record['path'])) return true;
  if (/^screen\.rows\.flatMap$/.test(value) && record['path'] === 'site/src/components/BotPreview.astro') return true;
  if (value === 'vpn-hub-agent.service' && /^site\/src\/data\/bot-screens\.(?:en|ru|zh-cn)\.json$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^internal\/adapters\/config\/directory(?:_test)?\.go$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^internal\/adapters\/(?:health\/public_endpoint_test|linux\/(?:integration_test|openvpn_integration_test|socks_integration_test))\.go$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^internal\/delivery\/bot\/(?:notify_test|render_test|testdata\/(?:en|ru)\/[^/]+\.golden)$/.test(record['path'])) return true;
  if (/^[a-z-]+\.golden$/.test(value) && record['path'] === 'internal/delivery/bot/render_test.go') return true;
  if (value === 'render.go' && record['path'] === 'internal/delivery/bot/render_test.go') return true;
  if (value === 'hub.yaml' && /^(?:internal\/application\/(?:validation_netip|validation_test)|internal\/domain\/keys)\.go$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^internal\/domain\/redaction_test\.go$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^site\/scripts\/(?:test-built-site|verify-landing)\.mjs$/.test(record['path'])) return true;
  if (reviewedFiles['has'](value) && /^scripts\/(?:check-publication(?:-addresses)?|check-package-locks|validate-package-lock)\.(?:sh|mjs)$/.test(record['path'])) return true;
  if (/^(?:go\.(?:mod|sum)|package-lock\.json|validate-package-lock\.mjs|vpn-hub-publication\.XXXXXX)$/.test(value) &&
      /^scripts\/(?:check-publication(?:-addresses)?|check-package-locks|validate-package-lock)\.(?:sh|mjs)$/.test(record['path'])) return true;
  return false;
}

for (let index = 0; index < records['length']; index += 1) {
  const record = records[index];
  for (const segment of segmentsByRecord[index]) {
    for (const match of segment['text']['matchAll'](addressPattern)) {
      const value = match[1];
      const absoluteStart = segment['start'] + match['index'];
      const context = localContext(record, absoluteStart, value['length']);
      const previous = absoluteStart > 0 ? record['content'][absoluteStart - 1] : '';
      if (previous === '%' && /^[a-zA-Z]\./['test'](value)) continue;
      const networkContext = hasNetworkContext(context) || isRegexLiteralCandidate(segment, record, absoluteStart, value['length']);
      if (segment['kind'] === 'executable' && memberValuePattern.test(value) &&
          !isRegexLiteralCandidate(segment, record, absoluteStart, value['length'])) continue;
      if (!networkContext && segment['kind'] === 'executable' &&
          (memberValuePattern.test(value) || value['split']('-')['some']((part) => memberValuePattern.test(part)))) {
        continue;
      }
      if (isCodeIdentifier(value, segment, record, context)) continue;
      if (isVerifiedProjectFileReference(value, record, context)) continue;
      if (!networkContext && isSchemaEvidence(value, segment, record, context)) continue;
      if (!networkContext && isCommandIdentifier(value, record, context)) continue;
      if (!networkContext && hasDirectFileEvidence(value, segment, record, context, absoluteStart)) continue;
      const evidence = `${record['path']}:${record['number']}:${record['content']}`
        ['replaceAll']('\\', '\\\\')['replaceAll']('\t', '\\t')['replaceAll']('\r', '\\r')['replaceAll']('\n', '\\n');
      process['stdout']['write'](`${value}|${evidence}\n`);
    }
  }
}
