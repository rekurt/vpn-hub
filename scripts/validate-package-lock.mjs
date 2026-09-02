const [displayPath] = process['argv']['slice'](2);
let source = '';

for await (const chunk of process['stdin']) source += chunk;

const errors = [];
let lock;
try {
  lock = JSON['parse'](source);
} catch {
  errors['push'](`${displayPath}: malformed JSON`);
}

function pointerSegment(value) {
  return value['replace'](/~/g, '~0')['replace'](/\//g, '~1');
}

function checkResolved(value, pointer) {
  if (typeof value !== 'string') {
    errors['push'](`${displayPath}:${pointer}: resolved must be a string`);
    return;
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    errors['push'](`${displayPath}:${pointer}: resolved URL is invalid`);
    return;
  }

  if (url['protocol'] !== 'https:') errors['push'](`${displayPath}:${pointer}: resolved URL must use https`);
  if (url['username'] || url['password']) errors['push'](`${displayPath}:${pointer}: resolved URL must not include userinfo`);
  if (url['search'] || url['hash']) errors['push'](`${displayPath}:${pointer}: resolved URL must not include query or fragment`);
  if (url['hostname'] !== 'registry.npmjs.org') {
    errors['push'](`${displayPath}:${pointer}: unapproved resolved host ${url['hostname']}`);
  }
}

function visit(value, pointer = '') {
  if (Array['isArray'](value)) {
    value['forEach']((item, index) => visit(item, `${pointer}/${index}`));
  } else if (value && typeof value === 'object') {
    for (const [key, item] of Object['entries'](value)) {
      const nextPointer = `${pointer}/${pointerSegment(key)}`;
      if (key === 'resolved') checkResolved(item, nextPointer);
      visit(item, nextPointer);
    }
  }
}

if (errors['length'] === 0) visit(lock);

if (errors['length'] > 0) {
  process['stderr']['write'](`package-lock validation failed:\n${errors['map']((error) => `- ${error}`)['join']('\n')}\n`);
  process['exitCode'] = 1;
}
