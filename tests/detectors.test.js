const test = require('node:test');
const assert = require('node:assert/strict');
const {
  detectDateTimeFormat,
  detectUsernameFormat,
  detectLineBreakFormat,
  detectRawFormat,
  reverseLookupTimeFormat,
  findTimestampCandidates,
  findUsernameCandidates,
  parseKeyValues,
  flattenObject,
  escapeLineBreakerLiteral,
  TIME_FORMATS,
  USERNAME_FORMATS
} = require('../app.js');

test('reference tables are non-empty and well-formed', () => {
  assert.ok(TIME_FORMATS.length > 0);
  assert.ok(USERNAME_FORMATS.length > 0);
  for (const row of USERNAME_FORMATS) {
    assert.doesNotThrow(() => new RegExp(row.regex), `bad regex for ${row.name}`);
  }
});

test('detectDateTimeFormat recognises ISO 8601 milliseconds', () => {
  const result = detectDateTimeFormat('2026-07-09T14:30:45.123Z');
  assert.equal(result.formatName, 'ISO 8601 / RFC 3339 - Milliseconds');
});

test('detectDateTimeFormat recognises epoch seconds', () => {
  const result = detectDateTimeFormat('1783868445');
  assert.notEqual(result.formatName, 'Unknown or unsupported timestamp format');
});

test('detectDateTimeFormat falls back to unknown for garbage input', () => {
  const result = detectDateTimeFormat('not a timestamp at all');
  assert.equal(result.formatName, 'Unknown or unsupported timestamp format');
});

test('detectUsernameFormat recognises UPN / email-style principals', () => {
  const result = detectUsernameFormat('jsmith@company.com');
  assert.equal(result.formatName, 'User Principal Name (UPN)');
});

test('detectUsernameFormat recognises down-level logon names', () => {
  const result = detectUsernameFormat('COMPANY\\jsmith');
  assert.match(result.formatName, /down-level/i);
});

test('detectRawFormat classifies a structured JSON event and extracts fields', () => {
  const raw = '{"timestamp":"2026-07-09T14:30:45.123Z","user":"jsmith","action":"login","result":"success"}';
  const result = detectRawFormat(raw);
  assert.equal(result.detected, 'Structured JSON');
  assert.equal(result.parseStatus, 'ok');
  assert.deepEqual(result.extracted.sort(), ['action', 'result', 'timestamp', 'user']);
  assert.equal(result.values.user, 'jsmith');
});

test('detectRawFormat handles key=value pairs', () => {
  const raw = 'timestamp=2026-07-09T14:30:45.123Z user=jsmith action=login result=success';
  const result = detectRawFormat(raw);
  assert.ok(result.extracted.includes('user'));
  assert.equal(result.values.action, 'login');
});

test('detectLineBreakFormat detects timestamp-anchored multiline events', () => {
  const raw = [
    '2026-07-09T14:30:45.123Z user=jsmith action=login',
    '    at auth.validate(auth.js:42)',
    '2026-07-09T14:31:02.901Z user=jsmith action=logout'
  ].join('\n');
  const result = detectLineBreakFormat(raw);
  assert.equal(result.shouldLineMerge, 'false');
  assert.equal(result.eventStartLines, 2);
  assert.equal(result.continuationLines, 1);
  assert.ok(result.lineBreaker.length > 0);
});

test('reverseLookupTimeFormat matches a known Splunk TIME_FORMAT exactly', () => {
  const result = reverseLookupTimeFormat('%Y-%m-%dT%H:%M:%S.%QZ');
  assert.ok(result.matches.exact.length > 0);
  assert.equal(result.matches.exact[0][0], 'ISO 8601 / RFC 3339 - Milliseconds');
  assert.equal(result.example, '2026-07-09T14:30:45.123Z');
});

test('findTimestampCandidates locates embedded timestamps in raw text', () => {
  const raw = 'level=error ts=2026-07-09T14:30:45.123+10:00 user=jsmith';
  const candidates = findTimestampCandidates(raw, {});
  assert.ok(candidates.length > 0);
  assert.ok(candidates.some(c => c.value.includes('2026-07-09T14:30:45.123')));
});

test('findUsernameCandidates locates embedded usernames in raw text', () => {
  const raw = 'user=jsmith@company.com action=login';
  const candidates = findUsernameCandidates(raw, {});
  assert.ok(candidates.some(c => c.value.includes('jsmith@company.com')));
  assert.ok(candidates.some(c => c.detection.formatName === 'User Principal Name (UPN)'));
});

test('parseKeyValues extracts key=value pairs', () => {
  const values = parseKeyValues('level=error user=jsmith action=login');
  assert.equal(values.level, 'error');
  assert.equal(values.user, 'jsmith');
  assert.equal(values.action, 'login');
});

test('flattenObject flattens nested JSON keys with dot notation', () => {
  const flat = flattenObject({ user: { name: 'jsmith' }, action: 'login' });
  assert.equal(flat['user.name'], 'jsmith');
  assert.equal(flat.action, 'login');
});

test('escapeLineBreakerLiteral escapes regex metacharacters and collapses whitespace', () => {
  const escaped = escapeLineBreakerLiteral('a.b  c');
  assert.doesNotThrow(() => new RegExp(escaped));
  assert.ok(new RegExp(escaped).test('a.b  c'));
  assert.ok(!new RegExp(escaped).test('aXb c'));
});
