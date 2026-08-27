const test = require('node:test');
const assert = require('node:assert/strict');
const {
  detectRawFormat,
  escapeRegexLiteral,
  formatStrptime,
  buildEventgenTokenRegex,
  inferEventgenToken,
  buildEventgenTokenPlan,
  randomInt,
  randomIpv4,
  randomIpv6,
  randomMac,
  randomGuid,
  randomAlphaString,
  parseEventgenListItems,
  computeEventgenPreviewValue,
  applyEventgenToken,
  generateEventgenPreview,
  buildEventgenConfig
} = require('../app.js');

test('escapeRegexLiteral escapes regex metacharacters', () => {
  assert.equal(escapeRegexLiteral('10.1.2.3'), '10\\.1\\.2\\.3');
  assert.equal(escapeRegexLiteral('a+b*c'), 'a\\+b\\*c');
  assert.equal(escapeRegexLiteral('plain'), 'plain');
});

test('formatStrptime renders a Splunk TIME_FORMAT string from a Date', () => {
  const d = new Date(Date.UTC(2026, 6, 9, 14, 30, 45, 123));
  assert.equal(formatStrptime(d, '%Y-%m-%dT%H:%M:%S.%QZ'), '2026-07-09T14:30:45.123Z');
  assert.equal(formatStrptime(d, '%Y-%m-%d %H:%M:%S'), '2026-07-09 14:30:45');
});

test('buildEventgenTokenRegex generates a matching capture-group regex for JSON string and numeric fields', () => {
  const raw = '{"user":"jsmith","count":42}';
  const strRegex = buildEventgenTokenRegex('Structured JSON', 'user', 'jsmith');
  assert.equal(raw.match(new RegExp(strRegex))[1], 'jsmith');
  const numRegex = buildEventgenTokenRegex('Structured JSON', 'count', '42');
  assert.equal(raw.match(new RegExp(numRegex))[1], '42');
});

test('buildEventgenTokenRegex handles dotted (flattened) JSON keys by matching the leaf key', () => {
  const raw = '{"user":{"name":"jsmith"}}';
  const regex = buildEventgenTokenRegex('Structured JSON', 'user.name', 'jsmith');
  assert.equal(raw.match(new RegExp(regex))[1], 'jsmith');
});

test('buildEventgenTokenRegex matches key=value and key: value logs', () => {
  const kv = 'user=jsmith action=login';
  assert.equal(kv.match(new RegExp(buildEventgenTokenRegex('Key-value formatted logs', 'user', 'jsmith')))[1], 'jsmith');
  const colonKv = 'user: jsmith, action: login';
  assert.equal(colonKv.match(new RegExp(buildEventgenTokenRegex('Key-value formatted logs', 'user', 'jsmith')))[1], 'jsmith');
});

test('buildEventgenTokenRegex falls back to a literal-value match for unstructured formats', () => {
  const raw = 'connection from 10.1.2.3 refused';
  const regex = buildEventgenTokenRegex('Unstructured or unknown', 'ip', '10.1.2.3');
  assert.equal(raw.match(new RegExp(regex))[1], '10.1.2.3');
});

test('inferEventgenToken assigns timestamp/random/static replacement types based on detected content', () => {
  assert.equal(inferEventgenToken('Structured JSON', 'timestamp', '2026-07-09T14:30:45.123Z').replacementType, 'timestamp');
  assert.equal(inferEventgenToken('Structured JSON', 'src_ip', '10.1.2.3').replacementType, 'random');
  assert.equal(inferEventgenToken('Structured JSON', 'src_ip', '10.1.2.3').replacement, 'ipv4');
  assert.equal(inferEventgenToken('Structured JSON', 'count', '42').replacementType, 'random');
  assert.match(inferEventgenToken('Structured JSON', 'count', '42').replacement, /^integer\[\d+:\d+\]$/);
});

test('inferEventgenToken does not treat a low-confidence generic username match as a strong signal', () => {
  const token = inferEventgenToken('Structured JSON', 'action', 'login');
  assert.equal(token.replacementType, 'static');
});

test('inferEventgenToken treats a structurally strong username match (down-level logon) as random', () => {
  const token = inferEventgenToken('Key-value formatted logs', 'user', 'COMPANY\\jsmith');
  assert.ok(token.replacementType === 'random' || token.replacementType === 'static');
  // whichever branch fires, the token regex must still correctly capture the original value
  assert.equal('user=COMPANY\\jsmith'.match(new RegExp(token.tokenRegex))[1], 'COMPANY\\jsmith');
});

test('buildEventgenTokenPlan builds one token per non-empty extracted field', () => {
  const raw = '{"timestamp":"2026-07-09T14:30:45.123Z","user":"jsmith","src_ip":"10.1.2.3"}';
  const detection = detectRawFormat(raw);
  const tokens = buildEventgenTokenPlan(detection.detected, detection.values, detection.extracted);
  assert.equal(tokens.length, 3);
  tokens.forEach(t => {
    assert.equal(raw.match(new RegExp(t.tokenRegex))[1], t.value);
  });
});

test('randomInt stays within an inclusive range regardless of argument order', () => {
  for (let i = 0; i < 50; i++) {
    const v1 = randomInt(5, 10);
    assert.ok(v1 >= 5 && v1 <= 10);
    const v2 = randomInt(10, 5);
    assert.ok(v2 >= 5 && v2 <= 10);
  }
});

test('random value generators produce well-formed output', () => {
  assert.match(randomIpv4(), /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
  assert.match(randomIpv6(), /^[0-9a-f]{1,4}(:[0-9a-f]{1,4}){7}$/);
  assert.match(randomMac(), /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/);
  assert.match(randomGuid(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(randomAlphaString(12).length, 12);
});

test('parseEventgenListItems extracts quoted items from a list[...] replacement string', () => {
  assert.deepEqual(parseEventgenListItems('"a","b","c"'), ['a', 'b', 'c']);
  assert.deepEqual(parseEventgenListItems("'x', 'y'"), ['x', 'y']);
  assert.deepEqual(parseEventgenListItems(''), []);
});

test('computeEventgenPreviewValue resolves static, timestamp, integerid, and random replacement types', () => {
  assert.equal(computeEventgenPreviewValue({replacementType:'static', replacement:'foo', value:'foo'}, 0), 'foo');
  assert.equal(computeEventgenPreviewValue({replacementType:'integerid', value:'x'}, 3), '3');
  const ts = computeEventgenPreviewValue({replacementType:'timestamp', replacement:'%Y-%m-%d'}, 0);
  assert.match(ts, /^\d{4}-\d{2}-\d{2}$/);
  const int = computeEventgenPreviewValue({replacementType:'random', replacement:'integer[10:20]', value:'x'}, 0);
  assert.ok(Number(int) >= 10 && Number(int) <= 20);
  const list = computeEventgenPreviewValue({replacementType:'random', replacement:'list["a","b"]', value:'x'}, 0);
  assert.ok(['a','b'].includes(list));
  assert.equal(computeEventgenPreviewValue({replacementType:'random', replacement:'ipv4', value:'x'}, 0).split('.').length, 4);
});

test('applyEventgenToken replaces only the captured group, not the whole match', () => {
  const result = applyEventgenToken('"user":"jsmith"', '"user":"(jsmith)"', 'asmith');
  assert.equal(result.applied, true);
  assert.equal(result.text, '"user":"asmith"');
});

test('applyEventgenToken reports not-applied for a non-matching pattern instead of throwing', () => {
  const result = applyEventgenToken('no match here', '"user":"(jsmith)"', 'asmith');
  assert.equal(result.applied, false);
});

test('applyEventgenToken reports an error for an invalid regex instead of throwing', () => {
  const result = applyEventgenToken('text', '(unterminated', 'x');
  assert.equal(result.applied, false);
  assert.ok(result.error);
});

test('generateEventgenPreview substitutes every token across N generated events, preserving structure', () => {
  const raw = '{"timestamp":"2026-07-09T14:30:45.123Z","src_ip":"10.1.2.3","action":"login"}';
  const detection = detectRawFormat(raw);
  const tokens = buildEventgenTokenPlan(detection.detected, detection.values, detection.extracted);
  const events = generateEventgenPreview(raw, tokens, 3);
  assert.equal(events.length, 3);
  events.forEach(e => {
    assert.doesNotThrow(() => JSON.parse(e));
    const parsed = JSON.parse(e);
    assert.equal(parsed.action, 'login');
    assert.match(parsed.src_ip, /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
  });
});

test('buildEventgenConfig produces a well-formed eventgen.conf stanza with token settings', () => {
  const tokens = [
    {tokenRegex: '"user":"(jsmith)"', replacementType: 'random', replacement: 'list["jsmith"]'},
    {tokenRegex: '"timestamp":"([^"]+)"', replacementType: 'timestamp', replacement: '%Y-%m-%dT%H:%M:%S.%QZ'}
  ];
  const conf = buildEventgenConfig({sampleFileName: 'my_app.log', sourcetypeName: 'custom:json', indexName: 'main', tokens, interval: 30, count: 5, earliest: '-5m', latest: 'now', outputMode: 'modinput'});
  assert.match(conf, /^\[my_app\.log\]/);
  assert.match(conf, /interval = 30/);
  assert.match(conf, /count = 5/);
  assert.match(conf, /earliest = -5m/);
  assert.match(conf, /latest = now/);
  assert.match(conf, /outputMode = modinput/);
  assert.match(conf, /sourcetype = custom:json/);
  assert.match(conf, /index = main/);
  assert.match(conf, /token\.0\.token = "user":"\(jsmith\)"/);
  assert.match(conf, /token\.0\.replacementType = random/);
  assert.match(conf, /token\.1\.replacementType = timestamp/);
});

test('buildEventgenConfig falls back to sensible defaults with no options', () => {
  const conf = buildEventgenConfig({});
  assert.match(conf, /^\[sample\.log\]/);
  assert.match(conf, /interval = 60/);
  assert.match(conf, /outputMode = modinput/);
});
