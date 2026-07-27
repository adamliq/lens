const test = require('node:test');
const assert = require('node:assert/strict');
const {
  slug,
  suggestSourcetypeName,
  suggestFieldExtraction,
  buildPropsConfBundle,
  checkBatchConsistency,
  runRegexTest,
  buildHighlightedText,
  detectRawFormat
} = require('../app.js');

test('slug normalises arbitrary text into a sourcetype-safe token', () => {
  assert.equal(slug('Palo Alto Networks'), 'palo-alto-networks');
  assert.equal(slug('  --Weird__Name!! '), 'weird-name');
  assert.equal(slug(''), '');
});

test('suggestSourcetypeName builds vendor:product:cef for CEF with vendor/product hints', () => {
  const name = suggestSourcetypeName('Common Event Format (CEF)', {deviceVendor: 'Palo Alto Networks', deviceProduct: 'PAN-OS'});
  assert.equal(name, 'palo-alto-networks:pan-os:cef');
});

test('suggestSourcetypeName falls back to a generic template without vendor hints', () => {
  assert.equal(suggestSourcetypeName('Common Event Format (CEF)', {}), 'vendor:product:cef');
  assert.equal(suggestSourcetypeName('Structured JSON', {}), 'custom:json');
  assert.equal(suggestSourcetypeName('RFC 5424 structured syslog', {}), 'syslog:rfc5424');
  assert.equal(suggestSourcetypeName('', {}), 'custom:unknown');
});

test('suggestFieldExtraction recommends INDEXED_EXTRACTIONS=json for structured JSON', () => {
  const result = suggestFieldExtraction('Structured JSON', '{}', {}, ['user','action']);
  assert.equal(result.cls, 'good');
  assert.match(result.propsConf, /INDEXED_EXTRACTIONS = json/);
});

test('suggestFieldExtraction generates a CEF header EXTRACT with KV_MODE=auto for extensions', () => {
  const result = suggestFieldExtraction('Common Event Format (CEF)', 'CEF:0|Vendor|Product|1.0|100|Login|5|', {}, []);
  assert.match(result.propsConf, /EXTRACT-cef_header/);
  assert.match(result.propsConf, /KV_MODE = auto/);
});

test('suggestFieldExtraction produces a valid EXTRACT regex for key-value logs', () => {
  const result = suggestFieldExtraction('Key-value formatted logs', 'user=jsmith action=login', {}, ['user','action']);
  const match = result.notes.join(' ').match(/EXTRACT-\w+ = .+$/m);
  assert.ok(match, 'expected an EXTRACT example in the notes');
  const regexPart = match[0].split(' = ')[1];
  assert.doesNotThrow(() => new RegExp(regexPart));
});

test('suggestFieldExtraction derives column count for CSV from the first line', () => {
  const result = suggestFieldExtraction('Comma-separated values (CSV)', 'a,b,c,d', {}, []);
  assert.match(result.propsConf, /FIELD_NAMES = field1,field2,field3,field4/);
});

test('suggestFieldExtraction handles unknown formats without throwing', () => {
  const result = suggestFieldExtraction('Unstructured or unknown', 'free text here', {}, []);
  assert.equal(result.cls, 'bad');
});

test('buildPropsConfBundle assembles a single stanza from all suggestion sources', () => {
  const text = buildPropsConfBundle({
    sourcetypeName: 'acme:widget:json',
    timestampProps: {maxLookahead: 30, timeFormat: '%Y-%m-%dT%H:%M:%S.%QZ', timePrefix: 'timestamp='},
    lineBreakProps: {shouldLineMerge: 'false', lineBreaker: '([\\r\\n]+)'},
    fieldExtraction: {propsConf: 'INDEXED_EXTRACTIONS = json\nKV_MODE = none'}
  });
  assert.match(text, /^\[acme:widget:json\]/);
  assert.match(text, /MAX_TIMESTAMP_LOOKAHEAD = 30/);
  assert.match(text, /TIME_FORMAT = %Y-%m-%dT%H:%M:%S\.%QZ/);
  assert.match(text, /SHOULD_LINEMERGE = false/);
  assert.match(text, /INDEXED_EXTRACTIONS = json/);
});

test('buildPropsConfBundle falls back to a placeholder sourcetype when none is given', () => {
  const text = buildPropsConfBundle({});
  assert.match(text, /^\[custom:sourcetype\]/);
});

test('checkBatchConsistency returns null for empty input', () => {
  assert.equal(checkBatchConsistency(''), null);
  assert.equal(checkBatchConsistency('   \n  \n'), null);
});

test('checkBatchConsistency reports a clean verdict for consistent JSON events', () => {
  const raw = [
    '{"timestamp":"2026-07-09T14:30:45.123Z","user":"jsmith","action":"login"}',
    '{"timestamp":"2026-07-09T14:31:02.901Z","user":"jsmith","action":"logout"}'
  ].join('\n');
  const result = checkBatchConsistency(raw);
  assert.equal(result.totalEvents, 2);
  assert.equal(result.dominantFormat, 'Structured JSON');
  assert.equal(result.formatDrift.length, 0);
  assert.equal(result.fieldDrift.length, 0);
  assert.equal(result.verdict, 'good');
});

test('checkBatchConsistency flags an event with a different format and missing fields', () => {
  const raw = [
    '{"timestamp":"2026-07-09T14:30:45.123Z","user":"jsmith","action":"login"}',
    '{"timestamp":"2026-07-09T14:31:02.901Z","user":"jsmith"}',
    'not even close to json'
  ].join('\n');
  const result = checkBatchConsistency(raw);
  assert.equal(result.totalEvents, 3);
  assert.ok(result.formatDrift.some(e => e.index === 3));
  assert.ok(result.fieldDrift.some(e => e.index === 2 && e.missing.includes('action')));
  assert.notEqual(result.verdict, 'good');
});

test('checkBatchConsistency flags timestamps missing timezone context', () => {
  const raw = [
    'timestamp=2026-07-09T14:30:45.123Z user=jsmith',
    'timestamp=20260709143045 user=jsmith'
  ].join('\n');
  const result = checkBatchConsistency(raw);
  assert.ok(result.tzDrift.some(e => e.index === 2));
});

test('runRegexTest reports invalid patterns without throwing', () => {
  const result = runRegexTest('(unclosed', '', 'abc');
  assert.equal(result.valid, false);
  assert.ok(result.error);
});

test('runRegexTest collects matches, capture groups, and named groups', () => {
  const result = runRegexTest('user=(?<user>\\w+)', '', 'user=jsmith action=login user=admin');
  assert.equal(result.valid, true);
  assert.equal(result.matches.length, 2);
  assert.equal(result.matches[0].namedGroups.user, 'jsmith');
  assert.equal(result.matches[1].namedGroups.user, 'admin');
});

test('runRegexTest does not hang on zero-length matches', () => {
  const result = runRegexTest('x*', '', 'aaa');
  assert.equal(result.valid, true);
  assert.ok(result.matches.length > 0);
  assert.ok(result.matches.length < 500);
});

test('buildHighlightedText wraps matches in <mark> and escapes surrounding text', () => {
  const result = runRegexTest('b', '', 'a<b>c');
  const html = buildHighlightedText('a<b>c', result.matches);
  assert.equal(html, 'a&lt;<mark>b</mark>&gt;c');
});

test('buildHighlightedText returns escaped text unchanged when there are no matches', () => {
  assert.equal(buildHighlightedText('<script>', []), '&lt;script&gt;');
});
