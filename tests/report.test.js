const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildCimFieldAliases,
  combineFieldExtractionWithCim,
  detectTruncationRisk,
  buildRawEventReport,
  buildAnalysisReportMarkdown
} = require('../app.js');

test('buildCimFieldAliases generates FIELDALIAS lines for matched categories', () => {
  const result = buildCimFieldAliases(['user', 'action', 'timestamp']);
  assert.ok(result.lines.some(l => l === 'FIELDALIAS-user_identity = user AS user_identity'));
  assert.ok(result.matches.length > 0);
});

test('buildCimFieldAliases returns no lines when nothing matches', () => {
  const result = buildCimFieldAliases(['totally_unrelated_field']);
  assert.deepEqual(result.lines, []);
});

test('combineFieldExtractionWithCim appends alias lines to existing props.conf text', () => {
  const base = {title: 't', cls: 'good', propsConf: 'KV_MODE = auto', notes: ['base note']};
  const cim = buildCimFieldAliases(['user']);
  const combined = combineFieldExtractionWithCim(base, cim);
  assert.match(combined.propsConf, /^KV_MODE = auto\nFIELDALIAS-user_identity/);
  assert.equal(combined.notes.length, 2);
});

test('combineFieldExtractionWithCim is a no-op when there are no alias matches', () => {
  const base = {title: 't', cls: 'good', propsConf: 'KV_MODE = auto', notes: []};
  const cim = buildCimFieldAliases(['nope']);
  assert.strictEqual(combineFieldExtractionWithCim(base, cim), base);
});

test('detectTruncationRisk flags unbalanced JSON and trailing commas', () => {
  const result = detectTruncationRisk('{"a":1,"b":');
  assert.equal(result.looksTruncated, true);
  assert.ok(result.reasons.some(r => /curly braces/.test(r)));
  assert.ok(result.reasons.some(r => /trailing comma/.test(r)));
});

test('detectTruncationRisk flags an odd number of quotes', () => {
  const result = detectTruncationRisk('{"a":"unterminated}');
  assert.equal(result.looksTruncated, true);
  assert.ok(result.reasons.some(r => /unescaped double quotes/.test(r)));
});

test('detectTruncationRisk does not flag a well-formed JSON event', () => {
  const result = detectTruncationRisk('{"a":1,"b":2}');
  assert.equal(result.looksTruncated, false);
  assert.deepEqual(result.reasons, []);
});

test('detectTruncationRisk does not misfire on non-JSON formats', () => {
  const result = detectTruncationRisk('user=jsmith action=login');
  assert.equal(result.looksTruncated, false);
});

test('detectTruncationRisk handles empty input without throwing', () => {
  assert.deepEqual(detectTruncationRisk(''), {looksTruncated:false, reasons:[]});
});

test('buildRawEventReport returns null for empty input', () => {
  assert.equal(buildRawEventReport(''), null);
  assert.equal(buildRawEventReport('   '), null);
});

test('buildRawEventReport assembles timestamp, username, IP, and CIM data for a JSON event', () => {
  const raw = '{"timestamp":"2026-07-09T14:30:45.123Z","user":"jsmith","src_ip":"10.1.2.3","action":"login"}';
  const report = buildRawEventReport(raw);
  assert.equal(report.logFormat.detected, 'Structured JSON');
  assert.equal(report.timestamp.formatName, 'ISO 8601 / RFC 3339 - Milliseconds');
  assert.equal(report.username.value, 'jsmith');
  assert.equal(report.ip.value, '10.1.2.3');
  assert.equal(report.ip.category, 'Private (RFC 1918)');
  assert.ok(report.categoryMatches.some(m => m.category === 'Source address'));
  assert.match(report.fieldExtraction.propsConf, /FIELDALIAS-source_address = src_ip AS source_address/);
});

test('buildRawEventReport surfaces a truncation warning for cut-off JSON', () => {
  const report = buildRawEventReport('{"timestamp":"2026-07-09T14:30:45.123Z","user":"jsmith",');
  assert.equal(report.truncation.looksTruncated, true);
});

test('buildAnalysisReportMarkdown renders a well-formed Markdown document', () => {
  const raw = '{"timestamp":"2026-07-09T14:30:45.123Z","user":"jsmith","src_ip":"10.1.2.3","action":"login"}';
  const markdown = buildAnalysisReportMarkdown(buildRawEventReport(raw));
  assert.match(markdown, /^# LENS Analysis Report/);
  assert.match(markdown, /## Log Format/);
  assert.match(markdown, /## Timestamp/);
  assert.match(markdown, /## IP \/ Network Address/);
  assert.match(markdown, /## Suggested props\.conf/);
  assert.match(markdown, /\[custom:json\]/);
});

test('buildAnalysisReportMarkdown returns an empty string for a null report', () => {
  assert.equal(buildAnalysisReportMarkdown(null), '');
});
