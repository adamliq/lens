const test = require('node:test');
const assert = require('node:assert/strict');
const {
  detectEncodingIssues,
  detectStackTrace,
  diffPropsConf,
  disambiguateDate,
  buildLookupSkeleton,
  csvEscape
} = require('../app.js');

test('detectEncodingIssues flags a leading byte order mark', () => {
  const result = detectEncodingIssues('﻿{"a":1}');
  assert.equal(result.hasIssues, true);
  assert.ok(result.issues.some(i => /byte order mark/.test(i.message)));
});

test('detectEncodingIssues flags mixed CRLF/LF line endings', () => {
  const result = detectEncodingIssues('line1\r\nline2\nline3');
  assert.equal(result.hasIssues, true);
  assert.ok(result.issues.some(i => /Mixed line endings/.test(i.message)));
});

test('detectEncodingIssues does not flag consistent line endings', () => {
  const crlfOnly = detectEncodingIssues('line1\r\nline2\r\n');
  assert.equal(crlfOnly.issues.some(i => /Mixed line endings/.test(i.message)), false);
});

test('detectEncodingIssues flags the Unicode replacement character', () => {
  const result = detectEncodingIssues('bad�text');
  assert.ok(result.issues.some(i => /replacement character/.test(i.message)));
});

test('detectEncodingIssues flags non-breaking space and other invisible characters', () => {
  const result = detectEncodingIssues('a b');
  assert.ok(result.issues.some(i => /non-breaking space/.test(i.message)));
});

test('detectEncodingIssues flags stray control characters', () => {
  const result = detectEncodingIssues('ab');
  assert.ok(result.issues.some(i => /control character/.test(i.message)));
});

test('detectEncodingIssues reports no issues for clean, empty, or consistent text', () => {
  assert.equal(detectEncodingIssues('clean text').hasIssues, false);
  assert.equal(detectEncodingIssues('').hasIssues, false);
});

test('detectStackTrace identifies a Java exception with Caused by and counts continuations', () => {
  const trace = [
    'java.lang.NullPointerException: Cannot invoke "String.length()" because "s" is null',
    '\tat com.example.Foo.bar(Foo.java:42)',
    '\tat com.example.Foo.main(Foo.java:10)',
    'Caused by: java.lang.RuntimeException: root cause',
    '\tat com.example.Foo.helper(Foo.java:30)',
    '\t... 1 more'
  ].join('\n');
  const result = detectStackTrace(trace);
  assert.equal(result.detected, true);
  assert.equal(result.languageId, 'java');
  assert.equal(result.exceptionType, 'java.lang.NullPointerException');
  assert.equal(result.continuationLineCount, 5);
  assert.doesNotThrow(() => new RegExp(result.lineBreaker));
});

test('detectStackTrace identifies a Python traceback and extracts the trailing exception line', () => {
  const trace = [
    'Traceback (most recent call last):',
    '  File "app.py", line 10, in <module>',
    '    main()',
    '  File "app.py", line 5, in main',
    '    raise ValueError("bad value")',
    'ValueError: bad value'
  ].join('\n');
  const result = detectStackTrace(trace);
  assert.equal(result.detected, true);
  assert.equal(result.languageId, 'python');
  assert.equal(result.exceptionType, 'ValueError');
  assert.equal(result.exceptionMessage, 'bad value');
});

test('detectStackTrace does not misclassify a Python trace as Java', () => {
  const trace = 'Traceback (most recent call last):\n  File "x.py", line 1\nRuntimeError: oops';
  const result = detectStackTrace(trace);
  assert.equal(result.languageId, 'python');
});

test('detectStackTrace identifies a .NET exception and a Go panic', () => {
  const dotnet = 'System.NullReferenceException: Object reference not set to an instance of an object.\n   at MyApp.Program.Main() in Program.cs:line 10';
  assert.equal(detectStackTrace(dotnet).languageId, 'dotnet');
  const go = 'panic: runtime error: index out of range\n\ngoroutine 1 [running]:\nmain.main()\n\t/app/main.go:10 +0x1b';
  assert.equal(detectStackTrace(go).languageId, 'go');
});

test('detectStackTrace returns not-detected for plain text and empty input', () => {
  assert.equal(detectStackTrace('plain text with no exception').detected, false);
  assert.equal(detectStackTrace('').detected, false);
});

test('diffPropsConf classifies added, removed, changed, and unchanged settings', () => {
  const before = 'TIME_FORMAT = %Y-%m-%d\nKV_MODE = auto\nSHOULD_LINEMERGE = false';
  const after = 'TIME_FORMAT = %Y-%m-%dT%H:%M:%S\nLINE_BREAKER = (x)\nSHOULD_LINEMERGE = false';
  const diff = diffPropsConf(before, after);
  assert.deepEqual(diff.added.map(a => a.key), ['LINE_BREAKER']);
  assert.deepEqual(diff.removed.map(r => r.key), ['KV_MODE']);
  assert.deepEqual(diff.changed.map(c => c.key), ['TIME_FORMAT']);
  assert.deepEqual(diff.unchanged.map(u => u.key), ['SHOULD_LINEMERGE']);
  assert.equal(diff.hasDiff, true);
});

test('diffPropsConf reports no diff for identical stanzas', () => {
  const text = 'TIME_FORMAT = %Y-%m-%d';
  const diff = diffPropsConf(text, text);
  assert.equal(diff.hasDiff, false);
});

test('disambiguateDate returns both interpretations for a genuinely ambiguous date', () => {
  const result = disambiguateDate('03/04/2026');
  assert.equal(result.applicable, true);
  assert.equal(result.ambiguous, true);
  assert.equal(result.usInterpretation, '2026-03-04');
  assert.equal(result.euInterpretation, '2026-04-03');
});

test('disambiguateDate recognises an unambiguous EU-only date (day > 12)', () => {
  const result = disambiguateDate('15/04/2026');
  assert.equal(result.ambiguous, false);
  assert.equal(result.usInterpretation, null);
  assert.equal(result.euInterpretation, '2026-04-15');
  assert.match(result.note, /can only be DD\/MM\/YYYY/);
});

test('disambiguateDate recognises an unambiguous US-only date (month > 12)', () => {
  const result = disambiguateDate('04/15/2026');
  assert.equal(result.ambiguous, false);
  assert.equal(result.euInterpretation, null);
  assert.equal(result.usInterpretation, '2026-04-15');
});

test('disambiguateDate preserves a trailing time component and expands a 2-digit year', () => {
  const result = disambiguateDate('03/04/26 14:30:00');
  assert.equal(result.yearAssumed, true);
  assert.equal(result.usInterpretation, '2026-03-04 14:30:00');
});

test('disambiguateDate is not applicable to non-slash-delimited or ISO dates', () => {
  assert.equal(disambiguateDate('2026-07-09').applicable, false);
  assert.equal(disambiguateDate('not a date').applicable, false);
});

test('csvEscape quotes values containing commas, quotes, or newlines', () => {
  assert.equal(csvEscape('plain'), 'plain');
  assert.equal(csvEscape('a,b'), '"a,b"');
  assert.equal(csvEscape('a"b'), '"a""b"');
});

test('buildLookupSkeleton generates a CSV skeleton with distinct values and matching conf lines', () => {
  const result = buildLookupSkeleton('action_code', '0\n1\n2, 0\n');
  assert.equal(result.valid, true);
  assert.equal(result.distinctValueCount, 3);
  assert.equal(result.csv, 'action_code,action_code_normalized\n0,\n1,\n2,\n');
  assert.equal(result.transformsConf, '[action_code_lookup]\nfilename = action_code_lookup.csv');
  assert.equal(result.propsConf, 'LOOKUP-action_code = action_code_lookup action_code OUTPUT action_code_normalized');
});

test('buildLookupSkeleton rejects empty value input', () => {
  const result = buildLookupSkeleton('x', '');
  assert.equal(result.valid, false);
  assert.ok(result.error);
});
