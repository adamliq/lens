const test = require('node:test');
const assert = require('node:assert/strict');
const { epochToDate, dateToEpoch } = require('../app.js');

test('epochToDate auto-detects seconds precision', () => {
  const result = epochToDate('1783607445');
  assert.equal(result.valid, true);
  assert.equal(result.unit, 'seconds');
  assert.equal(result.iso, '2026-07-09T14:30:45.000Z');
  assert.equal(result.dayOfWeek, 'Thursday');
  assert.equal(result.splunkTimeFormat, '%s');
});

test('epochToDate auto-detects milliseconds precision', () => {
  const result = epochToDate('1783607445123');
  assert.equal(result.unit, 'milliseconds');
  assert.equal(result.iso, '2026-07-09T14:30:45.123Z');
  assert.equal(result.splunkTimeFormat, '%s%Q');
});

test('epochToDate auto-detects microseconds and nanoseconds precision', () => {
  assert.equal(epochToDate('1783607445123456').unit, 'microseconds');
  assert.equal(epochToDate('1783607445123456789').unit, 'nanoseconds');
});

test('epochToDate honours an explicit unit override', () => {
  const result = epochToDate('1783607445', 'milliseconds');
  assert.equal(result.unit, 'milliseconds');
  assert.equal(result.iso, '1970-01-21T15:26:47.445Z');
});

test('epochToDate treats a fractional value as seconds', () => {
  const result = epochToDate('1783607445.5');
  assert.equal(result.unit, 'seconds');
  assert.equal(result.iso, '2026-07-09T14:30:45.500Z');
});

test('epochToDate rejects non-numeric and empty input', () => {
  assert.equal(epochToDate('not a number').valid, false);
  assert.equal(epochToDate('').valid, false);
  assert.equal(epochToDate('12ab34').valid, false);
});

test('epochToDate rejects an out-of-range value without throwing', () => {
  const result = epochToDate('9'.repeat(30));
  assert.equal(result.valid, false);
  assert.ok(result.error);
});

test('dateToEpoch parses an explicit UTC ISO timestamp deterministically', () => {
  const result = dateToEpoch('2026-07-09T14:30:45.123Z');
  assert.equal(result.valid, true);
  assert.equal(result.unixSeconds, 1783607445);
  assert.equal(result.unixMillis, 1783607445123);
  assert.equal(result.unixMicros, 1783607445123000);
  assert.equal(result.unixNanos, 1783607445123000000);
  assert.equal(result.dayOfWeek, 'Thursday');
  assert.match(result.timezoneNote, /Explicit timezone/);
});

test('dateToEpoch parses an explicit numeric-offset timestamp deterministically', () => {
  const result = dateToEpoch('2026-07-09T14:30:45+00:00');
  assert.equal(result.valid, true);
  assert.equal(result.unixSeconds, 1783607445);
});

test('dateToEpoch treats an ISO-like value without a timezone as UTC', () => {
  const result = dateToEpoch('2026-07-09 14:30:45');
  assert.equal(result.valid, true);
  assert.equal(result.iso, '2026-07-09T14:30:45.000Z');
  assert.match(result.timezoneNote, /interpreted as UTC/);
});

test('dateToEpoch round-trips with epochToDate', () => {
  const toEpoch = dateToEpoch('2026-07-09T14:30:45Z');
  const back = epochToDate(String(toEpoch.unixSeconds));
  assert.equal(back.iso, '2026-07-09T14:30:45.000Z');
});

test('dateToEpoch rejects unparseable input without throwing', () => {
  const result = dateToEpoch('definitely not a date');
  assert.equal(result.valid, false);
  assert.ok(result.error);
});

test('dateToEpoch rejects empty input', () => {
  assert.equal(dateToEpoch('').valid, false);
  assert.equal(dateToEpoch('   ').valid, false);
});
