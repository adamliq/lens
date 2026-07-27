const test = require('node:test');
const assert = require('node:assert/strict');
const {
  timeFormatToRegex,
  validateTimeFormatAgainstSample,
  parsePropsConfText,
  validatePropsConf,
  buildSplSearches,
  buildInputsConfStanza,
  estimateEventBytes,
  buildHecPayload,
  buildHecCurlCommand,
  CIM_DATA_MODELS,
  findCimFieldMatches,
  checkCimCompliance,
  estimateIndexVolume
} = require('../app.js');

test('timeFormatToRegex converts known strptime tokens and flags unknown ones', () => {
  const known = timeFormatToRegex('%Y-%m-%dT%H:%M:%S.%QZ');
  assert.equal(known.unsupported.length, 0);
  assert.doesNotThrow(() => new RegExp(known.pattern));
  assert.ok(new RegExp('^' + known.pattern + '$').test('2026-07-09T14:30:45.123Z'));

  const unknown = timeFormatToRegex('%Y-%X-%d');
  assert.deepEqual(unknown.unsupported, ['%X']);
});

test('validateTimeFormatAgainstSample matches a prefixed timestamp and checks lookahead', () => {
  const result = validateTimeFormatAgainstSample('timestamp=2026-07-09T14:30:45.123Z level=info', '%Y-%m-%dT%H:%M:%S.%QZ', 'timestamp=', 40);
  assert.equal(result.valid, true);
  assert.equal(result.matchedValue, '2026-07-09T14:30:45.123Z');
  assert.equal(result.withinLookahead, true);
});

test('validateTimeFormatAgainstSample flags a lookahead that is too short', () => {
  const result = validateTimeFormatAgainstSample('timestamp=2026-07-09T14:30:45.123Z level=info', '%Y-%m-%dT%H:%M:%S.%QZ', 'timestamp=', 5);
  assert.equal(result.valid, true);
  assert.equal(result.withinLookahead, false);
  assert.match(result.warning, /MAX_TIMESTAMP_LOOKAHEAD/);
});

test('validateTimeFormatAgainstSample reports no match when the pattern is absent', () => {
  const result = validateTimeFormatAgainstSample('no timestamp here', '%Y-%m-%dT%H:%M:%S.%QZ', '', null);
  assert.equal(result.valid, false);
  assert.ok(result.error);
});

test('parsePropsConfText parses a stanza header and key = value settings, ignoring comments', () => {
  const {stanza, settings} = parsePropsConfText('[my:sourcetype]\n# a comment\nTIME_FORMAT = %Y-%m-%d\nKV_MODE = auto\n');
  assert.equal(stanza, 'my:sourcetype');
  assert.equal(settings.TIME_FORMAT, '%Y-%m-%d');
  assert.equal(settings.KV_MODE, 'auto');
});

test('validatePropsConf validates TIME_FORMAT, LINE_BREAKER, and EXTRACT together', () => {
  const props = [
    'TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%QZ',
    'TIME_PREFIX = timestamp=',
    'LINE_BREAKER = ([\\r\\n]+)(?=timestamp=)',
    'EXTRACT-user = user=(?<user>\\S+)',
    'KV_MODE = auto'
  ].join('\n');
  const sample = [
    'timestamp=2026-07-09T14:30:45.123Z user=jsmith action=login',
    'timestamp=2026-07-09T14:31:02.901Z user=jsmith action=logout'
  ].join('\n');
  const result = validatePropsConf(props, sample);
  const byKey = Object.fromEntries(result.checks.map(c => [c.key, c]));
  assert.equal(byKey['TIME_FORMAT'].cls, 'good');
  assert.equal(byKey['LINE_BREAKER'].cls, 'good');
  assert.match(byKey['LINE_BREAKER'].message, /2 event/);
  assert.equal(byKey['EXTRACT-user'].cls, 'good');
  assert.match(byKey['EXTRACT-user'].message, /user=jsmith/);
  assert.equal(byKey['KV_MODE'].cls, 'good');
});

test('validatePropsConf flags an invalid LINE_BREAKER regex and an unrecognised KV_MODE', () => {
  const props = 'LINE_BREAKER = (unterminated\nKV_MODE = bogus';
  const result = validatePropsConf(props, 'sample text');
  const byKey = Object.fromEntries(result.checks.map(c => [c.key, c]));
  assert.equal(byKey['LINE_BREAKER'].cls, 'bad');
  assert.equal(byKey['KV_MODE'].cls, 'bad');
});

test('validatePropsConf flags a FIELDALIAS with bad syntax and accepts a valid one', () => {
  const bad = validatePropsConf('FIELDALIAS-x = not_valid_syntax', 'sample');
  assert.equal(bad.checks[0].cls, 'bad');
  const good = validatePropsConf('FIELDALIAS-x = src_ip AS src', 'sample');
  assert.equal(good.checks[0].cls, 'good');
});

test('validatePropsConf marks unrecognised settings as informational, not errors', () => {
  const result = validatePropsConf('SOME_UNKNOWN_SETTING = value', 'sample');
  assert.equal(result.checks[0].cls, 'info');
});

test('validatePropsConf returns an error when no settings are found', () => {
  const result = validatePropsConf('not a props.conf stanza at all', 'sample');
  assert.ok(result.error);
  assert.equal(result.checks.length, 0);
});

test('buildSplSearches produces ingestion, field-table, and timestamp-lag searches', () => {
  const searches = buildSplSearches({sourcetypeName:'acme:widget:json', indexName:'main', fields:['user','action']});
  assert.match(searches.ingestionCheck, /index=main sourcetype="acme:widget:json"/);
  assert.match(searches.fieldTable, /table _time, user, action/);
  assert.match(searches.timestampSanity, /index_lag_sec = _indextime - _time/);
});

test('buildSplSearches falls back to placeholders when index/sourcetype are omitted', () => {
  const searches = buildSplSearches({});
  assert.match(searches.ingestionCheck, /index=<index>/);
  assert.match(searches.ingestionCheck, /sourcetype="custom:sourcetype"/);
});

test('buildInputsConfStanza generates a monitor stanza with sensible defaults', () => {
  const stanza = buildInputsConfStanza({sourcetypeName:'acme:widget:json', indexName:'main', monitorPath:'/var/log/widget/*.log'});
  assert.match(stanza, /^\[monitor:\/\/\/var\/log\/widget\/\*\.log\]/);
  assert.match(stanza, /index = main/);
  assert.match(stanza, /sourcetype = acme:widget:json/);
});

test('estimateEventBytes counts UTF-8 bytes, not JS string length', () => {
  assert.equal(estimateEventBytes('abc'), 3);
  assert.equal(estimateEventBytes(''), 0);
});

test('buildHecPayload nests parsed JSON for structured JSON events and includes optional fields', () => {
  const payload = JSON.parse(buildHecPayload({raw:'{"user":"jsmith"}', detectedFormat:'Structured JSON', sourcetypeName:'acme:json', indexName:'main', timestampEpochSeconds:1783607445}));
  assert.deepEqual(payload.event, {user:'jsmith'});
  assert.equal(payload.sourcetype, 'acme:json');
  assert.equal(payload.index, 'main');
  assert.equal(payload.time, 1783607445);
});

test('buildHecPayload keeps the raw string for non-JSON formats and omits invalid time', () => {
  const payload = JSON.parse(buildHecPayload({raw:'user=jsmith action=login', detectedFormat:'Key-value formatted logs', sourcetypeName:'acme:kv'}));
  assert.equal(payload.event, 'user=jsmith action=login');
  assert.equal('time' in payload, false);
  assert.equal('index' in payload, false);
});

test('buildHecCurlCommand embeds the URL, token, and JSON payload', () => {
  const cmd = buildHecCurlCommand('{"event":"x"}', {hecUrl:'https://splunk:8088/services/collector/event', hecToken:'abc-123'});
  assert.match(cmd, /https:\/\/splunk:8088\/services\/collector\/event/);
  assert.match(cmd, /Authorization: Splunk abc-123/);
  assert.match(cmd, /-d '\{"event":"x"\}'/);
});

test('CIM_DATA_MODELS is non-empty and every model has fields', () => {
  assert.ok(CIM_DATA_MODELS.length > 0);
  CIM_DATA_MODELS.forEach(m => assert.ok(m.fields.length > 0, `${m.id} has no fields`));
});

test('findCimFieldMatches matches common aliases, not just exact names', () => {
  assert.deepEqual(findCimFieldMatches(['src_ip','user'], 'src'), ['src_ip']);
  assert.deepEqual(findCimFieldMatches(['totally_unrelated'], 'dest'), []);
});

test('checkCimCompliance computes coverage and lists present/missing fields', () => {
  const result = checkCimCompliance('authentication', ['user','action','dest_ip','src_ip']);
  assert.equal(result.model.id, 'authentication');
  assert.ok(result.present.some(p => p.field === 'user'));
  assert.ok(result.missing.includes('app'));
  assert.ok(result.coverage > 0 && result.coverage <= 100);
});

test('checkCimCompliance returns null for an unknown model id', () => {
  assert.equal(checkCimCompliance('does_not_exist', []), null);
});

test('estimateIndexVolume computes daily/monthly/annual raw volume from EPS', () => {
  const result = estimateIndexVolume({avgEventBytes: 500, eventsPerSecond: 100, retentionDays: 90});
  assert.equal(result.valid, true);
  assert.equal(result.dailyEvents, 8640000);
  assert.ok(Math.abs(result.dailyRawGB - 4.023) < 0.01);
  assert.ok(result.estimatedRetainedOnDiskGB > 0);
});

test('estimateIndexVolume accepts events per day directly and rejects invalid input', () => {
  const result = estimateIndexVolume({avgEventBytes: 1000, eventsPerDay: 1000000});
  assert.equal(result.valid, true);
  assert.equal(result.dailyEvents, 1000000);
  assert.equal(estimateIndexVolume({avgEventBytes: 0, eventsPerDay: 1000}).valid, false);
  assert.equal(estimateIndexVolume({avgEventBytes: 500}).valid, false);
});
