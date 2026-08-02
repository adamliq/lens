const test = require('node:test');
const assert = require('node:assert/strict');
const {
  detectDateTimeFormat,
  detectUsernameFormat,
  detectLineBreakFormat,
  detectRawFormat,
  extractWindowsEventXmlFields,
  extractGenericXmlFields,
  parseColonKeyValues,
  classifyKeyValueStyle,
  suggestFieldExtraction,
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

test('detectRawFormat classifies a Windows Event XML sample and extracts System/EventData fields', () => {
  const raw = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Channel>Security</Channel><Computer>DC01.contoso.com</Computer><Security UserID="S-1-5-18"/><TimeCreated SystemTime="2026-07-09T14:30:45.123456Z"/></System><EventData><Data Name="TargetUserName">jsmith</Data><Data Name="LogonType">3</Data></EventData></Event>';
  const result = detectRawFormat(raw);
  assert.equal(result.detected, 'Windows Event XML');
  assert.equal(result.values.EventID, '4624');
  assert.equal(result.values['Provider.Name'], 'Microsoft-Windows-Security-Auditing');
  assert.equal(result.values.TargetUserName, 'jsmith');
  assert.ok(result.extracted.includes('TargetUserName'));
});

test('detectRawFormat recognises Windows Event XML without the namespace via EventID + Provider tags', () => {
  const raw = '<Event><System><Provider Name="App"/><EventID>1000</EventID></System></Event>';
  assert.equal(detectRawFormat(raw).detected, 'Windows Event XML');
});

test('detectRawFormat classifies generic XML and extracts leaf text and attribute fields', () => {
  const raw = '<?xml version="1.0"?><log><timestamp>2026-07-09T14:30:45Z</timestamp><user id="42">jsmith</user><action>login</action></log>';
  const result = detectRawFormat(raw);
  assert.equal(result.detected, 'XML log');
  assert.equal(result.values.timestamp, '2026-07-09T14:30:45Z');
  assert.equal(result.values.user, 'jsmith');
  assert.equal(result.values['@id'], '42');
});

test('detectRawFormat does not misclassify CEF or KV logs that merely look XML-adjacent', () => {
  assert.equal(detectRawFormat('CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4').detected, 'Common Event Format (CEF)');
  assert.equal(detectRawFormat('user=jsmith action=login').detected, 'Key-value formatted logs');
});

test('extractWindowsEventXmlFields pulls System and EventData fields independently of detection', () => {
  const raw = '<Event><System><EventID>4625</EventID><Provider Name="Sec"/></System><EventData><Data Name="SubStatus">0xC0000064</Data></EventData></Event>';
  const values = extractWindowsEventXmlFields(raw);
  assert.equal(values.EventID, '4625');
  assert.equal(values['Provider.Name'], 'Sec');
  assert.equal(values.SubStatus, '0xC0000064');
});

test('extractGenericXmlFields ignores xmlns attributes and empty leaf elements', () => {
  const raw = '<root xmlns="urn:test"><empty></empty><a b="c">text</a></root>';
  const values = extractGenericXmlFields(raw);
  assert.equal('xmlns' in values, false);
  assert.equal('empty' in values, false);
  assert.equal(values.a, 'text');
  assert.equal(values['@b'], 'c');
});

test('detectRawFormat handles key=value pairs', () => {
  const raw = 'timestamp=2026-07-09T14:30:45.123Z user=jsmith action=login result=success';
  const result = detectRawFormat(raw);
  assert.ok(result.extracted.includes('user'));
  assert.equal(result.values.action, 'login');
});

test('classifyKeyValueStyle identifies space-separated logfmt-style key=value pairs', () => {
  const result = classifyKeyValueStyle('user=jsmith action=login result=success');
  assert.equal(result.applicable, true);
  assert.equal(result.separator, '=');
  assert.equal(result.delimiterLabel, 'Space-separated (logfmt-style)');
  assert.equal(result.pairCount, 3);
});

test('classifyKeyValueStyle identifies comma-separated colon-style key: value pairs', () => {
  const result = classifyKeyValueStyle('level: info, user: jsmith, action: login');
  assert.equal(result.applicable, true);
  assert.equal(result.separator, ':');
  assert.equal(result.delimiterLabel, 'Comma-separated');
  assert.equal(result.styleName, 'Comma-separated key: value');
});

test('classifyKeyValueStyle identifies semicolon- and comma-separated key=value pairs', () => {
  assert.equal(classifyKeyValueStyle('user=jsmith; action=login; result=success').delimiterLabel, 'Semicolon-separated');
  assert.equal(classifyKeyValueStyle('user=jsmith, action=login, result=success').delimiterLabel, 'Comma-separated');
});

test('classifyKeyValueStyle detects quoted values and returns not-applicable for plain text', () => {
  assert.equal(classifyKeyValueStyle('user="John Smith" action=login').hasQuotedValues, true);
  assert.equal(classifyKeyValueStyle('just some plain text').applicable, false);
});

test('parseColonKeyValues extracts colon-separated key: value pairs', () => {
  const values = parseColonKeyValues('level: info, user: jsmith, action: login');
  assert.equal(values.level, 'info');
  assert.equal(values.user, 'jsmith');
  assert.equal(values.action, 'login');
});

test('detectRawFormat classifies colon-separated KV logs (previously misclassified as CSV) and extracts fields', () => {
  const raw = 'level: info, user: jsmith, action: login, result: success';
  const result = detectRawFormat(raw);
  assert.equal(result.detected, 'Key-value formatted logs');
  assert.equal(result.values.user, 'jsmith');
  assert.equal(result.values.action, 'login');
});

test('detectRawFormat does not misclassify a single "Label: text" line as key-value', () => {
  const result = detectRawFormat('Error: could not connect to database');
  assert.equal(result.detected, 'Unstructured or unknown');
});

test('detectRawFormat is unaffected by a colon after a process name in syslog text', () => {
  const raw = '<34>Jul  9 14:30:45 host sshd[1234]: Failed password for invalid user admin';
  assert.equal(detectRawFormat(raw).detected, 'RFC 3164 syslog');
});

test('suggestFieldExtraction recommends explicit EXTRACT (not KV_MODE=auto) for colon-style KV logs', () => {
  const raw = 'level: info, user: jsmith, action: login, result: success';
  const kv = detectRawFormat(raw);
  const suggestion = suggestFieldExtraction(kv.detected, raw, kv.values, kv.extracted);
  assert.match(suggestion.propsConf, /EXTRACT-\w+ = \w+:\\s\+/);
  assert.match(suggestion.notes.join(' '), /KV_MODE = auto only extracts key=value pairs/);
});

test('suggestFieldExtraction still recommends KV_MODE=auto for equals-style KV logs', () => {
  const raw = 'user=jsmith action=login result=success';
  const kv = detectRawFormat(raw);
  const suggestion = suggestFieldExtraction(kv.detected, raw, kv.values, kv.extracted);
  assert.equal(suggestion.propsConf, 'KV_MODE = auto');
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
