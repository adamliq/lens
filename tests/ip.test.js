const test = require('node:test');
const assert = require('node:assert/strict');
const { classifyIpAddress, findIpCandidates } = require('../app.js');

test('classifyIpAddress recognises plain IPv4 addresses', () => {
  const result = classifyIpAddress('8.8.8.8');
  assert.equal(result.valid, true);
  assert.equal(result.version, 'IPv4');
  assert.equal(result.category, 'Public / globally routable (unless otherwise reserved)');
  assert.equal(result.isCidr, false);
});

test('classifyIpAddress recognises IPv4 CIDR ranges', () => {
  const result = classifyIpAddress('192.168.1.0/24');
  assert.equal(result.valid, true);
  assert.equal(result.isCidr, true);
  assert.equal(result.cidr, 24);
  assert.equal(result.category, 'Private (RFC 1918)');
});

test('classifyIpAddress categorises RFC 1918, loopback, and link-local IPv4', () => {
  assert.equal(classifyIpAddress('10.1.2.3').category, 'Private (RFC 1918)');
  assert.equal(classifyIpAddress('172.20.0.1').category, 'Private (RFC 1918)');
  assert.equal(classifyIpAddress('127.0.0.1').category, 'Loopback');
  assert.equal(classifyIpAddress('169.254.1.1').category, 'Link-local (APIPA)');
});

test('classifyIpAddress rejects out-of-range octets and bad CIDR prefixes', () => {
  assert.equal(classifyIpAddress('256.1.1.1').valid, false);
  assert.equal(classifyIpAddress('10.0.0.1/33').valid, false);
  assert.equal(classifyIpAddress('10.0.0.1/').valid, false);
});

test('classifyIpAddress recognises IPv6 addresses and categorises loopback/link-local', () => {
  assert.equal(classifyIpAddress('::1').category, 'Loopback');
  assert.equal(classifyIpAddress('fe80::1').category, 'Link-local (fe80::/10)');
  const global = classifyIpAddress('2001:4860:4860::8888');
  assert.equal(global.valid, true);
  assert.equal(global.version, 'IPv6');
});

test('classifyIpAddress recognises IPv6 CIDR ranges', () => {
  const result = classifyIpAddress('2001:db8::/32');
  assert.equal(result.valid, true);
  assert.equal(result.isCidr, true);
  assert.equal(result.cidr, 32);
});

test('classifyIpAddress rejects non-address text and empty input', () => {
  assert.equal(classifyIpAddress('not-an-ip').valid, false);
  assert.equal(classifyIpAddress('').valid, false);
});

test('findIpCandidates extracts IPs from raw text and key-based values', () => {
  const raw = 'src_ip=10.1.2.3 dst_ip=8.8.8.8 msg="connection established"';
  const candidates = findIpCandidates(raw, {src_ip: '10.1.2.3', dst_ip: '8.8.8.8'});
  const values = candidates.map(c => c.value).sort();
  assert.deepEqual(values, ['10.1.2.3', '8.8.8.8']);
});

test('findIpCandidates does not include invalid IP-shaped text', () => {
  const candidates = findIpCandidates('version=999.999.999.999 build=2026', {});
  assert.equal(candidates.length, 0);
});
