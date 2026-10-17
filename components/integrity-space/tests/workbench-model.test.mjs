import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizePage, readIdentity, safeLinks, cleanText} from '../ui/workbench-model.js';

test('different host response is rejected', () => {
  assert.throws(() => normalizePage({host_id:'other', tasks:[]}, 'selected'));
});
test('different thread response is rejected', () => {
  assert.throws(() => readIdentity({host_id:'selected', thread_id:'other', chunk:'text'}, 'selected', 'wanted'));
});
test('public links exclude local hosts, insecure links and embedded authentication', () => {
  const authenticated = new URL('https://example.invalid/');
  authenticated.username = 'synthetic-user';
  authenticated.password = 'synthetic-test-only';
  const links=safeLinks(`https://localhost/source http://192.0.2.1/ ${authenticated.href} https://docs.example.invalid/guide`);
  assert.deepEqual(links.map(x=>x.url), ['https://docs.example.invalid/guide']);
});
test('provider text is scrubbed before display', () => {
  assert.equal(cleanText('password=synthetic-value'), 'password=[скрыто]');
});
