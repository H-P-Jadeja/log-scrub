'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  scrub,
  scrubString,
  createScrubber,
  expressMiddleware,
} = require('../src');

const JWT =
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature';

test('redacts sensitive keys, leaves others alone', () => {
  const out = scrub({ user: 'sam', password: 'hunter2', age: 20 });
  assert.deepEqual(out, { user: 'sam', password: '[REDACTED]', age: 20 });
});

test('key matching ignores case and separators, supports suffixes', () => {
  const out = scrub({
    accessToken: 'a',
    ACCESS_TOKEN: 'b',
    'x-api-key': 'c',
    userPassword: 'd',
    tokenCount: 5,
  });
  assert.equal(out.accessToken, '[REDACTED]');
  assert.equal(out.ACCESS_TOKEN, '[REDACTED]');
  assert.equal(out['x-api-key'], '[REDACTED]');
  assert.equal(out.userPassword, '[REDACTED]');
  assert.equal(out.tokenCount, 5);
});

test('works on deeply nested objects and arrays', () => {
  const out = scrub({ a: [{ b: { secret: 's' } }], list: [1, 2] });
  assert.equal(out.a[0].b.secret, '[REDACTED]');
  assert.deepEqual(out.list, [1, 2]);
});

test('does not mutate the input', () => {
  const input = { password: 'x', nested: { token: 'y' } };
  scrub(input);
  assert.equal(input.password, 'x');
  assert.equal(input.nested.token, 'y');
});

test('handles circular references', () => {
  const a = { name: 'a', password: 'p' };
  a.self = a;
  const out = scrub(a);
  assert.equal(out.self, '[Circular]');
  assert.equal(out.password, '[REDACTED]');
});

test('shared (non-circular) references are copied normally', () => {
  const shared = { token: 't' };
  const out = scrub({ one: shared, two: shared });
  assert.equal(out.one.token, '[REDACTED]');
  assert.equal(out.two.token, '[REDACTED]');
});

test('custom keys (string and RegExp)', () => {
  const out = scrub(
    { nickname: 'n', internalId: 'i', other: 'o' },
    { keys: ['nickname', /^internal/] }
  );
  assert.equal(out.nickname, '[REDACTED]');
  assert.equal(out.internalId, '[REDACTED]');
  assert.equal(out.other, 'o');
});

test('replaceDefaultKeys uses only the provided keys', () => {
  const out = scrub(
    { password: 'p', custom: 'c' },
    { keys: ['custom'], replaceDefaultKeys: true }
  );
  assert.equal(out.password, 'p');
  assert.equal(out.custom, '[REDACTED]');
});

test('custom mask string and mask function', () => {
  assert.equal(scrub({ password: 'x' }, { mask: '***' }).password, '***');
  const out = scrub(
    { password: 'abcdef' },
    { mask: (v) => `*(${String(v).length})` }
  );
  assert.equal(out.password, '*(6)');
});

test('scrubs JWTs and bearer tokens inside strings', () => {
  assert.equal(scrubString(`token=${JWT} ok`), 'token=[REDACTED] ok');
  assert.equal(
    scrubString('Authorization: Bearer abcdefghijkl123'),
    'Authorization: Bearer [REDACTED]'
  );
});

test('scrubs AWS keys, GitHub tokens, URL credentials', () => {
  assert.equal(scrubString('key AKIAIOSFODNN7EXAMPLE'), 'key [REDACTED]');
  assert.equal(
    scrubString('ghp_' + 'a'.repeat(36)),
    '[REDACTED]'
  );
  assert.equal(
    scrubString('postgres://admin:s3cret@db.local:5432/app'),
    'postgres://admin:[REDACTED]@db.local:5432/app'
  );
});

test('credit cards are only masked when Luhn-valid', () => {
  assert.equal(scrubString('card 4242 4242 4242 4242'), 'card [REDACTED]');
  assert.equal(scrubString('order 1234567890123456'), 'order 1234567890123456');
});

test('email is opt-in', () => {
  assert.equal(scrubString('mail a@b.com'), 'mail a@b.com');
  assert.equal(scrubString('mail a@b.com', { patterns: ['email'] }), 'mail [REDACTED]');
});

test('patterns: false disables value scanning', () => {
  assert.equal(scrubString(JWT, { patterns: false }), JWT);
});

test('custom RegExp pattern', () => {
  const out = scrubString('id SSN-123 here', { patterns: [/SSN-\d+/] });
  assert.equal(out, 'id [REDACTED] here');
});

test('unknown pattern name throws', () => {
  assert.throws(() => scrubString('x', { patterns: ['nope'] }), /Unknown pattern/);
});

test('Errors become plain objects with scrubbed message', () => {
  const err = new Error(`failed with ${JWT}`);
  err.token = 'abc';
  const out = scrub(err);
  assert.equal(out.name, 'Error');
  assert.ok(!out.message.includes('eyJ'));
  assert.equal(out.token, '[REDACTED]');
});

test('Dates, Maps and Sets are handled', () => {
  const d = new Date(0);
  const out = scrub({
    d,
    m: new Map([['password', 'x'], ['ok', 'y']]),
    s: new Set([JWT]),
  });
  assert.equal(out.d.getTime(), 0);
  assert.equal(out.m.get('password'), '[REDACTED]');
  assert.equal(out.m.get('ok'), 'y');
  assert.ok(out.s.has('[REDACTED]'));
});

test('maxDepth guards against very deep structures', () => {
  const deep = { a: { b: { c: { d: 1 } } } };
  const out = scrub(deep, { maxDepth: 2 });
  assert.equal(out.a.b.c, '[MaxDepth]');
});

test('primitives and null pass through', () => {
  assert.equal(scrub(null), null);
  assert.equal(scrub(42), 42);
  assert.equal(scrub(undefined), undefined);
  assert.equal(scrub(true), true);
});

test('null/undefined values under sensitive keys are preserved', () => {
  const out = scrub({ password: null, token: undefined });
  assert.equal(out.password, null);
  assert.equal(out.token, undefined);
});

test('__proto__ key does not pollute', () => {
  const evil = JSON.parse('{"__proto__": {"polluted": true}, "password": "x"}');
  const out = scrub(evil);
  assert.equal({}.polluted, undefined);
  assert.equal(out.password, '[REDACTED]');
});

test('invalid options throw TypeError', () => {
  assert.throws(() => createScrubber({ keys: 'password' }), TypeError);
  assert.throws(() => createScrubber({ maxDepth: 0 }), TypeError);
  assert.throws(() => scrubString(123), TypeError);
});

test('createScrubber returns a reusable function', () => {
  const s = createScrubber({ mask: '###' });
  assert.equal(s({ password: 'a' }).password, '###');
  assert.equal(s({ password: 'b' }).password, '###');
});

test('expressMiddleware adds req.scrubbed()', () => {
  const req = {
    method: 'POST',
    originalUrl: '/login',
    headers: { authorization: 'Bearer abcdefghijkl', host: 'x.com' },
    body: { user: 'sam', password: 'hunter2' },
  };
  let called = false;
  expressMiddleware()(req, {}, () => (called = true));
  assert.ok(called);
  const snap = req.scrubbed();
  assert.equal(snap.url, '/login');
  assert.equal(snap.headers.authorization, '[REDACTED]');
  assert.equal(snap.headers.host, 'x.com');
  assert.equal(snap.body.password, '[REDACTED]');
  assert.equal(snap.body.user, 'sam');
});
