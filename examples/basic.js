'use strict';

const { scrub, scrubString, createScrubber, expressMiddleware } = require('../src');
// After publishing: const { scrub, ... } = require('@bladegg/log-scrub');

// 1. Scrub an object before logging
const user = {
  id: 7,
  email: 'sam@example.com',
  password: 'hunter2',
  profile: { apiKey: 'sk_live_123', city: 'Ahmedabad' },
};
console.log(scrub(user));

// 2. Scrub secrets hiding inside strings
console.log(
  scrubString('Calling API with Authorization: Bearer abc123def456ghi')
);

// 3. Custom options
const scrubber = createScrubber({
  keys: ['nickname', /^internal/i],
  patterns: ['jwt', 'email'],
  mask: '***',
});
console.log(scrubber({ nickname: 'sammy', note: 'mail sam@example.com' }));

// 4. Express usage (app.use(expressMiddleware()); then console.log(req.scrubbed()))
const mw = expressMiddleware();
const fakeReq = { method: 'POST', url: '/login', headers: { cookie: 'sid=abc' }, body: { password: 'x' } };
mw(fakeReq, {}, () => console.log(fakeReq.scrubbed()));
