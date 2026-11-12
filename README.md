# @bladegg/log-scrub

[![npm version](https://img.shields.io/npm/v/@bladegg/log-scrub.svg)](https://www.npmjs.com/package/@bladegg/log-scrub)
[![CI](https://github.com/H-P-Jadeja/log-scrub/actions/workflows/ci.yml/badge.svg)](https://github.com/H-P-Jadeja/log-scrub/actions)
[![license](https://img.shields.io/npm/l/@bladegg/log-scrub.svg)](LICENSE)

> Deep-redact passwords, tokens, JWTs, card numbers and other secrets from objects and strings **before** they reach your logs.

Zero dependencies · Never mutates your data · Handles circular references · TypeScript types included · Node ≥ 18

## What it does

`@bladegg/log-scrub` takes any JavaScript value (object, array, Error, string, Map, Set…) and returns a **safe copy** in which sensitive information is replaced with a mask such as `[REDACTED]`. It finds secrets in two ways:

1. **By key name**: `password`, `accessToken`, `x-api-key`, `Authorization`, `cookie`, …
2. **By value pattern**: JWTs, `Bearer` tokens, AWS access keys, GitHub tokens, credentials inside URLs, and Luhn-valid credit-card numbers, even when hidden inside a larger string.

## Why it is useful

Logging whole request bodies, headers or error objects is a common debugging habit, and a common way to leak secrets into log files, monitoring tools and third-party services. Hand-writing `delete body.password` everywhere is easy to forget. `@bladegg/log-scrub` gives you one small function to call at the logging boundary.

## Installation

```bash
npm install @bladegg/log-scrub
```

## Basic usage

```js
const { scrub } = require('@bladegg/log-scrub');

const user = {
  id: 7,
  password: 'hunter2',
  profile: { apiKey: 'sk_live_123', city: 'Ahmedabad' },
};

console.log(scrub(user));
// {
//   id: 7,
//   password: '[REDACTED]',
//   profile: { apiKey: '[REDACTED]', city: 'Ahmedabad' }
// }
```

Scrub secrets hiding inside text:

```js
const { scrubString } = require('@bladegg/log-scrub');

scrubString('Authorization: Bearer abc123def456ghi');
// 'Authorization: Bearer [REDACTED]'

scrubString('postgres://admin:s3cret@db.local/app');
// 'postgres://admin:[REDACTED]@db.local/app'
```

Express middleware:

```js
const express = require('express');
const { expressMiddleware } = require('@baldegg/log-scrub');

const app = express();
app.use(express.json());
app.use(expressMiddleware());

app.post('/login', (req, res) => {
  console.log(req.scrubbed()); // method, url, headers, query, params, body, all redacted
  res.sendStatus(200);
});
```

## API

### `scrub(value, [options])`
Deep-clones `value`, redacting sensitive keys and string patterns.

| Parameter | Type | Description |
|---|---|---|
| `value` | `any` | Object, array, Error, string, Map, Set, or primitive |
| `options` | `ScrubOptions` | See [Options](#options) |

**Returns:** a new value of the same shape. The input is never modified. `Error` objects are returned as plain objects (`name`, `message`, `stack` + own props). `Buffer`s become `'[Buffer]'`; circular references become `'[Circular]'`.

### `scrubString(text, [options])`
Applies the value patterns to a string.
**Returns:** `string`. Throws `TypeError` if `text` is not a string.

### `createScrubber([options])`
Builds a reusable function `(value) => scrubbedValue` with options validated once. Use this in hot paths or when configuring a logger.

### `expressMiddleware([options])`
Express/Connect middleware. Adds `req.scrubbed()` → a redacted snapshot of `{ method, url, headers, query, params, body }`. Calls `next()`.

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `mask` | `string \| (value, path) => any` | `'[REDACTED]'` | Replacement text, or a function that computes it |
| `keys` | `(string \| RegExp)[]` | `[]` | Extra sensitive keys. Strings ignore case and separators and match exact or as a suffix (`'token'` matches `accessToken`, `access_token`, not `tokenCount`). RegExps test the raw key |
| `replaceDefaultKeys` | `boolean` | `false` | Use only `keys` instead of adding to the built-ins |
| `patterns` | `boolean \| (string \| RegExp)[]` | `true` | `true` = default patterns, `false` = off, or a list of names / RegExps |
| `maxDepth` | `number` | `20` | Depth limit; deeper values become `'[MaxDepth]'` |

**Built-in pattern names:** `jwt`, `bearer`, `aws-access-key`, `github-token`, `url-credentials`, `credit-card`, `email`. All are on by default **except `email`**, which is opt-in (`patterns: ['jwt', 'email']`).

**Exports:** `DEFAULT_KEYS`, `PATTERN_NAMES`, `DEFAULT_PATTERN_NAMES`.

### More examples

```js
const { createScrubber } = require('@bladegg/log-scrub');

const scrubber = createScrubber({
  keys: ['nickname', /^internal/i],
  patterns: ['jwt', 'email'],
  mask: (value) => `[hidden:${String(value).length} chars]`,
});

scrubber({ nickname: 'sammy', internalId: 'x1', note: 'mail sam@example.com' });
```

Run the bundled examples: `npm run example` or see [`examples/`](examples).

## Limitations

- Detection is heuristic. It reduces accidental leaks but is **not** a guarantee. Don't treat it as your only security control.
- Secrets in unusual key names or unrecognised formats need custom `keys` / `patterns`.
- Class instances are cloned as plain objects (prototypes and non-enumerable properties are not preserved).
- `Buffer` contents are never inspected.

## Running tests

```bash
npm test
```

## Contributing

1. Fork the repo and create a branch: `git checkout -b feature/my-change`
2. Add or update tests in `test/`
3. Make sure `npm test` passes
4. Open a pull request describing the change

Please follow [Semantic Versioning](https://semver.org/) expectations and update `CHANGELOG.md`.

## License

[MIT](LICENSE)
