'use strict';

const { DEFAULT_KEYS, buildKeyMatcher } = require('./keys');
const { PATTERNS, DEFAULT_PATTERN_NAMES } = require('./patterns');

const DEFAULTS = {
  mask: '[REDACTED]',
  keys: [],
  replaceDefaultKeys: false,
  patterns: true,
  maxDepth: 20,
};

function resolvePatterns(option) {
  if (option === false) return [];
  const list = option === true ? DEFAULT_PATTERN_NAMES : option;
  if (!Array.isArray(list)) {
    throw new TypeError('`patterns` must be a boolean or an array');
  }
  return list.map((item) => {
    if (item instanceof RegExp) {
      const flags = item.flags.includes('g') ? item.flags : item.flags + 'g';
      return { regex: new RegExp(item.source, flags), replace: (_m, mask) => mask };
    }
    const builtin = PATTERNS[item];
    if (!builtin) throw new Error(`Unknown pattern "${item}"`);
    return builtin;
  });
}

function setSafe(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

/**
 * Create a reusable scrubber function with fixed options.
 *
 * @param {object} [options]
 * @param {string|function} [options.mask='[REDACTED]']
 * @param {Array<string|RegExp>} [options.keys=[]]
 * @param {boolean} [options.replaceDefaultKeys=false]
 * @param {boolean|Array<string|RegExp>} [options.patterns=true]
 * @param {number} [options.maxDepth=20]
 * @returns {(value: any) => any}
 */
function createScrubber(options = {}) {
  const opts = { ...DEFAULTS, ...options };
  if (!Array.isArray(opts.keys)) throw new TypeError('`keys` must be an array');
  if (typeof opts.maxDepth !== 'number' || opts.maxDepth < 1) {
    throw new TypeError('`maxDepth` must be a positive number');
  }

  const rules = opts.replaceDefaultKeys ? opts.keys : [...DEFAULT_KEYS, ...opts.keys];
  const isSensitiveKey = buildKeyMatcher(rules);
  const patterns = resolvePatterns(opts.patterns);
  const makeMask = typeof opts.mask === 'function' ? opts.mask : () => opts.mask;

  function scrubText(str) {
    let out = str;
    for (const p of patterns) {
      p.regex.lastIndex = 0;
      out = out.replace(p.regex, (match) => {
        if (p.validate && !p.validate(match)) return match;
        return p.replace(match, String(makeMask(match, undefined)));
      });
    }
    return out;
  }

  function walk(value, depth, ancestors, path) {
    if (typeof value === 'string') return scrubText(value);
    if (value === null || typeof value !== 'object') return value;

    if (value instanceof Date) return new Date(value.getTime());
    if (value instanceof RegExp) return new RegExp(value.source, value.flags);
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) return '[Buffer]';
    if (ancestors.has(value)) return '[Circular]';
    if (depth > opts.maxDepth) return '[MaxDepth]';

    ancestors.add(value);
    try {
      if (Array.isArray(value)) {
        return value.map((item, i) => walk(item, depth + 1, ancestors, path.concat(i)));
      }

      if (value instanceof Map) {
        const out = new Map();
        for (const [k, v] of value) {
          const sensitive = typeof k === 'string' && isSensitiveKey(k);
          out.set(
            k,
            sensitive
              ? makeMask(v, path.concat(k))
              : walk(v, depth + 1, ancestors, path.concat(String(k)))
          );
        }
        return out;
      }

      if (value instanceof Set) {
        const out = new Set();
        for (const v of value) out.add(walk(v, depth + 1, ancestors, path));
        return out;
      }

      const source =
        value instanceof Error
          ? Object.assign(
              { name: value.name, message: value.message, stack: value.stack },
              value
            )
          : value;

      const out = {};
      for (const key of Object.keys(source)) {
        const child = source[key];
        const childPath = path.concat(key);
        if (isSensitiveKey(key) && child !== null && child !== undefined) {
          setSafe(out, key, makeMask(child, childPath));
        } else {
          setSafe(out, key, walk(child, depth + 1, ancestors, childPath));
        }
      }
      return out;
    } finally {
      ancestors.delete(value);
    }
  }

  return function scrubber(value) {
    return walk(value, 0, new WeakSet(), []);
  };
}

/** One-off scrub. For repeated use, prefer `createScrubber`. */
function scrub(value, options) {
  return createScrubber(options)(value);
}

/** Scrub patterns (JWTs, card numbers, ...) inside a plain string. */
function scrubString(str, options) {
  if (typeof str !== 'string') throw new TypeError('scrubString expects a string');
  return createScrubber(options)(str);
}

module.exports = { scrub, scrubString, createScrubber };
