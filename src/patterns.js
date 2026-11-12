'use strict';

/**
 * Built-in value patterns. Each pattern finds sensitive text inside a string.
 * `replace(match, mask)` returns the replacement for one match.
 * `validate(match)` (optional) lets a pattern reject false positives.
 */

function luhn(input) {
  const digits = input.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

const PATTERNS = {
  jwt: {
    regex: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g,
    replace: (_m, mask) => mask,
  },
  bearer: {
    regex: /\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]{6,}=*/gi,
    replace: (m, mask) => `${m.split(/\s+/)[0]} ${mask}`,
  },
  'aws-access-key': {
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    replace: (_m, mask) => mask,
  },
  'github-token': {
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    replace: (_m, mask) => mask,
  },
  'url-credentials': {
    regex: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]+@/gi,
    replace: (m, mask) => m.replace(/\/\/([^:]+):[^@]+@/, `//$1:${mask}@`),
  },
  'credit-card': {
    regex: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: luhn,
    replace: (_m, mask) => mask,
  },
  email: {
    regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    replace: (_m, mask) => mask,
  },
};

/** Patterns enabled when `patterns: true` (the default). Email is opt-in. */
const DEFAULT_PATTERN_NAMES = [
  'jwt',
  'bearer',
  'aws-access-key',
  'github-token',
  'url-credentials',
  'credit-card',
];

module.exports = { PATTERNS, DEFAULT_PATTERN_NAMES, luhn };
