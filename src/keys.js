'use strict';

/** Normalised (lowercase, letters/digits only) names of sensitive keys. */
const DEFAULT_KEYS = [
  'password',
  'passwd',
  'pwd',
  'passphrase',
  'secret',
  'clientsecret',
  'token',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'apikey',
  'authorization',
  'auth',
  'cookie',
  'setcookie',
  'privatekey',
  'sessionid',
  'creditcard',
  'cardnumber',
  'cvv',
  'cvc',
  'ssn',
];

function normalize(key) {
  return String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Build a predicate `(key) => boolean` from a list of key rules.
 * - strings are matched case-insensitively, ignoring separators, as an exact
 *   match or suffix: "token" matches "accessToken" and "access_token"
 *   but not "tokenCount".
 * - RegExps are tested against the raw key.
 */
function buildKeyMatcher(rules) {
  const names = [];
  const regexes = [];
  for (const rule of rules) {
    if (rule instanceof RegExp) {
      regexes.push(rule);
    } else if (typeof rule === 'string' && rule.length > 0) {
      names.push(normalize(rule));
    } else {
      throw new TypeError('Key rules must be non-empty strings or RegExps');
    }
  }
  return function isSensitiveKey(key) {
    if (typeof key !== 'string') return false;
    const n = normalize(key);
    if (n.length > 0) {
      for (const name of names) {
        if (n === name || n.endsWith(name)) return true;
      }
    }
    for (const re of regexes) {
      re.lastIndex = 0;
      if (re.test(key)) return true;
    }
    return false;
  };
}

module.exports = { DEFAULT_KEYS, buildKeyMatcher, normalize };
