'use strict';

const { scrub, scrubString, createScrubber } = require('./scrub');
const { expressMiddleware } = require('./middleware');
const { DEFAULT_KEYS } = require('./keys');
const { PATTERNS, DEFAULT_PATTERN_NAMES } = require('./patterns');

module.exports = {
  scrub,
  scrubString,
  createScrubber,
  expressMiddleware,
  DEFAULT_KEYS,
  PATTERN_NAMES: Object.keys(PATTERNS),
  DEFAULT_PATTERN_NAMES,
};
