'use strict';

const { createScrubber } = require('./scrub');

/**
 * Express/Connect middleware. Adds `req.scrubbed()` which returns a loggable,
 * redacted snapshot of the request (method, url, headers, query, params, body).
 *
 * @param {object} [options] Same options as `createScrubber`.
 */
function expressMiddleware(options) {
  const scrubber = createScrubber(options);
  return function logScrubMiddleware(req, _res, next) {
    req.scrubbed = function scrubbed() {
      return scrubber({
        method: req.method,
        url: req.originalUrl || req.url,
        headers: req.headers,
        query: req.query,
        params: req.params,
        body: req.body,
      });
    };
    next();
  };
}

module.exports = { expressMiddleware };
