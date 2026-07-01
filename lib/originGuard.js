'use strict';

const { URL } = require('url');

/**
 * Custom error type thrown / reported for blocked requests.
 */
class OriginGuardError extends Error {
  constructor(message, statusCode = 403, code = 'ORIGIN_NOT_ALLOWED') {
    super(message);
    this.name = 'OriginGuardError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

/**
 * Normalizes one or many frontend URLs into a comparable internal shape.
 * @param {string|string[]} input
 * @returns {Array<{raw:string, protocol:string, hostname:string, port:string, origin:string}>}
 */
function normalizeOrigins(input) {
  const list = Array.isArray(input) ? input : [input];

  return list.filter(Boolean).map((urlString) => {
    let parsed;
    try {
      parsed = new URL(urlString);
    } catch (err) {
      throw new TypeError(
        `[express-origin-guard] Invalid origin: "${urlString}". Provide a full URL, e.g. "https://app.example.com".`
      );
    }

    return {
      raw: urlString.replace(/\/+$/, ''),
      protocol: parsed.protocol.replace(':', ''), // 'https' | 'http'
      hostname: parsed.hostname,
      // Only treated as a hard constraint when the configured origin explicitly
      // included a port (e.g. "http://localhost:5173"). Otherwise port
      // is not compared, since it is derived purely from the protocol.
      explicitPort: parsed.port || null,
      origin: parsed.origin,
    };
  });
}

/**
 * Creates an Express middleware that only allows requests originating from
 * a pre-configured frontend URL, optionally enforcing a specific protocol
 * (http vs https).
 *
 * @param {object} options
 * @param {string|string[]} options.origin - The trusted frontend origin(s), e.g. "https://your-frontend.com"
 * @param {boolean} [options.https] - If true, only https requests are accepted. If false, only http. If omitted, the protocol from the configured origin is used as the requirement.
 * @param {boolean} [options.allowCredentials=true] - Sets Access-Control-Allow-Credentials.
 * @param {string[]} [options.allowedMethods] - Allowed HTTP methods for CORS preflight.
 * @param {string[]} [options.allowedHeaders] - Allowed request headers for CORS preflight.
 * @param {string[]} [options.exposeHeaders] - Headers exposed to the frontend via CORS.
 * @param {number} [options.maxAge=86400] - Preflight cache duration in seconds.
 * @param {boolean} [options.trustReferer=true] - Fall back to the Referer header when Origin is absent (useful for simple GET navigations).
 * @param {Function} [options.onBlocked] - Custom handler: (req, res, info) => void. Overrides the default 403 JSON response.
 * @param {Function} [options.logger] - Called as logger(event, details) whenever a request is blocked. Never throws into the request cycle.
 * @param {boolean} [options.failClosed=true] - If false, disallowed origins are logged but still allowed through (monitor-only mode).
 * @returns {import('express').RequestHandler}
 */
function createOriginGuard(options = {}) {
  const {
    origin,
    frontendUrl,
    https,
    allowCredentials = true,
    allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders = ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposeHeaders = [],
    maxAge = 86400,
    trustReferer = true,
    onBlocked,
    logger = null,
    failClosed = true,
  } = options;

  const configuredOrigin = origin ?? frontendUrl;

  if (!configuredOrigin) {
    throw new TypeError(
      '[express-origin-guard] "origin" is required, e.g. createOriginGuard({ origin: "https://your-frontend.com", https: true })'
    );
  }

  const allowedOrigins = normalizeOrigins(configuredOrigin);

  // If `https` is explicitly passed, it becomes a hard requirement.
  // Otherwise the protocol declared in the configured origin itself is enforced.
  const enforceExplicitProtocol = typeof https === 'boolean';
  const requiredProtocol = https ? 'https' : 'http';

  function log(event, details) {
    if (typeof logger === 'function') {
      try {
        logger(event, details);
      } catch (_) {
        // Logging must never break the request pipeline.
      }
    }
  }

  function extractRequestOrigin(req) {
    const originHeader = req.headers['origin'];
    if (originHeader) return originHeader;

    if (trustReferer && req.headers['referer']) {
      try {
        return new URL(req.headers['referer']).origin;
      } catch (_) {
        return null;
      }
    }

    return null;
  }

  function isOriginAllowed(originString) {
    if (!originString) {
      return { allowed: false, reason: 'MISSING_ORIGIN' };
    }

    let parsed;
    try {
      parsed = new URL(originString);
    } catch (_) {
      return { allowed: false, reason: 'MALFORMED_ORIGIN' };
    }

    const protocol = parsed.protocol.replace(':', '');
    const hostname = parsed.hostname;
    const port = parsed.port || (protocol === 'https' ? '443' : '80');

    const match = allowedOrigins.find((o) => {
      if (o.hostname !== hostname) return false;
      // Only enforce port equality if the configured origin pinned
      // an explicit, non-default port (e.g. local dev on :5173).
      if (o.explicitPort) return o.explicitPort === port;
      return true;
    });

    if (!match) {
      return { allowed: false, reason: 'HOST_MISMATCH' };
    }

    const expectedProtocol = enforceExplicitProtocol ? requiredProtocol : match.protocol;

    if (protocol !== expectedProtocol) {
      return {
        allowed: false,
        reason: 'PROTOCOL_MISMATCH',
        expected: expectedProtocol,
        got: protocol,
      };
    }

    return {
      allowed: true,
      matchedOrigin: `${protocol}://${hostname}:${port}`,
      canonical: match.origin,
    };
  }

  function defaultBlockedHandler(req, res, info) {
    res.status(403).json({
      error: 'Forbidden',
      message: 'This backend only accepts requests from its configured frontend.',
      code: info.reason || 'ORIGIN_NOT_ALLOWED',
    });
  }

  return function originGuard(req, res, next) {
    const requestOrigin = extractRequestOrigin(req);
    const result = isOriginAllowed(requestOrigin);

    if (result.allowed) {
      res.setHeader('Access-Control-Allow-Origin', result.canonical);
      res.setHeader('Vary', 'Origin');
      if (allowCredentials) res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', allowedMethods.join(','));
      res.setHeader('Access-Control-Allow-Headers', allowedHeaders.join(','));
      if (exposeHeaders.length) {
        res.setHeader('Access-Control-Expose-Headers', exposeHeaders.join(','));
      }
      res.setHeader('Access-Control-Max-Age', String(maxAge));

      if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
      }
      return next();
    }

    log('blocked', {
      requestOrigin,
      reason: result.reason,
      expectedProtocol: result.expected,
      gotProtocol: result.got,
      path: req.originalUrl,
      method: req.method,
      ip: req.ip,
      time: new Date().toISOString(),
    });

    if (!failClosed) {
      return next();
    }

    if (typeof onBlocked === 'function') {
      return onBlocked(req, res, result);
    }

    return defaultBlockedHandler(req, res, result);
  };
}

module.exports = createOriginGuard;
module.exports.createOriginGuard = createOriginGuard;
module.exports.OriginGuardError = OriginGuardError;
