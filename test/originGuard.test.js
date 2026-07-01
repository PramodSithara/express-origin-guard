'use strict';

const assert = require('assert');
const createOriginGuard = require('../lib/originGuard');

function mockReq({ origin, referer, method = 'GET' } = {}) {
  return {
    headers: {
      ...(origin ? { origin } : {}),
      ...(referer ? { referer } : {}),
    },
    method,
    originalUrl: '/api/test',
    ip: '127.0.0.1',
  };
}

function mockRes() {
  const res = {
    statusCode: null,
    headers: {},
    body: null,
    setHeader(key, value) {
      this.headers[key] = value;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
    sendStatus(code) {
      this.statusCode = code;
      return this;
    },
  };
  return res;
}

function run(name, fn) {
  try {
    fn();
    console.log(`\u2713 ${name}`);
  } catch (err) {
    console.error(`\u2717 ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

run('allows exact https origin when https:true', () => {
  const guard = createOriginGuard({ origin: 'https://your-frontend.com', https: true });
  const req = mockReq({ origin: 'https://your-frontend.com' });
  const res = mockRes();
  let nextCalled = false;
  guard(req, res, () => (nextCalled = true));
  assert.strictEqual(nextCalled, true);
  assert.strictEqual(res.headers['Access-Control-Allow-Origin'], 'https://your-frontend.com');
});

run('blocks http origin when https:true', () => {
  const guard = createOriginGuard({ origin: 'https://your-frontend.com', https: true });
  const req = mockReq({ origin: 'http://your-frontend.com' });
  const res = mockRes();
  let nextCalled = false;
  guard(req, res, () => (nextCalled = true));
  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.statusCode, 403);
  assert.strictEqual(res.body.code, 'PROTOCOL_MISMATCH');
});

run('allows http origin when https:false', () => {
  const guard = createOriginGuard({ origin: 'http://localhost:5173', https: false });
  const req = mockReq({ origin: 'http://localhost:5173' });
  const res = mockRes();
  let nextCalled = false;
  guard(req, res, () => (nextCalled = true));
  assert.strictEqual(nextCalled, true);
});

run('blocks a completely different host', () => {
  const guard = createOriginGuard({ origin: 'https://your-frontend.com', https: true });
  const req = mockReq({ origin: 'https://evil.example.com' });
  const res = mockRes();
  let nextCalled = false;
  guard(req, res, () => (nextCalled = true));
  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.body.code, 'HOST_MISMATCH');
});

run('blocks requests with no Origin/Referer by default', () => {
  const guard = createOriginGuard({ origin: 'https://your-frontend.com', https: true });
  const req = mockReq({});
  const res = mockRes();
  let nextCalled = false;
  guard(req, res, () => (nextCalled = true));
  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.body.code, 'MISSING_ORIGIN');
});

run('falls back to Referer header when trustReferer is true', () => {
  const guard = createOriginGuard({ origin: 'https://your-frontend.com', https: true });
  const req = mockReq({ referer: 'https://your-frontend.com/checkout' });
  const res = mockRes();
  let nextCalled = false;
  guard(req, res, () => (nextCalled = true));
  assert.strictEqual(nextCalled, true);
});

run('responds 204 to OPTIONS preflight for allowed origin', () => {
  const guard = createOriginGuard({ origin: 'https://your-frontend.com', https: true });
  const req = mockReq({ origin: 'https://your-frontend.com', method: 'OPTIONS' });
  const res = mockRes();
  guard(req, res, () => {});
  assert.strictEqual(res.statusCode, 204);
});

run('failClosed:false lets blocked requests through but still logs', () => {
  let loggedEvent = null;
  const guard = createOriginGuard({
    origin: 'https://your-frontend.com',
    https: true,
    failClosed: false,
    logger: (event, details) => (loggedEvent = { event, details }),
  });
  const req = mockReq({ origin: 'https://evil.example.com' });
  const res = mockRes();
  let nextCalled = false;
  guard(req, res, () => (nextCalled = true));
  assert.strictEqual(nextCalled, true);
  assert.strictEqual(loggedEvent.event, 'blocked');
});

run('custom onBlocked handler overrides default response', () => {
  const guard = createOriginGuard({
    origin: 'https://your-frontend.com',
    https: true,
    onBlocked: (req, res) => res.status(418).json({ custom: true }),
  });
  const req = mockReq({ origin: 'https://evil.example.com' });
  const res = mockRes();
  guard(req, res, () => {});
  assert.strictEqual(res.statusCode, 418);
  assert.strictEqual(res.body.custom, true);
});

run('supports multiple allowed origins', () => {
  const guard = createOriginGuard({
    origin: ['https://your-frontend.com', 'https://admin.your-frontend.com'],
    https: true,
  });
  const res1 = mockRes();
  guard(mockReq({ origin: 'https://admin.your-frontend.com' }), res1, () => {});
  assert.strictEqual(res1.headers['Access-Control-Allow-Origin'], 'https://admin.your-frontend.com');
});

run('throws a clear error when origin is missing', () => {
  assert.throws(() => createOriginGuard({}), /origin.*required/);
});

console.log('\nAll originGuard tests completed.');
