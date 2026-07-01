# express-origin-guard

Lock an Express backend down to a **single trusted frontend origin**, with strict `http`/`https` protocol enforcement. Requests from any other origin — or the wrong protocol — are rejected before they reach your routes.

Useful when a backend is meant to serve exactly one production frontend (e.g. `https://your-frontend.com`) and you want to make sure random scripts, other domains, or downgraded `http` requests can't talk to your API.

## Install

```bash
npm install express-origin-guard
```

## Quick start

```js
const express = require('express');
const originGuard = require('express-origin-guard');

const app = express();

app.use(
  originGuard({
    origin: 'https://your-frontend.com', // the only frontend allowed to call this API
    https: true, // reject anything that isn't https
  })
);

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.listen(3000);
```

With this configuration:

- Requests from `https://your-frontend.com` → **allowed**
- Requests from `http://your-frontend.com` → **blocked** (`https: true` requires https)
- Requests from `https://some-other-site.com` → **blocked**
- Requests with no `Origin`/`Referer` header (e.g. server-to-server, curl, Postman) → **blocked** by default

Flip the flag for local/dev HTTP:

```js
app.use(
  originGuard({
    origin: 'http://localhost:5173',
    https: false,
  })
);
```

If you omit `https` entirely, the protocol declared in `origin` itself becomes the requirement — so `origin: 'https://your-frontend.com'` behaves the same as passing `https: true` implicitly.

## API

### `originGuard(options)`

Returns an Express middleware function.

| Option | Type | Default | Description |
|---|---|---|---|
| `origin` | `string \| string[]` | **required** | The trusted frontend origin(s), e.g. `"https://your-frontend.com"`. Pass an array to allow more than one origin (e.g. production + staging). |
| `https` | `boolean` | derived from `origin` | If `true`, only `https` requests are accepted. If `false`, only `http`. |
| `allowCredentials` | `boolean` | `true` | Sets `Access-Control-Allow-Credentials`. |
| `allowedMethods` | `string[]` | `['GET','POST','PUT','PATCH','DELETE','OPTIONS']` | Methods advertised in CORS preflight. |
| `allowedHeaders` | `string[]` | `['Content-Type','Authorization','X-Requested-With']` | Headers advertised in CORS preflight. |
| `exposeHeaders` | `string[]` | `[]` | Headers exposed to the frontend via `Access-Control-Expose-Headers`. |
| `maxAge` | `number` | `86400` | Preflight cache duration, in seconds. |
| `trustReferer` | `boolean` | `true` | Falls back to the `Referer` header when `Origin` is missing (helps plain-navigation GET requests). |
| `onBlocked` | `(req, res, info) => void` | default 403 JSON handler | Fully override what happens on a blocked request. |
| `logger` | `(event, details) => void` | `null` | Called for every blocked request. Exceptions inside it are swallowed so logging never breaks a request. |
| `failClosed` | `boolean` | `true` | Set to `false` to run in **monitor-only mode**: mismatched origins are logged but still allowed through. Useful while first rolling this out. |

### Default blocked response

```json
{
  "error": "Forbidden",
  "message": "This backend only accepts requests from its configured frontend.",
  "code": "HOST_MISMATCH"
}
```

`code` will be one of: `MISSING_ORIGIN`, `MALFORMED_ORIGIN`, `HOST_MISMATCH`, `PROTOCOL_MISMATCH`.

### Custom block handling

```js
app.use(
  originGuard({
    origin: 'https://your-frontend.com',
    https: true,
    onBlocked: (req, res, info) => {
      res.status(403).json({ message: 'Nice try.', reason: info.reason });
    },
  })
);
```

### Multiple allowed frontends

```js
app.use(
  originGuard({
    origin: ['https://your-frontend.com', 'https://admin.your-frontend.com'],
    https: true,
  })
);
```

### Monitor-only rollout

Deploy safely by logging violations without blocking real traffic first:

```js
app.use(
  originGuard({
    origin: 'https://your-frontend.com',
    https: true,
    failClosed: false,
    logger: (event, details) => console.warn(event, details),
  })
);
```

## How it works

Reads the incoming `Origin` header (or `Referer` as a fallback), checks its hostname and protocol against your configured `origin`, and either sets the correct `Access-Control-Allow-*` headers and calls `next()`, or logs the attempt and returns a `403`.

## Notes

- This middleware should run **before** your routes and before `express.json()` is strictly necessary, but after any reverse-proxy trust setup (`app.set('trust proxy', ...)`) if you're behind one.
- Origin checking is a browser-cooperative mechanism (it relies on the `Origin`/`Referer` headers browsers send). It stops browser-based cross-origin abuse and casual misuse, but it is **not** a substitute for authentication/authorization on sensitive routes — non-browser clients can set these headers to whatever they want.

---

## Author

**Pramod Sithara Jayansiri**
- GitHub: [@PramodSithara](https://github.com/PramodSithara)
- npm: [npmjs.com/pramodsithara](https://www.npmjs.com/pramodsithara)

---

## License

MIT
