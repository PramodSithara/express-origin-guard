'use strict';

/**
 * Example: lock this Express backend to a single trusted frontend.
 * Run with: node examples/server.js
 */

const express = require('express');
const originGuard = require('../index');

const app = express();

app.use(
  originGuard({
    origin: 'https://your-frontend.com', // only this frontend may call this backend
    https: true, // reject any request that isn't https
    allowCredentials: true,
    logger: (event, details) => {
      console.warn(`[origin-guard] ${event}:`, details);
    },
  })
);

app.use(express.json());

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000, () => {
  console.log('API listening on http://localhost:3000 (locked to https://your-frontend.com)');
});
