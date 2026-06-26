import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { after, before, test } from 'node:test';

let upstream;
let upstreamOrigin;
let proxy;
let proxyOrigin;
let tempDir;
const sessionSecret = 'test-session-secret-with-more-than-32-chars';
const userID = crypto.randomBytes(32).toString('base64url');

before(async () => {
  upstream = await startMockUpstream();
  upstreamOrigin = `http://127.0.0.1:${upstream.address().port}`;
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pass-key-app-test-'));
  fs.writeFileSync(path.join(tempDir, 'state.json'), JSON.stringify({
    users: [{ id: userID, username: 'test-admin', displayName: 'Test Admin', credentials: [] }],
    bootstrapUsed: true,
  }, null, 2));

  const proxyPort = await freePort();
  proxyOrigin = `http://127.0.0.1:${proxyPort}`;
  proxy = spawn(process.execPath, ['src/server.mjs'], {
    cwd: path.resolve('.'),
    env: {
      ...process.env,
      PUBLIC_ORIGIN: proxyOrigin,
      RP_ID: '127.0.0.1',
      RP_NAME: 'Integration Test App',
      PORT: String(proxyPort),
      UPSTREAM_ORIGIN: upstreamOrigin,
      UPSTREAM_AUTH_MODE: 'form',
      UPSTREAM_LOGIN_PATH: '/login',
      UPSTREAM_LOGIN_USERNAME: 'admin',
      UPSTREAM_LOGIN_PASSWORD: 'password',
      UPSTREAM_SESSION_COOKIE_REGEX: '^MOCK_SID=',
      SESSION_SECRET: sessionSecret,
      BOOTSTRAP_TOKEN: 'test-bootstrap-token-1234567890',
      DATA_DIR: tempDir,
      STRIP_UPSTREAM_SET_COOKIE: 'true',
      REWRITE_UPSTREAM_ORIGIN: 'true',
      FORWARD_CLIENT_COOKIES: 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitForHTTP(`${proxyOrigin}/healthz`);
});

after(async () => {
  if (proxy) proxy.kill('SIGTERM');
  await new Promise((resolve) => upstream?.close(resolve));
  if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
});

test('redirects unauthenticated browser requests to passkey login', async () => {
  const response = await fetch(`${proxyOrigin}/`, { redirect: 'manual', headers: { accept: 'text/html' } });
  assert.equal(response.status, 302);
  assert.match(response.headers.get('location'), /^\/passkey\/login\?next=/);
});

test('proxies authenticated requests and strips upstream Set-Cookie', async () => {
  const response = await fetch(`${proxyOrigin}/`, {
    headers: { cookie: authCookie(), accept: 'text/html' },
  });
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Mock Upstream App/);
  assert.equal(response.headers.get('set-cookie'), null);
});

test('logs into upstream form auth and rewrites public Referer for CSRF-sensitive APIs', async () => {
  const response = await fetch(`${proxyOrigin}/api/check`, {
    headers: {
      cookie: authCookie(),
      referer: `${proxyOrigin}/`,
      accept: 'application/json',
    },
  });
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.ok, true);
  assert.equal(payload.referer, `${upstreamOrigin}/`);
});

function authCookie() {
  const now = Math.floor(Date.now() / 1000);
  const payload = { uid: userID, username: 'test-admin', iat: now, exp: now + 600, nonce: 'test' };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', sessionSecret).update(encoded).digest('base64url');
  return `pka_auth=${encoded}.${sig}`;
}

function startMockUpstream() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/login') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        const params = new URLSearchParams(body);
        if (params.get('username') === 'admin' && params.get('password') === 'password') {
          res.writeHead(204, { 'set-cookie': 'MOCK_SID=abc123; Path=/; HttpOnly' });
          res.end();
        } else {
          res.writeHead(403);
          res.end('bad login');
        }
      });
      return;
    }

    if (req.url === '/api/check') {
      if (!String(req.headers.cookie || '').includes('MOCK_SID=abc123')) {
        res.writeHead(401, { 'content-type': 'text/plain' });
        res.end('missing upstream session');
        return;
      }
      if (req.headers.referer !== `${upstreamOrigin}/`) {
        res.writeHead(401, { 'content-type': 'text/plain' });
        res.end(`bad referer: ${req.headers.referer}`);
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, referer: req.headers.referer }));
      return;
    }

    res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'UPSTREAM_UI=do-not-forward; Path=/' });
    res.end('<!doctype html><title>Mock Upstream App</title><h1>Mock Upstream App</h1>');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

function freePort() {
  const server = http.createServer();
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitForHTTP(url) {
  const started = Date.now();
  while (Date.now() - started < 10_000) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${url}`);
}
