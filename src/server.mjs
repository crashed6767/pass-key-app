import express from 'express';
import http from 'http';
import httpProxy from 'http-proxy';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { clearCookie, parseCookies, setCookie, signPayload, verifyPayload } from './cookies.mjs';
import { loadConfig } from './config.mjs';
import { JsonStateStore, randomBase64Url } from './state.mjs';
import { UpstreamAuthenticator } from './upstream-auth.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const config = loadConfig();
const store = new JsonStateStore(config.dataDir);
const upstreamAuth = new UpstreamAuthenticator(config);
const pendingFlows = new Map();
const FLOW_TTL_MS = 10 * 60 * 1000;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);

const authJson = express.json({ limit: '1mb' });

app.get('/healthz', (req, res) => {
  res.json({ ok: true, service: 'pass-key-app', upstream: config.upstream.origin });
});

app.use('/passkey/assets', express.static(path.join(rootDir, 'public'), {
  maxAge: '1h',
  immutable: false,
}));

app.get('/passkey/login', (req, res) => sendAuthPage(res, 'login.html'));

app.get('/passkey/setup', (req, res) => {
  const user = getAuthUser(req);
  if (store.users.length === 0) {
    if (store.bootstrapUsed || req.query.token !== config.bootstrapToken) {
      return res.status(403).type('html').send(simplePage('Setup link invalid', 'This setup link is invalid or already used.'));
    }
  } else if (!user) {
    return res.redirect(`/passkey/login?next=${encodeURIComponent(req.originalUrl || '/passkey/account')}`);
  }
  sendAuthPage(res, 'setup.html');
});

app.get('/passkey/account', (req, res) => {
  if (!getAuthUser(req)) return res.redirect('/passkey/login?next=%2Fpasskey%2Faccount');
  sendAuthPage(res, 'account.html');
});

app.get('/passkey/logout', logout);
app.post('/passkey/logout', logout);

app.get('/passkey/api/status', (req, res) => {
  const user = getAuthUser(req);
  res.set('Cache-Control', 'no-store');
  res.json({
    hasUser: store.users.length > 0,
    authenticated: Boolean(user),
    username: user?.username || null,
    credentialCount: user?.credentials?.length || 0,
    rpID: config.rpID,
    rpName: config.rpName,
    origin: config.publicOrigin,
  });
});

app.post('/passkey/api/register/options', authJson, async (req, res) => {
  try {
    const flow = ensureFlow(req, res);
    const token = req.body?.token || req.query?.token;
    const authenticatedUser = getAuthUser(req);
    let user = authenticatedUser;
    let bootstrap = false;

    if (!user) {
      if (store.users.length === 0 && !store.bootstrapUsed && token === config.bootstrapToken) {
        user = store.createBootstrapUser(config.adminUsername, config.adminDisplayName);
        bootstrap = true;
      } else {
        return res.status(401).json({ error: 'Passkey login required' });
      }
    }

    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpID,
      userID: Buffer.from(user.id, 'base64url'),
      userName: user.username,
      userDisplayName: user.displayName || user.username,
      attestationType: 'none',
      excludeCredentials: (user.credentials || []).map((credential) => ({
        id: credential.id,
        transports: credential.transports || undefined,
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred',
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    putPending('registration', flow, { challenge: options.challenge, user, bootstrap });
    res.set('Cache-Control', 'no-store');
    res.json(options);
  } catch (error) {
    console.error('register/options failed', error);
    res.status(500).json({ error: 'Could not start passkey registration' });
  }
});

app.post('/passkey/api/register/verify', authJson, async (req, res) => {
  try {
    const flow = ensureFlow(req, res);
    const pending = takePending('registration', flow);
    if (!pending) return res.status(400).json({ error: 'Registration challenge expired. Refresh and try again.' });

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: pending.challenge,
      expectedOrigin: config.publicOrigin,
      expectedRPID: config.rpID,
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Passkey registration was not verified' });
    }

    let user;
    if (pending.bootstrap) {
      if (store.users.length !== 0 || store.bootstrapUsed) {
        return res.status(409).json({ error: 'Initial setup has already been completed' });
      }
      user = pending.user;
      store.state.users.push(user);
      store.bootstrapUsed = true;
    } else {
      user = store.findUserById(pending.user.id);
      if (!user) return res.status(404).json({ error: 'User no longer exists' });
    }

    store.addCredential(user, normalizeRegistrationCredential(verification.registrationInfo, req.body));
    setAuthCookie(res, user);
    res.json({ ok: true, redirect: '/' });
  } catch (error) {
    console.error('register/verify failed', error);
    res.status(400).json({ error: 'Could not verify passkey registration' });
  }
});

app.post('/passkey/api/authentication/options', authJson, async (req, res) => {
  try {
    if (store.users.length === 0) {
      return res.status(409).json({ error: 'No passkey is registered yet. Use the one-time setup link first.' });
    }
    const flow = ensureFlow(req, res);
    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      userVerification: 'preferred',
    });
    putPending('authentication', flow, { challenge: options.challenge });
    res.set('Cache-Control', 'no-store');
    res.json(options);
  } catch (error) {
    console.error('authentication/options failed', error);
    res.status(500).json({ error: 'Could not start passkey login' });
  }
});

app.post('/passkey/api/authentication/verify', authJson, async (req, res) => {
  try {
    const flow = ensureFlow(req, res);
    const pending = takePending('authentication', flow);
    if (!pending) return res.status(400).json({ error: 'Login challenge expired. Try again.' });

    const found = store.findCredential(req.body?.id);
    if (!found) return res.status(400).json({ error: 'That passkey is not registered here' });

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: pending.challenge,
      expectedOrigin: config.publicOrigin,
      expectedRPID: config.rpID,
      credential: credentialForVerification(found.credential),
      requireUserVerification: false,
    });

    if (!verification.verified) return res.status(401).json({ error: 'Passkey login failed' });

    found.credential.counter = verification.authenticationInfo?.newCounter ?? found.credential.counter;
    found.credential.lastUsedAt = new Date().toISOString();
    found.user.updatedAt = new Date().toISOString();
    store.save();
    setAuthCookie(res, found.user);
    res.json({ ok: true, redirect: sanitizeNext(req.body?.next) || '/' });
  } catch (error) {
    console.error('authentication/verify failed', error);
    res.status(400).json({ error: 'Could not verify passkey login' });
  }
});

app.use('/passkey', (req, res) => res.status(404).json({ error: 'Not found' }));

const proxy = httpProxy.createProxyServer({
  target: config.upstream.origin,
  changeOrigin: true,
  xfwd: true,
  ws: true,
});

proxy.on('proxyReq', applyProxyRequestHeaders);
proxy.on('proxyReqWs', applyProxyRequestHeaders);
proxy.on('proxyRes', (proxyRes) => {
  if (config.upstream.stripSetCookie) delete proxyRes.headers['set-cookie'];
});
proxy.on('error', (error, req, resOrSocket) => {
  console.error('proxy failed', error);
  if ('writeHead' in resOrSocket && !resOrSocket.headersSent) {
    resOrSocket.writeHead(502, { 'content-type': 'text/plain' });
    resOrSocket.end('Upstream app is not reachable through Pass Key App.');
  } else if ('destroy' in resOrSocket) {
    resOrSocket.destroy();
  }
});

app.use(async (req, res) => {
  if (!getAuthUser(req)) return rejectUnauthenticated(req, res);
  try {
    req.passKeyAppUpstreamHeaders = await upstreamAuth.headersFor(req);
    proxy.web(req, res);
  } catch (error) {
    console.error('upstream auth/proxy preparation failed', error);
    if (!res.headersSent) res.status(502).type('text/plain').send('Could not authenticate to upstream app.');
  }
});

const server = http.createServer(app);
server.on('upgrade', async (req, socket, head) => {
  if (!getAuthUser(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  try {
    req.passKeyAppUpstreamHeaders = await upstreamAuth.headersFor(req);
    proxy.ws(req, socket, head);
  } catch (error) {
    console.error('websocket upstream auth failed', error);
    socket.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
    socket.destroy();
  }
});

server.listen(config.port, '0.0.0.0', () => {
  console.log(`Pass Key App listening on :${config.port} for ${config.publicOrigin} -> ${config.upstream.origin}`);
});

function applyProxyRequestHeaders(proxyReq, req) {
  const headers = req.passKeyAppUpstreamHeaders || {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === '') proxyReq.removeHeader(name);
    else proxyReq.setHeader(name, value);
  }
}

function rejectUnauthenticated(req, res) {
  const loginURL = `/passkey/login?next=${encodeURIComponent(req.originalUrl || '/')}`;
  if (wantsHtml(req)) return res.redirect(loginURL);
  return res.status(401).json({ error: 'Passkey login required', login: loginURL });
}

function logout(req, res) {
  clearCookie(res, config.authCookieName, { secure: config.cookieSecure });
  res.redirect('/passkey/login');
}

function sendAuthPage(res, filename) {
  res.set({
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
  });
  res.sendFile(path.join(rootDir, 'public', filename));
}

function simplePage(title, body) {
  return `<!doctype html><meta charset="utf-8"><title>${escapeHtml(title)}</title><body style="font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(body)}</p></body>`;
}

function setAuthCookie(res, user) {
  const now = Math.floor(Date.now() / 1000);
  setCookie(res, config.authCookieName, signPayload({
    uid: user.id,
    username: user.username,
    iat: now,
    exp: now + config.sessionTTLSeconds,
    nonce: randomBase64Url(12),
  }, config.sessionSecret), {
    secure: config.cookieSecure,
    maxAge: config.sessionTTLSeconds,
  });
}

function getAuthUser(req) {
  const payload = verifyPayload(parseCookies(req.headers.cookie || '')[config.authCookieName], config.sessionSecret);
  if (!payload || !payload.uid || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return store.findUserById(payload.uid);
}

function ensureFlow(req, res) {
  const cookies = parseCookies(req.headers.cookie || '');
  let flow = cookies[config.flowCookieName];
  if (!flow || !/^[A-Za-z0-9_-]{24,}$/.test(flow)) flow = randomBase64Url(24);
  setCookie(res, config.flowCookieName, flow, { secure: config.cookieSecure, maxAge: Math.ceil(FLOW_TTL_MS / 1000) });
  return flow;
}

function putPending(type, flow, data) {
  cleanupPending();
  pendingFlows.set(`${type}:${flow}`, { ...data, expiresAt: Date.now() + FLOW_TTL_MS });
}

function takePending(type, flow) {
  cleanupPending();
  const key = `${type}:${flow}`;
  const value = pendingFlows.get(key);
  pendingFlows.delete(key);
  if (!value || value.expiresAt < Date.now()) return null;
  return value;
}

function cleanupPending() {
  const now = Date.now();
  for (const [key, value] of pendingFlows.entries()) {
    if (value.expiresAt < now) pendingFlows.delete(key);
  }
}

function normalizeRegistrationCredential(info, body) {
  const source = info.credential || {};
  const id = toBase64Url(source.id || info.credentialID || body.id);
  const publicKey = toBase64Url(source.publicKey || info.credentialPublicKey);
  if (!id || !publicKey) throw new Error('Registration did not return a credential id/public key');
  return {
    id,
    publicKey,
    counter: source.counter ?? info.counter ?? 0,
    transports: body?.response?.transports || source.transports || [],
    deviceType: info.credentialDeviceType || null,
    backedUp: Boolean(info.credentialBackedUp),
    createdAt: new Date().toISOString(),
  };
}

function credentialForVerification(credential) {
  return {
    id: credential.id,
    publicKey: Buffer.from(credential.publicKey, 'base64url'),
    counter: credential.counter || 0,
    transports: credential.transports || undefined,
  };
}

function toBase64Url(value) {
  if (!value) return '';
  if (typeof value === 'string') return value;
  return Buffer.from(value).toString('base64url');
}

function sanitizeNext(next) {
  if (typeof next !== 'string' || !next.startsWith('/') || next.startsWith('//')) return '/';
  if (next.startsWith('/passkey/')) return '/';
  return next;
}

function wantsHtml(req) {
  return (req.headers.accept || '').includes('text/html') || req.method === 'GET';
}

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
