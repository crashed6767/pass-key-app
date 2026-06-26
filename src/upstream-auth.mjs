import http from 'http';
import https from 'https';
import { mergeCookieHeaders, removeCookiesFromHeader } from './cookies.mjs';

export class UpstreamAuthenticator {
  constructor(config) {
    this.config = config;
    this.cachedSession = null;
  }

  async headersFor(req) {
    const headers = {};
    const upstream = this.config.upstream;

    if (upstream.authMode === 'basic') {
      const token = Buffer.from(`${upstream.basic.username}:${upstream.basic.password}`).toString('base64');
      headers.authorization = `Basic ${token}`;
    }

    if (upstream.authMode === 'header') {
      headers[upstream.header.name.toLowerCase()] = upstream.header.value;
    }

    let upstreamCookie = '';
    if (upstream.authMode === 'form') {
      upstreamCookie = await this.#ensureFormSession();
    }

    const clientCookie = upstream.forwardClientCookies
      ? removeCookiesFromHeader(req.headers.cookie || '', [this.config.authCookieName, this.config.flowCookieName])
      : '';
    const cookie = mergeCookieHeaders(clientCookie, upstreamCookie);
    if (cookie) headers.cookie = cookie;
    else headers.cookie = '';

    if (upstream.rewriteOrigin) {
      if (req.headers.origin) headers.origin = upstream.origin;
      if (req.headers.referer) headers.referer = `${upstream.origin}/`;
    }

    return headers;
  }

  async #ensureFormSession() {
    const form = this.config.upstream.form;
    if (this.cachedSession && this.cachedSession.expiresAt > Date.now() + 30_000) {
      return this.cachedSession.cookie;
    }

    const loginURL = new URL(form.loginPath, this.config.upstream.origin);
    const body = buildLoginBody(form);
    const headers = buildLoginHeaders(form, body);
    const { statusCode, headers: responseHeaders, responseText } = await requestRaw(loginURL, {
      method: form.method,
      headers,
      body,
    });

    if (!form.successStatuses.includes(statusCode)) {
      throw new Error(`Upstream login failed with HTTP ${statusCode}: ${responseText.slice(0, 120)}`);
    }

    const setCookies = responseHeaders['set-cookie'] || [];
    const selected = setCookies
      .map((cookie) => cookie.split(';')[0])
      .filter((cookie) => !form.cookieRegex || form.cookieRegex.test(cookie));

    if (selected.length === 0) {
      throw new Error('Upstream login succeeded but did not return a matching Set-Cookie header');
    }

    this.cachedSession = {
      cookie: selected.join('; '),
      expiresAt: Date.now() + form.ttlSeconds * 1000,
    };
    return this.cachedSession.cookie;
  }
}

function buildLoginBody(form) {
  const params = { ...form.extraParams, [form.usernameField]: form.username, [form.passwordField]: form.password };
  if (form.contentType === 'json') return JSON.stringify(params);
  return new URLSearchParams(params).toString();
}

function buildLoginHeaders(form, body) {
  const contentType = form.contentType === 'json' ? 'application/json' : 'application/x-www-form-urlencoded';
  return {
    'content-type': contentType,
    'content-length': Buffer.byteLength(body),
    'user-agent': 'pass-key-app/1.0',
  };
}

function requestRaw(url, options) {
  const transport = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = transport.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port,
      method: options.method,
      path: `${url.pathname}${url.search}`,
      headers: options.headers,
      timeout: 15_000,
    }, (res) => {
      let responseText = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { responseText += chunk; });
      res.on('end', () => resolve({ statusCode: res.statusCode || 0, headers: res.headers, responseText }));
    });
    req.on('timeout', () => req.destroy(new Error('Upstream login timed out')));
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}
