import fs from 'fs';
import path from 'path';

loadDotEnv(process.env.ENV_FILE || '.env');

export function loadConfig(env = process.env) {
  const publicOrigin = normalizeOrigin(required(env, 'PUBLIC_ORIGIN'));
  const upstreamOrigin = normalizeOrigin(required(env, 'UPSTREAM_ORIGIN'));
  const publicURL = new URL(publicOrigin);
  const upstreamURL = new URL(upstreamOrigin);
  const upstreamAuthMode = (env.UPSTREAM_AUTH_MODE || 'none').toLowerCase();

  if (!['none', 'basic', 'header', 'form'].includes(upstreamAuthMode)) {
    throw new Error(`Invalid UPSTREAM_AUTH_MODE: ${upstreamAuthMode}`);
  }

  const config = {
    port: intEnv(env, 'PORT', 8091),
    publicOrigin,
    publicHost: publicURL.host,
    rpID: env.RP_ID || publicURL.hostname,
    rpName: env.RP_NAME || 'Pass Key App',
    dataDir: env.DATA_DIR || path.resolve('data'),
    sessionSecret: required(env, 'SESSION_SECRET'),
    bootstrapToken: required(env, 'BOOTSTRAP_TOKEN'),
    sessionTTLSeconds: intEnv(env, 'SESSION_TTL_SECONDS', 12 * 60 * 60),
    adminUsername: env.ADMIN_USERNAME || 'admin',
    adminDisplayName: env.ADMIN_DISPLAY_NAME || 'Passkey admin',
    cookieSecure: boolEnv(env, 'COOKIE_SECURE', publicURL.protocol === 'https:'),
    authCookieName: env.AUTH_COOKIE_NAME || 'pka_auth',
    flowCookieName: env.FLOW_COOKIE_NAME || 'pka_flow',
    upstream: {
      origin: upstreamOrigin,
      url: upstreamURL,
      authMode: upstreamAuthMode,
      rewriteOrigin: boolEnv(env, 'REWRITE_UPSTREAM_ORIGIN', true),
      stripSetCookie: boolEnv(env, 'STRIP_UPSTREAM_SET_COOKIE', true),
      forwardClientCookies: boolEnv(env, 'FORWARD_CLIENT_COOKIES', false),
      basic: {
        username: env.UPSTREAM_BASIC_USERNAME || '',
        password: env.UPSTREAM_BASIC_PASSWORD || '',
      },
      header: {
        name: env.UPSTREAM_AUTH_HEADER_NAME || '',
        value: env.UPSTREAM_AUTH_HEADER_VALUE || '',
      },
      form: {
        loginPath: env.UPSTREAM_LOGIN_PATH || '/login',
        method: (env.UPSTREAM_LOGIN_METHOD || 'POST').toUpperCase(),
        contentType: (env.UPSTREAM_LOGIN_CONTENT_TYPE || 'form').toLowerCase(),
        usernameField: env.UPSTREAM_LOGIN_USERNAME_FIELD || 'username',
        passwordField: env.UPSTREAM_LOGIN_PASSWORD_FIELD || 'password',
        username: env.UPSTREAM_LOGIN_USERNAME || '',
        password: env.UPSTREAM_LOGIN_PASSWORD || '',
        extraParams: parseQueryish(env.UPSTREAM_LOGIN_EXTRA_PARAMS || ''),
        successStatuses: parseStatusList(env.UPSTREAM_LOGIN_SUCCESS_STATUS || '200,204'),
        cookieRegex: env.UPSTREAM_SESSION_COOKIE_REGEX ? new RegExp(env.UPSTREAM_SESSION_COOKIE_REGEX) : null,
        ttlSeconds: intEnv(env, 'UPSTREAM_SESSION_TTL_SECONDS', 50 * 60),
      },
    },
  };

  validateConfig(config);
  return config;
}

function validateConfig(config) {
  if (config.sessionSecret.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters');
  }
  if (config.bootstrapToken.length < 16) {
    throw new Error('BOOTSTRAP_TOKEN must be at least 16 characters');
  }
  if (config.upstream.authMode === 'basic') {
    if (!config.upstream.basic.username || !config.upstream.basic.password) {
      throw new Error('UPSTREAM_BASIC_USERNAME and UPSTREAM_BASIC_PASSWORD are required for basic mode');
    }
  }
  if (config.upstream.authMode === 'header') {
    if (!config.upstream.header.name || !config.upstream.header.value) {
      throw new Error('UPSTREAM_AUTH_HEADER_NAME and UPSTREAM_AUTH_HEADER_VALUE are required for header mode');
    }
  }
  if (config.upstream.authMode === 'form') {
    const form = config.upstream.form;
    if (!form.username || !form.password) {
      throw new Error('UPSTREAM_LOGIN_USERNAME and UPSTREAM_LOGIN_PASSWORD are required for form mode');
    }
    if (!['form', 'json'].includes(form.contentType)) {
      throw new Error('UPSTREAM_LOGIN_CONTENT_TYPE must be form or json');
    }
  }
}

function loadDotEnv(file) {
  if (!file || !fs.existsSync(file)) return;
  const text = fs.readFileSync(file, 'utf8');
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const index = trimmed.indexOf('=');
    if (index === -1) continue;
    const key = trimmed.slice(0, index).trim();
    let value = trimmed.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

function required(env, name) {
  const value = env[name];
  if (!value) throw new Error(`Missing required environment variable ${name}`);
  return value;
}

function normalizeOrigin(value) {
  const url = new URL(value);
  url.pathname = '';
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

function boolEnv(env, name, fallback) {
  const value = env[name];
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function intEnv(env, name, fallback) {
  const value = env[name];
  if (value === undefined || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) throw new Error(`${name} must be an integer`);
  return parsed;
}

function parseStatusList(value) {
  return String(value).split(',').map((part) => Number.parseInt(part.trim(), 10)).filter(Number.isFinite);
}

function parseQueryish(value) {
  const params = {};
  if (!value) return params;
  for (const [key, val] of new URLSearchParams(value)) {
    params[key] = val;
  }
  return params;
}
