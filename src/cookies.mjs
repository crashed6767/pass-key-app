import crypto from 'crypto';

export function parseCookies(header = '') {
  const cookies = {};
  for (const part of String(header).split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!name) continue;
    try {
      cookies[name] = decodeURIComponent(value);
    } catch {
      cookies[name] = value;
    }
  }
  return cookies;
}

export function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${options.path || '/'}`, 'HttpOnly', `SameSite=${options.sameSite || 'Lax'}`];
  if (options.secure) parts.push('Secure');
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  return parts.join('; ');
}

export function setCookie(res, name, value, options = {}) {
  res.append('Set-Cookie', serializeCookie(name, value, options));
}

export function clearCookie(res, name, options = {}) {
  setCookie(res, name, '', { ...options, maxAge: 0 });
}

export function signPayload(payload, secret) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

export function verifyPayload(value, secret) {
  if (!value || !value.includes('.')) return null;
  const [encoded, signature] = value.split('.', 2);
  const expected = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  if (!timingSafeEqual(signature, expected)) return null;
  try {
    return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export function removeCookiesFromHeader(header = '', names = []) {
  const blocked = new Set(names);
  const cookies = parseCookies(header);
  const kept = [];
  for (const [name, value] of Object.entries(cookies)) {
    if (!blocked.has(name)) kept.push(`${name}=${encodeURIComponent(value)}`);
  }
  return kept.join('; ');
}

export function mergeCookieHeaders(...headers) {
  return headers.filter(Boolean).join('; ');
}

function timingSafeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}
