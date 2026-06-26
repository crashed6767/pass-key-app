function qs(selector) {
  return document.querySelector(selector);
}

function setMessage(text, kind = 'info') {
  const box = qs('#message');
  if (!box) return;
  box.textContent = text;
  box.className = `message ${kind}`;
}

async function apiPost(path, body = {}) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'same-origin',
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

async function apiGet(path) {
  const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store' });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

function base64URLStringToBuffer(base64URLString) {
  const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64URLString(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function decodeCreationOptions(options) {
  if (window.PublicKeyCredential?.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(options);
  const publicKey = structuredClone(options);
  publicKey.challenge = base64URLStringToBuffer(publicKey.challenge);
  publicKey.user.id = base64URLStringToBuffer(publicKey.user.id);
  if (Array.isArray(publicKey.excludeCredentials)) {
    publicKey.excludeCredentials = publicKey.excludeCredentials.map((credential) => ({ ...credential, id: base64URLStringToBuffer(credential.id) }));
  }
  return publicKey;
}

function decodeRequestOptions(options) {
  if (window.PublicKeyCredential?.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(options);
  const publicKey = structuredClone(options);
  publicKey.challenge = base64URLStringToBuffer(publicKey.challenge);
  if (Array.isArray(publicKey.allowCredentials)) {
    publicKey.allowCredentials = publicKey.allowCredentials.map((credential) => ({ ...credential, id: base64URLStringToBuffer(credential.id) }));
  }
  return publicKey;
}

function credentialToJSON(credential) {
  if (!credential) throw new Error('No passkey was selected');
  const response = credential.response;
  const json = {
    id: credential.id,
    rawId: bufferToBase64URLString(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    clientExtensionResults: credential.getClientExtensionResults?.() || {},
    response: { clientDataJSON: bufferToBase64URLString(response.clientDataJSON) },
  };
  if (response.attestationObject) {
    json.response.attestationObject = bufferToBase64URLString(response.attestationObject);
    json.response.transports = response.getTransports?.() || [];
  }
  if (response.authenticatorData) {
    json.response.authenticatorData = bufferToBase64URLString(response.authenticatorData);
    json.response.signature = bufferToBase64URLString(response.signature);
    json.response.userHandle = response.userHandle ? bufferToBase64URLString(response.userHandle) : null;
  }
  return json;
}

function requireWebAuthn() {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('This browser does not support passkeys/WebAuthn.');
  }
}

async function login() {
  const button = qs('#login-button');
  button.disabled = true;
  try {
    requireWebAuthn();
    setMessage('Waiting for your passkey…');
    const next = new URL(window.location.href).searchParams.get('next') || '/';
    const options = await apiPost('/passkey/api/authentication/options');
    const credential = await navigator.credentials.get({ publicKey: decodeRequestOptions(options) });
    const result = await apiPost('/passkey/api/authentication/verify', { ...credentialToJSON(credential), next });
    setMessage('Logged in. Opening app…', 'success');
    window.location.href = result.redirect || next || '/';
  } catch (error) {
    setMessage(error.message || String(error), 'error');
  } finally {
    button.disabled = false;
  }
}

async function registerPasskey() {
  const button = qs('#setup-button') || qs('#add-passkey-button');
  button.disabled = true;
  try {
    requireWebAuthn();
    const token = new URL(window.location.href).searchParams.get('token') || undefined;
    setMessage('Creating passkey…');
    const options = await apiPost('/passkey/api/register/options', { token });
    const credential = await navigator.credentials.create({ publicKey: decodeCreationOptions(options) });
    const result = await apiPost('/passkey/api/register/verify', credentialToJSON(credential));
    setMessage('Passkey saved. Opening app…', 'success');
    window.location.href = result.redirect || '/';
  } catch (error) {
    setMessage(error.message || String(error), 'error');
  } finally {
    button.disabled = false;
  }
}

async function populateAccount() {
  try {
    const status = await apiGet('/passkey/api/status');
    qs('#app-name').textContent = status.rpName || 'Pass Key App';
    qs('#account-summary').textContent = `${status.username} · ${status.credentialCount} passkey${status.credentialCount === 1 ? '' : 's'} registered for ${status.rpID}`;
  } catch (error) {
    setMessage(error.message || String(error), 'error');
  }
}

window.addEventListener('DOMContentLoaded', () => {
  const loginButton = qs('#login-button');
  const setupButton = qs('#setup-button');
  const addButton = qs('#add-passkey-button');
  if (loginButton) loginButton.addEventListener('click', login);
  if (setupButton) setupButton.addEventListener('click', registerPasskey);
  if (addButton) addButton.addEventListener('click', registerPasskey);
  if (qs('#account-summary')) populateAccount();
});
