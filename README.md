# Pass Key App

A reusable **passkey/WebAuthn login gate** for programs that do **not** support passkeys natively.

It sits in front of an existing web app as a reverse proxy:

```text
browser
  ↓ passkey login
Pass Key App
  ↓ authenticated reverse proxy
existing app
```

This lets you add a **"Log in with passkey"** button to apps that only have old auth, weak auth, or no auth at all.

## What it does

- Adds WebAuthn/passkey registration and login.
- Stores only public keys on the server; private keys stay in the user's password manager, device, or hardware key.
- Proxies authenticated traffic to an upstream app.
- Can optionally log into the upstream app server-side and inject its auth cookie/header.
- Works well behind Cloudflare Tunnel, Caddy, nginx, Traefik, or any HTTPS reverse proxy.

## What it does not do

- It does not patch the upstream app's source code.
- It does not create per-user permissions inside the upstream app.
- It does not magically fix apps that depend on unusual browser-side auth flows; some apps may need header/cookie/referer tuning.

## Quick start

```bash
git clone https://github.com/crashed6767/pass-key-app.git
cd pass-key-app
cp .env.example .env
node scripts/generate-secrets.mjs
```

Put the generated `SESSION_SECRET` and `BOOTSTRAP_TOKEN` into `.env`, then set:

```dotenv
PUBLIC_ORIGIN=https://your-app.example.com
RP_ID=your-app.example.com
RP_NAME=Your App
UPSTREAM_ORIGIN=http://your-existing-app:8080
UPSTREAM_AUTH_MODE=none
```

Start it:

```bash
docker compose -f docker-compose.example.yml up -d --build
```

Then open the one-time setup URL:

```text
https://your-app.example.com/passkey/setup?token=<BOOTSTRAP_TOKEN>
```

Create your first passkey. After that, normal login is:

```text
https://your-app.example.com/
```

## Upstream auth modes

### 1. `none`

Use this when the upstream app has no auth, or when you only want Pass Key App to gate the public route.

```dotenv
UPSTREAM_AUTH_MODE=none
UPSTREAM_ORIGIN=http://app:8080
```

### 2. `basic`

Inject HTTP Basic Auth upstream.

```dotenv
UPSTREAM_AUTH_MODE=basic
UPSTREAM_BASIC_USERNAME=admin
UPSTREAM_BASIC_PASSWORD=change-me
```

### 3. `header`

Inject one static auth header upstream.

```dotenv
UPSTREAM_AUTH_MODE=header
UPSTREAM_AUTH_HEADER_NAME=Authorization
UPSTREAM_AUTH_HEADER_VALUE=Bearer change-me
```

### 4. `form`

Log into the upstream app from the proxy, cache the upstream `Set-Cookie`, and inject it into proxied requests.

```dotenv
UPSTREAM_AUTH_MODE=form
UPSTREAM_LOGIN_PATH=/api/v2/auth/login
UPSTREAM_LOGIN_METHOD=POST
UPSTREAM_LOGIN_CONTENT_TYPE=form
UPSTREAM_LOGIN_USERNAME_FIELD=username
UPSTREAM_LOGIN_PASSWORD_FIELD=password
UPSTREAM_LOGIN_USERNAME=admin
UPSTREAM_LOGIN_PASSWORD=change-me
UPSTREAM_LOGIN_SUCCESS_STATUS=200,204
UPSTREAM_SESSION_COOKIE_REGEX=^QBT_SID
UPSTREAM_SESSION_TTL_SECONDS=3000
```

If an app's UI loads but its API calls return `401`, keep this enabled:

```dotenv
REWRITE_UPSTREAM_ORIGIN=true
```

That rewrites browser `Origin`/`Referer` headers to match the upstream app before proxying, which helps apps with CSRF checks.

## Cloudflare Tunnel example

Route the public hostname to the proxy, not the upstream app:

```yaml
ingress:
  - hostname: app-random-subdomain.example.com
    service: http://127.0.0.1:8091
  - service: http_status:404
```

Validate and restart cloudflared:

```bash
cloudflared tunnel --config ~/.cloudflared/config.yml ingress validate
launchctl kickstart -k "gui/$(id -u)/com.cloudflare.cloudflared"
```

## Adding more passkeys

After you are logged in:

```text
https://your-app.example.com/passkey/account
```

Register at least two passkeys so you have a backup device/security key.

## Recovery if you lose every passkey

1. Stop the proxy.
2. Back up `DATA_DIR/state.json`.
3. Move/delete `DATA_DIR/state.json`.
4. Put a new `BOOTSTRAP_TOKEN` in `.env`.
5. Restart and open `/passkey/setup?token=<new token>`.

## Security notes

- Use HTTPS for the public URL. Browsers require secure context for passkeys, except localhost.
- Keep `.env` and `DATA_DIR/state.json` private.
- Do not publish bootstrap tokens.
- Prefer random public hostnames for admin apps.
- This is an edge auth gate; it does not replace careful upstream app hardening.

## Development

```bash
npm install
npm test
npm run check
```
