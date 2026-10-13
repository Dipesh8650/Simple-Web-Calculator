import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
const APP_ID = 'd285e05b-f8f1-442b-934e-fc79dcb190ae';
const OTHER_APP = '11111111-1111-4111-8111-111111111111';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'local-test-key', alg: 'RS256', use: 'sig' };
const consumed = new Set();
let fixture;
let app;
let appUrl;
function jwt(payload) {
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' })}.${encode(payload)}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}
function bridgeSession(token) {
  const now = Math.floor(Date.now() / 1000);
  const appId = token === 'wrong-app' ? OTHER_APP : APP_ID;
  const expires = token === 'expired' ? now - 30 : now + 120;
  return {
    appId,
    appSlug: 'simple-web-calculator',
    appScopedUserId: 'fixture-user',
    entitlementId: randomUUID(),
    entitlementStatus: 'active',
    integrationStatus: 'active',
    sessionAssertion: jwt({
      iss: 'kaino-marketplace',
      aud: `integrated-app:${appId}`,
      sub: token === 'wrong-subject' ? 'someone-else' : 'fixture-user',
      iat: now - 60,
      exp: expires,
    }),
    issuedAt: new Date((now - 60) * 1000).toISOString(),
    assertionExpiresAt: new Date(expires * 1000).toISOString(),
  };
}
function json(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(value));
}
async function freePort() {
  const server = http.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
before(async () => {
  fixture = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/api/integrations/assertion-jwks') {
      return json(res, 200, { keys: [jwk] });
    }
    if (req.method === 'POST' && req.url === '/api/integrations/bridge-session') {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const token = JSON.parse(raw).bridgeToken;
      if (consumed.has(token)) {
        return json(res, 409, {
          error: 'Bridge token already consumed',
          replayAction: 'request-new-bridge-token',
        });
      }
      if (!['valid', 'wrong-app', 'wrong-subject', 'expired'].includes(token)) {
        return json(res, 401, {
          error: 'Invalid or expired bridge token',
          renewalAction: 'request-new-bridge-token',
        });
      }
      consumed.add(token);
      return json(res, 200, bridgeSession(token));
    }
    return json(res, 404, { error: 'Not found' });
  });
  await new Promise(resolve => fixture.listen(0, '127.0.0.1', resolve));
  const port = await freePort();
  appUrl = `http://127.0.0.1:${port}`;
  app = spawn(process.execPath, ['server.mjs'], {
    cwd: fileURLToPath(new URL('.', import.meta.url)),
    env: {
      ...process.env,
      PORT: String(port),
      KAINO_MARKETPLACE_URL: `http://127.0.0.1:${fixture.address().port}`,
      KAINO_INTEGRATION_CLIENT_ID: 'local-fixture-client',
      KAINO_INTEGRATION_CLIENT_SECRET: 'local-fixture-secret-not-production',
    },
    stdio: 'ignore',
    windowsHide: true,
  });
  for (let attempt = 0; attempt < 50; attempt++) {
    if (app.exitCode !== null) throw new Error('Calculator server exited');
    try {
      if ((await fetch(`${appUrl}/health`)).status === 200) return;
    } catch {}
    await delay(100);
  }
  throw new Error('Calculator server did not start');
});
after(async () => {
  app?.kill();
  fixture?.closeAllConnections();
  if (fixture) await new Promise(resolve => fixture.close(resolve));
});
async function callback(token) {
  return fetch(`${appUrl}/api/kaino/callback?bridge_token=${token}`, {
    redirect: 'manual',
  });
}
test('signed launch grants a short-lived session and serves the calculator', async () => {
  const response = await callback('valid');
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), '/');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  const setCookie = response.headers.get('set-cookie');
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /SameSite=Lax/);
  const page = await fetch(appUrl, { headers: { Cookie: setCookie.split(';')[0] } });
  assert.equal(page.status, 200);
  assert.match(await page.text(), /calculator/i);
});
test('a consumed bridge token cannot create a second session', async () => {
  const response = await callback('valid');
  assert.equal(response.status, 400);
  assert.equal(response.headers.get('location'), null);
});
test('wrong-app, wrong-subject and expired assertions are rejected', async () => {
  for (const token of ['wrong-app', 'wrong-subject', 'expired']) {
    const response = await callback(token);
    assert.equal(response.status, 400, token);
    assert.equal(response.headers.get('location'), null);
  }
});
