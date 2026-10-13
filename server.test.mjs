import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
const port = 30000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${port}`;
let child;
before(async () => {
  const env = {
    ...process.env,
    PORT: String(port),
    KAINO_INTEGRATION_CLIENT_SECRET: 'local-test-only-not-a-real-secret',
  };
  delete env.KAINO_MARKETPLACE_URL;
  delete env.KAINO_INTEGRATION_CLIENT_ID;
  child = spawn(process.execPath, ['server.mjs'], {
    cwd: fileURLToPath(new URL('.', import.meta.url)),
    env,
    stdio: 'ignore',
    windowsHide: true,
  });
  for (let attempt = 0; attempt < 50; attempt++) {
    if (child.exitCode !== null) throw new Error('Test server exited');
    try {
      if ((await fetch(`${base}/health`)).status === 200) return;
    } catch {}
    await delay(100);
  }
  throw new Error('Test server did not start');
});
after(() => child?.kill());
test('health works without active Kaino integration', async () => {
  const response = await fetch(`${base}/health`);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'ok');
});
test('calculator page requires a verified session', async () => {
  for (const path of ['/', '/index.html']) {
    const response = await fetch(`${base}${path}`);
    assert.equal(response.status, 401);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  }
});
test('callback rejects missing and duplicate bridge tokens', async () => {
  for (const path of [
    '/api/kaino/callback',
    '/api/kaino/callback?bridge_token=one&bridge_token=two',
  ]) {
    const response = await fetch(`${base}${path}`, { redirect: 'manual' });
    assert.equal(response.status, 400);
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(response.headers.get('location'), null);
  }
});
test('forged session cookie cannot open the calculator', async () => {
  const response = await fetch(base, {
    headers: { Cookie: 'kaino_session=v1.invalid.invalid.invalid' },
  });
  assert.equal(response.status, 401);
});
test('unknown routes and unsupported methods are denied', async () => {
  assert.equal((await fetch(`${base}/unknown`)).status, 404);
  assert.equal((await fetch(base, { method: 'POST' })).status, 405);
});
