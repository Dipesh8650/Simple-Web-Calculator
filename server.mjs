import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { createKainoServerClient } from '@kainostore/sdk/server';
const APP_ID = 'd285e05b-f8f1-442b-934e-fc79dcb190ae';
const COOKIE = 'kaino_session';
const page = await readFile(new URL('./index.html', import.meta.url));
let client;
function kaino() {
  return client ??= createKainoServerClient({
    marketplaceUrl: process.env.KAINO_MARKETPLACE_URL,
    clientId: process.env.KAINO_INTEGRATION_CLIENT_ID,
    clientSecret: process.env.KAINO_INTEGRATION_CLIENT_SECRET,
    assertionIssuer: process.env.KAINO_INTEGRATED_SESSION_ISSUER ?? 'kaino-marketplace',
  });
}
function cookieKey() {
  const secret = process.env.KAINO_INTEGRATION_CLIENT_SECRET;
  if (!secret) throw new Error('Managed integration binding unavailable');
  return Buffer.from(hkdfSync('sha256', secret, APP_ID, 'calculator-cookie-v1', 32));
}
function seal(session) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', cookieKey(), iv);
  cipher.setAAD(Buffer.from(APP_ID));
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(session), 'utf8'),
    cipher.final(),
  ]);
  return ['v1', iv.toString('base64url'), encrypted.toString('base64url'),
    cipher.getAuthTag().toString('base64url')].join('.');
}
function unseal(value) {
  const [version, iv, encrypted, tag, extra] = value.split('.');
  if (version !== 'v1' || !iv || !encrypted || !tag || extra !== undefined) {
    throw new Error('Invalid session cookie');
  }
  const decipher = createDecipheriv('aes-256-gcm', cookieKey(), Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(APP_ID));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(encrypted, 'base64url')),
    decipher.final(),
  ]).toString('utf8'));
}
function sessionCookie(req) {
  const matches = (req.headers.cookie ?? '').split(';').map(x => x.trim())
    .filter(x => x.startsWith(`${COOKIE}=`));
  return matches.length === 1 ? matches[0].slice(COOKIE.length + 1) : null;
}
function reply(res, status, message, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', ...headers });
  res.end(message);
}
async function handle(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') return reply(res, 405, 'Method not allowed');
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/health') return reply(res, 200, 'ok');
  if (url.pathname === '/api/kaino/callback') {
    const tokens = url.searchParams.getAll('bridge_token');
    if (tokens.length !== 1 || !tokens[0]) {
      return reply(res, 400, 'Start a new launch from Kaino');
    }
    try {
      const integrated = await kaino().createIntegratedSession(tokens[0]);
      if (integrated.appId !== APP_ID ||
          integrated.integrationStatus !== 'active' ||
          integrated.entitlementStatus !== 'active' ||
          integrated.verifiedSubject !== integrated.appScopedUserId) {
        throw new Error('Launch is not authorized for this app');
      }
      const expires = Date.parse(integrated.assertionExpiresAt);
      const maxAge = Math.floor((expires - Date.now()) / 1000);
      if (!Number.isFinite(expires) || maxAge < 1) throw new Error('Expired assertion');
      const { assertionPayload, verifiedIssuer, verifiedAudience, verifiedSubject,
        ...storedSession } = integrated;
      const sealed = seal(storedSession);
      if (sealed.length > 3800) throw new Error('Session exceeds cookie size');
      res.writeHead(303, {
        Location: '/',
        'Set-Cookie': `${COOKIE}=${sealed}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`,
      });
      return res.end();
    } catch {
      return reply(res, 400, 'Start a new launch from Kaino', {
        'Set-Cookie': `${COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`,
      });
    }
  }
  if (url.pathname !== '/' && url.pathname !== '/index.html') {
    return reply(res, 404, 'Not found');
  }
  try {
    const value = sessionCookie(req);
    if (!value) throw new Error('Missing session');
    const session = unseal(value);
    const expires = Date.parse(session.assertionExpiresAt);
    if (session.appId !== APP_ID ||
        session.integrationStatus !== 'active' ||
        session.entitlementStatus !== 'active' ||
        !Number.isFinite(expires) || Date.now() >= expires) {
      throw new Error('Invalid session');
    }
    const verified = await kaino().verifySessionAssertion(session);
    if (verified.subject !== session.appScopedUserId) throw new Error('Wrong subject');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(page);
  } catch {
    return reply(res, 401, 'Launch this calculator from Kaino to sign in', {
      'Set-Cookie': `${COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`,
    });
  }
}
const port = Number(process.env.PORT ?? 3000);
http.createServer((req, res) => {
  handle(req, res).catch(() => reply(res, 500, 'Server error'));
}).listen(port, '0.0.0.0');
