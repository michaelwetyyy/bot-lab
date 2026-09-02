import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

const base = new URL(process.env.BOT_LAB_PUBLIC_BASE || 'https://botlab.tensorhost.com/');
if (base.protocol !== 'https:') throw new Error('public smoke target must use HTTPS');

const endpoint = (pathname) => new URL(pathname, base);
const page = await fetch(endpoint('/'), { cache: 'no-store' });
assert.equal(page.status, 200);
assert.match(page.headers.get('content-security-policy') || '', /challenges\.cloudflare\.com/);

const config = await fetch(endpoint('/api/config'), { cache: 'no-store' }).then((response) => response.json());
assert.equal(config.turnstile.enabled, true);
assert.equal(config.turnstile.action, 'bot-lab-compare');

const session = await fetch(endpoint('/api/session'), { cache: 'no-store' });
assert.equal(session.status, 200);
const cookieHeader = session.headers.get('set-cookie') || '';
assert.match(cookieHeader, /HttpOnly/i);
assert.match(cookieHeader, /Secure/i);
assert.match(cookieHeader, /SameSite=Strict/i);
const cookie = cookieHeader.split(';')[0];
assert.ok(cookie.startsWith('bot_lab_session='));

const syntheticObservation = JSON.stringify({
  visitorId: randomBytes(16).toString('hex'),
  componentCount: 42,
  collectionMs: 1,
  webdriver: false,
  touchPoints: 0,
  context: 'unlabelled',
  viewport: '1280x720',
  interaction: { pageAgeMs: 0, pointerEvents: 0, keyEvents: 0 },
});
const withoutSession = await fetch(endpoint('/api/observe'), {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: syntheticObservation,
});
assert.equal(withoutSession.status, 401);

const tamperedSession = await fetch(endpoint('/api/observe'), {
  method: 'POST',
  headers: { 'content-type': 'application/json', cookie: `${cookie}x` },
  body: syntheticObservation,
});
assert.equal(tamperedSession.status, 401);

const forgedTurnstile = await fetch(endpoint('/api/turnstile/verify'), {
  method: 'POST',
  headers: { 'content-type': 'application/json', cookie },
  body: JSON.stringify({ token: 'FORGED.SYNTHETIC.TOKEN' }),
});
assert.equal(forgedTurnstile.status, 400);
const forgedResult = await forgedTurnstile.json();
assert.equal(forgedResult.verified, false);
assert.equal(forgedResult.enforcement, false);

const health = await fetch(endpoint('/healthz'), { cache: 'no-store' });
assert.equal(health.status, 200);

console.log(JSON.stringify({
  target: base.hostname,
  page: page.status,
  turnstileConfigured: config.turnstile.enabled,
  secureSessionCookie: true,
  unsignedObservationRejected: withoutSession.status,
  tamperedSessionRejected: tamperedSession.status,
  forgedTurnstileRejected: forgedTurnstile.status,
  enforcement: forgedResult.enforcement,
  health: health.status,
}));
