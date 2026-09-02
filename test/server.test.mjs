import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { once } from 'node:events';
import test from 'node:test';

import { solveChallenge } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

import { createBotLab } from '../src/server.mjs';

async function fixture(t, overrides = {}) {
  const server = createBotLab({
    secret: 'a'.repeat(64),
    keySecret: 'b'.repeat(64),
    challengeCost: 2,
    counterMin: 3,
    counterMax: 3,
    trustCloudflare: false,
    ...overrides,
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const { port } = server.address();
  return `http://127.0.0.1:${port}`;
}

async function sessionCookie(base) {
  const response = await fetch(`${base}/api/session`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    issued: true,
    expiresInSeconds: 600,
    storage: 'signed HttpOnly cookie',
  });
  return response.headers.get('set-cookie').split(';')[0];
}

test('health and static responses carry defensive headers', async (t) => {
  const base = await fixture(t);
  const health = await fetch(`${base}/healthz`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: 'ok', storage: 'ephemeral' });
  assert.equal(health.headers.get('x-robots-tag'), 'noindex, nofollow, noarchive');

  const page = await fetch(base);
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.match(page.headers.get('content-security-policy'), /frame-src https:\/\/challenges\.cloudflare\.com/);
  const pageBody = await page.text();
  assert.match(pageBody, /Browser signals and proof of work/);
  assert.match(pageBody, /Compare repeated runs/);
  assert.match(pageBody, /Local security processing/);
  assert.match(pageBody, /Authorised testing boundary/);
  assert.match(pageBody, /This notice is not access control/);
  assert.match(pageBody, /app-v6-2\.js/);

  const protectedDemo = await fetch(`${base}/protected-demo`);
  assert.equal(protectedDemo.status, 200);
  assert.match(await protectedDemo.text(), /Anubis challenge passed/);

  const client = await fetch(`${base}/assets/app-v6-2.js`);
  assert.equal(client.status, 200);
  const clientBody = await client.text();
  assert.match(clientBody, /Full local value/);
  assert.match(clientBody, /Raw value sent to Bot Lab/);
  assert.match(clientBody, /botLabEntryAcknowledged/);
  assert.match(clientBody, /image data hidden in preview/);
});

test('a signed proof verifies once and is then rejected as a replay', async (t) => {
  const base = await fixture(t);
  const challengeResponse = await fetch(`${base}/api/challenge`);
  assert.equal(challengeResponse.status, 200);
  const challenge = await challengeResponse.json();
  assert.match(challenge.signature, /^[a-f0-9]{64}$/);

  const solution = await solveChallenge({ challenge, deriveKey, timeout: 5_000 });
  assert.ok(solution);
  const payload = Buffer.from(JSON.stringify({ challenge, solution })).toString('base64');

  const verified = await fetch(`${base}/api/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ payload }),
  });
  assert.equal(verified.status, 200);
  assert.equal((await verified.json()).verified, true);

  const replay = await fetch(`${base}/api/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ payload }),
  });
  assert.equal(replay.status, 409);
  assert.equal((await replay.json()).verified, false);
});

test('observations are minimized and identifiers are immediately transformed', async (t) => {
  const base = await fixture(t);
  const cookie = await sessionCookie(base);
  const rawSession = 'session-1234567890abcdef';
  const rawVisitor = '0123456789abcdef0123456789abcdef';
  const response = await fetch(`${base}/api/observe`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({
      sessionId: rawSession,
      visitorId: rawVisitor,
      componentCount: 41,
      collectionMs: 187,
      webdriver: false,
      touchPoints: 2,
      viewport: '1440x900',
      context: 'ordinary',
      interaction: { pageAgeMs: 500, pointerEvents: 1, keyEvents: 0 },
    }),
  });
  assert.equal(response.status, 201);
  const rawResponse = await response.text();
  assert.doesNotMatch(rawResponse, new RegExp(rawSession));
  assert.doesNotMatch(rawResponse, new RegExp(rawVisitor));
  const body = JSON.parse(rawResponse);
  assert.match(body.observation.fingerprintTag, /^[a-f0-9]{16}$/);
  assert.equal(body.retentionSeconds, 900);

  const stats = await fetch(`${base}/api/stats`).then((result) => result.json());
  assert.equal(stats.activeObservations, 1);
  assert.equal(stats.observations, 1);
});

test('comparison reports are aggregate, thresholded and use bounded context labels', async (t) => {
  const base = await fixture(t);
  const cookie = await sessionCookie(base);
  const rawSession = 'report-session-1234567890';
  const rawVisitor = 'abcdefabcdefabcdefabcdefabcdefab';
  const observe = (context, sessionId = rawSession, visitorId = rawVisitor) => fetch(`${base}/api/observe`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({
      sessionId,
      visitorId,
      componentCount: 42,
      collectionMs: 120,
      webdriver: context === 'authorised-automation',
      touchPoints: 0,
      viewport: '1280x720',
      context,
      interaction: { pageAgeMs: 500, pointerEvents: 1, keyEvents: 0 },
    }),
  });

  assert.equal((await observe('ordinary')).status, 201);
  assert.equal((await observe('ordinary')).status, 201);
  assert.equal((await observe('authorised-automation', 'automation-session-123456', '1234567890abcdef1234567890abcdef')).status, 201);
  assert.equal((await observe('invented-context', 'unlabelled-session-123456', 'fedcbafedcbafedcbafedcbafedcbafe')).status, 201);

  const response = await fetch(`${base}/api/report`);
  assert.equal(response.status, 200);
  const rawReport = await response.text();
  assert.doesNotMatch(rawReport, new RegExp(rawSession));
  assert.doesNotMatch(rawReport, new RegExp(rawVisitor));
  const report = JSON.parse(rawReport);
  const ordinary = report.contexts.find((context) => context.context === 'ordinary');
  assert.equal(ordinary.ready, true);
  assert.equal(ordinary.observations, 2);
  assert.equal(ordinary.distinctFingerprintTags, 1);
  assert.equal(ordinary.repeatStabilityPercent, 100);
  const automation = report.contexts.find((context) => context.context === 'authorised-automation');
  assert.deepEqual(automation, {
    context: 'authorised-automation',
    observations: 1,
    ready: false,
    minimumObservations: 2,
  });
  assert.equal(report.contexts.find((context) => context.context === 'unlabelled').observations, 1);
});

test('shadow scoring is transparent, context-independent and never enforced', async (t) => {
  const base = await fixture(t);
  const observe = async ({ context, visitorId, cookie, webdriver = false }) => {
    const response = await fetch(`${base}/api/observe`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'accept-language': 'en-GB',
        'sec-fetch-site': 'same-origin',
        cookie,
      },
      body: JSON.stringify({
        visitorId,
        componentCount: 42,
        collectionMs: 100,
        webdriver,
        touchPoints: 0,
        viewport: '1280x720',
        context,
        interaction: { pageAgeMs: 500, pointerEvents: 1, keyEvents: 0 },
      }),
    });
    assert.equal(response.status, 201);
    return response.json();
  };

  const ordinaryCookie = await sessionCookie(base);
  const automationCookie = await sessionCookie(base);
  const ordinary = await observe({
    context: 'ordinary',
    cookie: ordinaryCookie,
    visitorId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  });
  const automation = await observe({
    context: 'authorised-automation',
    cookie: automationCookie,
    visitorId: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  });
  assert.equal(ordinary.observation.shadowScore, automation.observation.shadowScore);
  assert.deepEqual(ordinary.observation.shadowRules, []);

  await observe({
    context: 'ordinary',
    cookie: ordinaryCookie,
    visitorId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  });
  const webdriver = await observe({
    context: 'authorised-automation',
    cookie: automationCookie,
    visitorId: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    webdriver: true,
  });
  assert.equal(webdriver.observation.shadowScore, 40);
  assert.deepEqual(webdriver.observation.shadowRules, ['webdriver-reported']);

  const report = await fetch(`${base}/api/shadow-report`).then((response) => response.json());
  assert.equal(report.mode, 'shadow');
  assert.equal(report.enforcement, false);
  assert.equal(report.reviewThreshold, 40);
  assert.equal(report.evaluation.automationRecallPercent, 50);
  assert.equal(report.evaluation.falsePositiveRatePercent, 0);
  assert.match(report.interpretation, /never as a score input/);
});

test('client-hint coherence retains mismatch booleans only and has zero shadow weight', async (t) => {
  const base = await fixture(t);
  const cookie = await sessionCookie(base);
  const response = await fetch(`${base}/api/observe`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'accept-language': 'en-GB',
      'sec-fetch-site': 'same-origin',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/152.0',
      'sec-ch-ua-platform': '"macOS"',
      'sec-ch-ua-mobile': '?1',
      cookie,
    },
    body: JSON.stringify({
      visitorId: 'dddddddddddddddddddddddddddddddd',
      componentCount: 42,
      collectionMs: 100,
      webdriver: false,
      touchPoints: 0,
      viewport: '1280x720',
      context: 'authorised-automation',
      botd: { available: true, bot: true, kind: 'headless_chrome' },
      interaction: { pageAgeMs: 500, pointerEvents: 1, keyEvents: 0 },
    }),
  });
  assert.equal(response.status, 201);
  const text = await response.text();
  const observation = JSON.parse(text).observation;
  assert.equal(observation.shadowScore, 0);
  assert.deepEqual(observation.shadowRules, [
    'client-hint-platform-mismatch',
    'client-hint-mobile-mismatch',
  ]);
  assert.deepEqual(observation.requestEvidence, {
    userAgentPresent: true,
    acceptLanguagePresent: true,
    fetchSite: 'same-origin',
    platformHintMismatch: true,
    mobileHintMismatch: true,
  });
  assert.doesNotMatch(text, /Windows NT|macOS/);

  const report = await fetch(`${base}/api/shadow-report`).then((result) => result.json());
  assert.equal(report.weights['client-hint-platform-mismatch'], 0);
  assert.equal(report.weights['client-hint-mobile-mismatch'], 0);
  assert.equal(report.enforcement, false);
});

test('open-source BotD is bounded, aggregate and evaluated separately from the custom score', async (t) => {
  const base = await fixture(t);
  const ordinaryCookie = await sessionCookie(base);
  const automationCookie = await sessionCookie(base);
  const observe = async ({ context, cookie, visitorId, botd }) => {
    const response = await fetch(`${base}/api/observe`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'accept-language': 'en-GB',
        'sec-fetch-site': 'same-origin',
        cookie,
      },
      body: JSON.stringify({
        visitorId,
        componentCount: 42,
        collectionMs: 100,
        webdriver: false,
        touchPoints: 0,
        viewport: '1280x720',
        context,
        botd,
        interaction: { pageAgeMs: 500, pointerEvents: 1, keyEvents: 0 },
      }),
    });
    assert.equal(response.status, 201);
    return response.json();
  };

  await observe({
    context: 'ordinary', cookie: ordinaryCookie,
    visitorId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    botd: { available: true, bot: false, kind: null },
  });
  await observe({
    context: 'ordinary', cookie: ordinaryCookie,
    visitorId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    botd: { available: true, bot: false, kind: null },
  });
  const detected = await observe({
    context: 'authorised-automation', cookie: automationCookie,
    visitorId: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    botd: { available: true, bot: true, kind: 'headless_chrome' },
  });
  assert.deepEqual(detected.observation.botd, { available: true, bot: true, kind: 'headless_chrome' });
  const bounded = await observe({
    context: 'authorised-automation', cookie: automationCookie,
    visitorId: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    botd: { available: true, bot: true, kind: '<unexpected>' },
  });
  assert.equal(bounded.observation.botd.kind, 'unknown');
  assert.equal(bounded.observation.shadowScore, 0);

  const comparison = await fetch(`${base}/api/report`).then((response) => response.json());
  const automation = comparison.contexts.find((context) => context.context === 'authorised-automation');
  assert.equal(automation.botdAvailable, 2);
  assert.equal(automation.botdDetected, 2);

  const shadow = await fetch(`${base}/api/shadow-report`).then((response) => response.json());
  assert.equal(shadow.evaluation.automationRecallPercent, 0);
  assert.deepEqual(shadow.evaluation.openSourceBotd, {
    labelledAutomation: 2,
    automationDetected: 2,
    automationRecallPercent: 100,
    labelledNonAutomation: 2,
    nonAutomationDetected: 0,
    falsePositiveRatePercent: 0,
  });
  assert.equal(shadow.enforcement, false);
});

test('known-good automation requires a fresh non-replayable HMAC proof and never changes enforcement', async (t) => {
  const verifiedAgentSecret = 'v'.repeat(64);
  const base = await fixture(t, { verifiedAgentSecret });
  const cookie = await sessionCookie(base);
  const timestamp = String(Date.now());
  const nonce = 'a'.repeat(32);
  const agent = 'bot-lab-playwright';
  const signature = createHmac('sha256', verifiedAgentSecret)
    .update(`${agent}:${timestamp}:${nonce}:POST:/api/observe`)
    .digest('hex');
  const headers = {
    'content-type': 'application/json',
    cookie,
    'x-bot-lab-agent': agent,
    'x-bot-lab-agent-timestamp': timestamp,
    'x-bot-lab-agent-nonce': nonce,
    'x-bot-lab-agent-signature': signature,
  };
  const body = JSON.stringify({
    visitorId: 'cccccccccccccccccccccccccccccccc',
    componentCount: 42,
    collectionMs: 100,
    webdriver: true,
    viewport: '1280x720',
    context: 'authorised-automation',
    botd: { available: true, bot: true, kind: 'headless_chrome' },
    interaction: { pageAgeMs: 500, pointerEvents: 1, keyEvents: 0 },
  });

  const accepted = await fetch(`${base}/api/observe`, { method: 'POST', headers, body });
  assert.equal(accepted.status, 201);
  const acceptedText = await accepted.text();
  assert.equal(JSON.parse(acceptedText).observation.verifiedAgent, true);
  assert.doesNotMatch(acceptedText, new RegExp(signature));

  const replay = await fetch(`${base}/api/observe`, { method: 'POST', headers, body });
  assert.equal(replay.status, 201);
  assert.equal((await replay.json()).observation.verifiedAgent, false);

  const report = await fetch(`${base}/api/report`).then((response) => response.json());
  const automation = report.contexts.find((context) => context.context === 'authorised-automation');
  assert.equal(automation.verifiedAgentObservations, 1);
  const shadow = await fetch(`${base}/api/shadow-report`).then((response) => response.json());
  assert.equal(shadow.evaluation.verifiedKnownGoodAutomation, 1);
  assert.equal(shadow.enforcement, false);
});

test('unknown paths and oversized claims fail closed', async (t) => {
  const base = await fixture(t);
  const cookie = await sessionCookie(base);
  assert.equal((await fetch(`${base}/missing`)).status, 404);

  const invalid = await fetch(`${base}/api/observe`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ sessionId: 'short', visitorId: 'wrong' }),
  });
  assert.equal(invalid.status, 400);
});

test('observation sessions require an untampered short-lived server cookie', async (t) => {
  const base = await fixture(t);
  const body = JSON.stringify({
    visitorId: '0123456789abcdef0123456789abcdef',
    componentCount: 42,
    collectionMs: 10,
    context: 'ordinary',
    viewport: '1280x720',
    interaction: { pageAgeMs: 500, pointerEvents: 1, keyEvents: 0 },
  });
  const missing = await fetch(`${base}/api/observe`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body,
  });
  assert.equal(missing.status, 401);
  const cookie = await sessionCookie(base);
  const tampered = await fetch(`${base}/api/observe`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: `${cookie}x` },
    body,
  });
  assert.equal(tampered.status, 401);
});

test('Turnstile comparison verifies hostname and action server-side without enforcement', async (t) => {
  const server = createBotLab({
    secret: 'a'.repeat(64),
    keySecret: 'b'.repeat(64),
    challengeCost: 2,
    counterMin: 3,
    counterMax: 3,
    turnstileSitekey: 'public-test-sitekey',
    turnstileSecretKey: 'private-test-secret',
    turnstileExpectedHostname: 'botlab.tensorhost.com',
    turnstileVerify: async () => ({
      success: true,
      hostname: 'botlab.tensorhost.com',
      action: 'bot-lab-compare',
      'error-codes': [],
    }),
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const config = await fetch(`${base}/api/config`).then((response) => response.json());
  assert.equal(config.turnstile.enabled, true);
  assert.equal(config.turnstile.sitekey, 'public-test-sitekey');
  assert.doesNotMatch(JSON.stringify(config), /private-test-secret/);
  const cookie = await sessionCookie(base);
  const verified = await fetch(`${base}/api/turnstile/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ token: 'valid-turnstile-token' }),
  });
  assert.equal(verified.status, 200);
  const result = await verified.json();
  assert.deepEqual({ ...result, validationMs: 0 }, {
    verified: true,
    hostnameMatched: true,
    actionMatched: true,
    validationMs: 0,
    errors: [],
    enforcement: false,
  });
  assert.ok(Number.isInteger(result.validationMs));
  assert.ok(result.validationMs >= 0 && result.validationMs <= 100);
});

test('session issuance rate limit fails closed with retry guidance', async (t) => {
  const base = await fixture(t);
  for (let index = 0; index < 30; index += 1) {
    assert.equal((await fetch(`${base}/api/session`)).status, 200);
  }
  const limited = await fetch(`${base}/api/session`);
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('retry-after'), '60');
});

test('a naive headerless zero-interaction script crosses only the shadow review threshold', async (t) => {
  const base = await fixture(t);
  const cookie = await sessionCookie(base);
  const body = JSON.stringify({
    visitorId: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    componentCount: 42,
    collectionMs: 1,
    webdriver: false,
    touchPoints: 0,
    context: 'authorised-automation',
    viewport: '1280x720',
    interaction: { pageAgeMs: 0, pointerEvents: 0, keyEvents: 0 },
  });
  for (let index = 0; index < 2; index += 1) {
    const response = await fetch(`${base}/api/observe`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': '',
        'accept-language': '',
        cookie,
      },
      body,
    });
    assert.equal(response.status, 201);
    const observation = (await response.json()).observation;
    assert.equal(observation.shadowScore, 65);
    assert.deepEqual(observation.shadowRules, [
      'missing-user-agent',
      'missing-accept-language',
      'missing-fetch-metadata',
      'implausibly-fast-action',
      'no-interaction-before-run',
    ]);
  }
  const report = await fetch(`${base}/api/shadow-report`).then((response) => response.json());
  const automation = report.contexts.find((context) => context.context === 'authorised-automation');
  assert.equal(automation.meanScore, 65);
  assert.equal(automation.wouldReview, 2);
  assert.equal(report.evaluation.automationRecallPercent, 100);
  assert.equal(report.enforcement, false);
});

async function turnstileTransportFixture(t, turnstileFetch) {
  const server = createBotLab({
    secret: 'a'.repeat(64),
    keySecret: 'b'.repeat(64),
    challengeCost: 2,
    counterMin: 3,
    counterMax: 3,
    turnstileSitekey: 'public-test-sitekey',
    turnstileSecretKey: 'private-test-secret',
    turnstileExpectedHostname: 'botlab.tensorhost.com',
    turnstileFetch,
    turnstileRetryDelayMs: 0,
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, cookie: await sessionCookie(base) };
}

async function submitTurnstile(base, cookie) {
  return fetch(`${base}/api/turnstile/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ token: 'transport-test-token' }),
  });
}

test('Turnstile transport retries once with the same idempotency key', async (t) => {
  const idempotencyKeys = [];
  let attempts = 0;
  const { base, cookie } = await turnstileTransportFixture(t, async (_url, options) => {
    attempts += 1;
    idempotencyKeys.push(new URLSearchParams(options.body).get('idempotency_key'));
    if (attempts === 1) throw new TypeError('synthetic transport timeout');
    return new Response(JSON.stringify({
      success: true,
      hostname: 'botlab.tensorhost.com',
      action: 'bot-lab-compare',
      'error-codes': [],
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  const response = await submitTurnstile(base, cookie);
  assert.equal(response.status, 200);
  assert.equal(attempts, 2);
  assert.equal(idempotencyKeys[0], idempotencyKeys[1]);
});

test('Turnstile invalid-token responses are not retried', async (t) => {
  let attempts = 0;
  const { base, cookie } = await turnstileTransportFixture(t, async () => {
    attempts += 1;
    return new Response(JSON.stringify({
      success: false,
      'error-codes': ['invalid-input-response'],
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  const response = await submitTurnstile(base, cookie);
  assert.equal(response.status, 400);
  assert.equal(attempts, 1);
  assert.deepEqual((await response.json()).errors, ['invalid-input-response']);
});

test('Turnstile transport exhaustion returns a safe retryable-service error', async (t) => {
  let attempts = 0;
  const { base, cookie } = await turnstileTransportFixture(t, async () => {
    attempts += 1;
    throw new TypeError('synthetic transport timeout');
  });
  const response = await submitTurnstile(base, cookie);
  assert.equal(response.status, 502);
  assert.equal(attempts, 2);
  assert.deepEqual(await response.json(), { error: 'Turnstile validation temporarily unavailable' });
});
