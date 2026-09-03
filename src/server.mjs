import { createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createChallenge, verifySolution } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

const ROOT = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const PUBLIC = path.join(ROOT, 'public');
const MAX_BODY_BYTES = 32 * 1024;
const OBSERVATION_TTL_MS = 15 * 60 * 1000;
const MAX_OBSERVATIONS = 500;
const MAX_ISSUED_CHALLENGES = 2_000;
const MAX_RATE_BUCKETS = 4_096;
const MAX_VERIFIED_AGENT_NONCES = 2_048;
const VERIFIED_AGENT_WINDOW_MS = 60_000;
const SESSION_TTL_MS = 10 * 60 * 1000;
const REPORT_MIN_OBSERVATIONS = 2;
const EXPERIMENT_CONTEXTS = ['ordinary', 'private', 'authorised-automation', 'unlabelled'];
const BOTD_KINDS = new Set([
  'awesomium', 'cef', 'cefsharp', 'coachjs', 'electron', 'fminer', 'geb', 'nightmarejs',
  'phantomas', 'phantomjs', 'rhino', 'selenium', 'sequentum', 'slimerjs', 'webdriverio',
  'webdriver', 'headless_chrome', 'unknown',
]);
const SHADOW_REVIEW_THRESHOLD = 40;
const SHADOW_RULES = {
  'webdriver-reported': 40,
  'same-viewport-tag-drift': 35,
  'atypical-signal-count': 15,
  'small-viewport-no-touch': 5,
  'missing-user-agent': 20,
  'missing-accept-language': 15,
  'missing-fetch-metadata': 10,
  'cross-site-observation': 20,
  'implausibly-fast-action': 10,
  'no-interaction-before-run': 10,
  'client-hint-platform-mismatch': 0,
  'client-hint-mobile-mismatch': 0,
  'client-hint-browser-version-mismatch': 40,
  'client-hint-browser-family-mismatch': 40,
  'navigation-protocol-opaque': 40,
};

const MIME = new Map([
  ['.css', 'text/css; charset=utf-8'],
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.txt', 'text/plain; charset=utf-8'],
]);

function json(response, status, body) {
  response.setHeader('cache-control', 'no-store');
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(body));
}

function error(status, message) {
  return Object.assign(new Error(message), { status });
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw error(413, 'request body too large');
    chunks.push(chunk);
  }
  if (!chunks.length) throw error(400, 'JSON body required');
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw error(400, 'invalid JSON');
  }
}

function decodePayload(payload) {
  if (typeof payload !== 'string' || payload.length < 8 || payload.length > 24_000) {
    throw error(400, 'invalid ALTCHA payload');
  }
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
    if (!parsed?.challenge?.signature || !parsed?.solution) throw new Error('missing fields');
    return parsed;
  } catch {
    throw error(400, 'malformed ALTCHA payload');
  }
}

function safeNumber(value, min, max, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, number)) : fallback;
}

function pruneMap(map, now) {
  for (const [key, value] of map) if (value.expiresAt <= now) map.delete(key);
}

function capMap(map, maximum) {
  while (map.size >= maximum) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) break;
    map.delete(oldest);
  }
}

function fixedWindowAllowed(buckets, key, limit, windowMs, now) {
  if (buckets.size >= MAX_RATE_BUCKETS) {
    for (const [bucketKey, value] of buckets) {
      if (value.resetAt <= now) buckets.delete(bucketKey);
    }
    capMap(buckets, MAX_RATE_BUCKETS);
  }
  const existing = buckets.get(key);
  if (!existing || existing.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  existing.count += 1;
  return existing.count <= limit;
}

function staticPath(pathname) {
  if (pathname === '/') return path.join(PUBLIC, 'index.html');
  const allowed = new Map([
    ['/protected-demo', 'protected-demo.html'],
    ['/app.css', 'app.css'],
    ['/robots.txt', 'robots.txt'],
    ['/assets/app-v6-2.js', 'assets/app-v6-2.js'],
  ]);
  const file = allowed.get(pathname);
  return file ? path.join(PUBLIC, file) : null;
}

function addSecurityHeaders(response) {
  response.setHeader('content-security-policy', [
    "default-src 'none'",
    "script-src 'self' https://challenges.cloudflare.com",
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self' https://challenges.cloudflare.com",
    "img-src 'self' data:",
    "worker-src 'self' blob:",
    "font-src 'self'",
    "frame-src https://challenges.cloudflare.com",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; '));
  response.setHeader('cross-origin-opener-policy', 'same-origin');
  response.setHeader('cross-origin-resource-policy', 'same-origin');
  response.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  response.setHeader('referrer-policy', 'no-referrer');
  response.setHeader('x-content-type-options', 'nosniff');
  response.setHeader('x-frame-options', 'DENY');
  response.setHeader('x-robots-tag', 'noindex, nofollow, noarchive');
}

export function createBotLab(options = {}) {
  const now = options.now || (() => Date.now());
  const secret = options.secret || randomBytes(32).toString('hex');
  const keySecret = options.keySecret || randomBytes(32).toString('hex');
  const challengeCost = options.challengeCost || Number(process.env.ALTCHA_COST || 750);
  const counterMin = options.counterMin ?? 250;
  const counterMax = options.counterMax ?? 900;
  const trustCloudflare = options.trustCloudflare ?? process.env.TRUST_CLOUDFLARE === 'true';
  const turnstileSitekey = options.turnstileSitekey ?? process.env.TURNSTILE_SITEKEY ?? '';
  const turnstileSecretKey = options.turnstileSecretKey ?? process.env.TURNSTILE_SECRET_KEY ?? '';
  const turnstileExpectedHostname = options.turnstileExpectedHostname
    ?? process.env.TURNSTILE_EXPECTED_HOSTNAME
    ?? 'botlab.tensorhost.com';
  const turnstileAction = 'bot-lab-compare';
  const turnstileFetch = options.turnstileFetch || fetch;
  const turnstileRetryDelayMs = options.turnstileRetryDelayMs ?? 250;
  const verifiedAgentSecret = options.verifiedAgentSecret ?? process.env.BOT_LAB_VERIFIED_AGENT_SECRET ?? '';
  const turnstileVerify = options.turnstileVerify || (async (token) => {
    const idempotencyKey = randomUUID();
    const body = new URLSearchParams({
      secret: turnstileSecretKey,
      response: token,
      idempotency_key: idempotencyKey,
    }).toString();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const response = await turnstileFetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body,
          signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) throw error(502, 'Turnstile validation temporarily unavailable');
        return await response.json();
      } catch (caught) {
        if (caught?.status === 502) throw caught;
        if (attempt === 0) {
          await new Promise((resolve) => setTimeout(resolve, turnstileRetryDelayMs));
          continue;
        }
        throw error(502, 'Turnstile validation temporarily unavailable');
      }
    }
    throw error(502, 'Turnstile validation temporarily unavailable');
  });
  const issued = new Map();
  const observations = [];
  const rateBuckets = new Map();
  const verifiedAgentNonces = new Map();
  const counters = {
    challenges: 0,
    verified: 0,
    rejected: 0,
    observations: 0,
    turnstileVerified: 0,
    turnstileRejected: 0,
  };

  const signSessionPayload = (payload) => createHmac('sha256', keySecret)
    .update(`browser-session:${payload}`)
    .digest('base64url');

  const issueSession = (requestNow) => {
    const payload = Buffer.from(JSON.stringify({
      version: 1,
      nonce: randomBytes(16).toString('hex'),
      issuedAt: requestNow,
      expiresAt: requestNow + SESSION_TTL_MS,
    })).toString('base64url');
    return `${payload}.${signSessionPayload(payload)}`;
  };

  const readSession = (request, requestNow) => {
    const cookieHeader = typeof request.headers.cookie === 'string' ? request.headers.cookie : '';
    const token = cookieHeader.split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith('bot_lab_session='))
      ?.slice('bot_lab_session='.length);
    if (!token) throw error(401, 'valid browser session required');
    const [payload, signature, extra] = token.split('.');
    if (!payload || !signature || extra) throw error(401, 'invalid browser session');
    const expected = Buffer.from(signSessionPayload(payload));
    const supplied = Buffer.from(signature);
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) {
      throw error(401, 'invalid browser session');
    }
    try {
      const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      if (session.version !== 1 || typeof session.nonce !== 'string'
        || session.issuedAt > requestNow + 5_000 || session.expiresAt <= requestNow) {
        throw new Error('expired');
      }
      return session;
    } catch {
      throw error(401, 'expired browser session');
    }
  };

  const requestEvidence = (request) => {
    const userAgent = typeof request.headers['user-agent'] === 'string'
      && request.headers['user-agent'].length <= 512
      ? request.headers['user-agent']
      : '';
    const platformHint = typeof request.headers['sec-ch-ua-platform'] === 'string'
      && request.headers['sec-ch-ua-platform'].length <= 32
      ? request.headers['sec-ch-ua-platform'].replaceAll('"', '').trim()
      : '';
    const mobileHint = request.headers['sec-ch-ua-mobile'];
    const browserHint = typeof request.headers['sec-ch-ua'] === 'string'
      && request.headers['sec-ch-ua'].length <= 512
      ? request.headers['sec-ch-ua']
      : '';
    const platformPatterns = [
      ['Android', /Android/i],
      ['Windows', /Windows/i],
      ['macOS', /Macintosh|Mac OS X/i],
      ['iOS', /iPhone|iPad/i],
      ['Chrome OS', /CrOS/i],
      ['Linux', /Linux/i],
    ];
    const userAgentPlatform = platformPatterns.find(([, pattern]) => pattern.test(userAgent))?.[0];
    const userAgentMobile = /Mobile|Android|iPhone|iPad/i.test(userAgent);
    const chromeMajor = /(?:Chrome|CriOS)\/(\d{1,3})\b/i.exec(userAgent)?.[1];
    const hintedChromiumMajors = [...browserHint.matchAll(
      /"(?:Chromium|Google Chrome)"\s*;\s*v="(\d{1,3})(?:[."])/gi,
    )].map((match) => match[1]);
    const claimsFirefox = /(?:Firefox|FxiOS)\/\d/i.test(userAgent);
    const claimsSafari = /Version\/\d[\d.]*\s+(?:Mobile\/\S+\s+)?Safari\/\d/i.test(userAgent)
      && !/(?:Chrome|CriOS|Chromium|EdgA?|EdgiOS|OPR|SamsungBrowser)\//i.test(userAgent);
    return {
      userAgentPresent: userAgent.trim().length > 0,
      acceptLanguagePresent: typeof request.headers['accept-language'] === 'string'
        && request.headers['accept-language'].trim().length > 0,
      fetchSite: typeof request.headers['sec-fetch-site'] === 'string'
        ? request.headers['sec-fetch-site']
        : 'missing',
      platformHintMismatch: Boolean(userAgentPlatform && platformHint && userAgentPlatform !== platformHint),
      mobileHintMismatch: ['?0', '?1'].includes(mobileHint)
        && (mobileHint === '?1') !== userAgentMobile,
      browserVersionHintMismatch: Boolean(
        chromeMajor
        && hintedChromiumMajors.length
        && !hintedChromiumMajors.includes(chromeMajor),
      ),
      browserFamilyHintMismatch: Boolean(
        hintedChromiumMajors.length
        && (claimsFirefox || claimsSafari),
      ),
    };
  };

  const verifyAgentProof = (request, pathname, requestNow) => {
    if (!verifiedAgentSecret) return false;
    const agent = request.headers['x-bot-lab-agent'];
    const timestamp = request.headers['x-bot-lab-agent-timestamp'];
    const nonce = request.headers['x-bot-lab-agent-nonce'];
    const signature = request.headers['x-bot-lab-agent-signature'];
    if (typeof agent !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(agent)
      || typeof timestamp !== 'string' || !/^\d{13}$/.test(timestamp)
      || typeof nonce !== 'string' || !/^[a-f0-9]{24,64}$/.test(nonce)
      || typeof signature !== 'string' || !/^[a-f0-9]{64}$/.test(signature)) return false;
    const issuedAt = Number(timestamp);
    if (!Number.isFinite(issuedAt) || Math.abs(requestNow - issuedAt) > VERIFIED_AGENT_WINDOW_MS) return false;
    pruneMap(verifiedAgentNonces, requestNow);
    if (verifiedAgentNonces.has(nonce)) return false;
    const expected = Buffer.from(createHmac('sha256', verifiedAgentSecret)
      .update(`${agent}:${timestamp}:${nonce}:${request.method}:${pathname}`)
      .digest('hex'));
    const supplied = Buffer.from(signature);
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return false;
    capMap(verifiedAgentNonces, MAX_VERIFIED_AGENT_NONCES);
    verifiedAgentNonces.set(nonce, { expiresAt: requestNow + VERIFIED_AGENT_WINDOW_MS });
    return true;
  };

  const pruneObservations = (requestNow) => {
    while (observations[0]?.expiresAt <= requestNow) observations.shift();
  };

  const experimentReport = (requestNow) => {
    pruneObservations(requestNow);
    const contexts = EXPERIMENT_CONTEXTS.map((context) => {
      const cohort = observations.filter((observation) => observation.context === context);
      if (cohort.length < REPORT_MIN_OBSERVATIONS) {
        return {
          context,
          observations: cohort.length,
          ready: false,
          minimumObservations: REPORT_MIN_OBSERVATIONS,
        };
      }

      const sessions = new Map();
      for (const observation of cohort) {
        const session = sessions.get(observation.sessionTag) || { runs: 0, fingerprints: new Set() };
        session.runs += 1;
        session.fingerprints.add(observation.fingerprintTag);
        sessions.set(observation.sessionTag, session);
      }
      const repeatedSessions = [...sessions.values()].filter((session) => session.runs >= 2);
      const stableSessions = repeatedSessions.filter((session) => session.fingerprints.size === 1);
      const durations = cohort.map((observation) => observation.collectionMs).sort((left, right) => left - right);
      const middle = Math.floor(durations.length / 2);
      const median = durations.length % 2
        ? durations[middle]
        : Math.round((durations[middle - 1] + durations[middle]) / 2);

      return {
        context,
        observations: cohort.length,
        ready: true,
        sessions: sessions.size,
        distinctFingerprintTags: new Set(cohort.map((observation) => observation.fingerprintTag)).size,
        meanComponentCount: Math.round(
          (cohort.reduce((total, observation) => total + observation.componentCount, 0) / cohort.length) * 10,
        ) / 10,
        medianCollectionMs: median,
        webdriverReported: cohort.filter((observation) => observation.webdriver).length,
        botdAvailable: cohort.filter((observation) => observation.botd.available).length,
        botdDetected: cohort.filter((observation) => observation.botd.available && observation.botd.bot).length,
        verifiedAgentObservations: cohort.filter((observation) => observation.verifiedAgent).length,
        repeatedSessions: repeatedSessions.length,
        repeatStabilityPercent: repeatedSessions.length
          ? Math.round((stableSessions.length / repeatedSessions.length) * 100)
          : null,
      };
    });
    return {
      generatedAt: new Date(requestNow).toISOString(),
      windowMinutes: OBSERVATION_TTL_MS / 60_000,
      minimumPerContext: REPORT_MIN_OBSERVATIONS,
      contexts,
      interpretation: 'Self-declared contexts and browser signals are experimental evidence, not identity or bot classification.',
    };
  };

  const scoreObservation = (observation) => {
    const rules = [];
    if (observation.webdriver) rules.push('webdriver-reported');
    const previousSameViewport = observations.findLast((candidate) => (
      candidate.sessionTag === observation.sessionTag
      && candidate.viewport === observation.viewport
    ));
    if (previousSameViewport && previousSameViewport.fingerprintTag !== observation.fingerprintTag) {
      rules.push('same-viewport-tag-drift');
    }
    if (observation.componentCount < 30 || observation.componentCount > 70) {
      rules.push('atypical-signal-count');
    }
    const viewportWidth = Number.parseInt(observation.viewport.split('x')[0], 10);
    if (Number.isFinite(viewportWidth) && viewportWidth <= 500 && observation.touchPoints === 0) {
      rules.push('small-viewport-no-touch');
    }
    if (!observation.requestEvidence.userAgentPresent) rules.push('missing-user-agent');
    if (!observation.requestEvidence.acceptLanguagePresent) rules.push('missing-accept-language');
    if (observation.requestEvidence.fetchSite === 'missing') rules.push('missing-fetch-metadata');
    if (!['missing', 'same-origin', 'same-site', 'none'].includes(observation.requestEvidence.fetchSite)) {
      rules.push('cross-site-observation');
    }
    if (observation.requestEvidence.platformHintMismatch) rules.push('client-hint-platform-mismatch');
    if (observation.requestEvidence.mobileHintMismatch) rules.push('client-hint-mobile-mismatch');
    if (observation.requestEvidence.browserVersionHintMismatch) {
      rules.push('client-hint-browser-version-mismatch');
    }
    if (observation.requestEvidence.browserFamilyHintMismatch) {
      rules.push('client-hint-browser-family-mismatch');
    }
    if (observation.runtimeEvidence.navigationProtocolCategory === 'opaque') {
      rules.push('navigation-protocol-opaque');
    }
    if (observation.interaction.pageAgeMs < 100) rules.push('implausibly-fast-action');
    if (observation.interaction.pointerEvents === 0 && observation.interaction.keyEvents === 0) {
      rules.push('no-interaction-before-run');
    }
    return {
      score: rules.reduce((total, rule) => total + SHADOW_RULES[rule], 0),
      rules,
    };
  };

  const shadowReport = (requestNow) => {
    pruneObservations(requestNow);
    const contexts = EXPERIMENT_CONTEXTS.map((context) => {
      const cohort = observations.filter((observation) => observation.context === context);
      if (cohort.length < REPORT_MIN_OBSERVATIONS) {
        return {
          context,
          observations: cohort.length,
          ready: false,
          minimumObservations: REPORT_MIN_OBSERVATIONS,
        };
      }
      const ruleHits = Object.fromEntries(Object.keys(SHADOW_RULES).map((rule) => [
        rule,
        cohort.filter((observation) => observation.shadowRules.includes(rule)).length,
      ]));
      return {
        context,
        observations: cohort.length,
        ready: true,
        meanScore: Math.round(
          (cohort.reduce((total, observation) => total + observation.shadowScore, 0) / cohort.length) * 10,
        ) / 10,
        maximumScore: Math.max(...cohort.map((observation) => observation.shadowScore)),
        wouldReview: cohort.filter((observation) => observation.shadowScore >= SHADOW_REVIEW_THRESHOLD).length,
        ruleHits,
      };
    });
    const labelledAutomation = observations.filter((observation) => observation.context === 'authorised-automation');
    const labelledNonAutomation = observations.filter((observation) => (
      observation.context === 'ordinary' || observation.context === 'private'
    ));
    const flagged = (cohort) => cohort.filter((observation) => (
      observation.shadowScore >= SHADOW_REVIEW_THRESHOLD
    )).length;
    const botdAvailable = (cohort) => cohort.filter((observation) => observation.botd.available);
    const botdDetected = (cohort) => botdAvailable(cohort).filter((observation) => observation.botd.bot).length;
    const botdAutomation = botdAvailable(labelledAutomation);
    const botdNonAutomation = botdAvailable(labelledNonAutomation);
    return {
      generatedAt: new Date(requestNow).toISOString(),
      mode: 'shadow',
      enforcement: false,
      reviewThreshold: SHADOW_REVIEW_THRESHOLD,
      weights: SHADOW_RULES,
      contexts,
      evaluation: {
        labelledAutomation: labelledAutomation.length,
        automationWouldReview: flagged(labelledAutomation),
        automationRecallPercent: labelledAutomation.length
          ? Math.round((flagged(labelledAutomation) / labelledAutomation.length) * 100)
          : null,
        labelledNonAutomation: labelledNonAutomation.length,
        nonAutomationWouldReview: flagged(labelledNonAutomation),
        falsePositiveRatePercent: labelledNonAutomation.length
          ? Math.round((flagged(labelledNonAutomation) / labelledNonAutomation.length) * 100)
          : null,
        openSourceBotd: {
          labelledAutomation: botdAutomation.length,
          automationDetected: botdDetected(botdAutomation),
          automationRecallPercent: botdAutomation.length
            ? Math.round((botdDetected(botdAutomation) / botdAutomation.length) * 100)
            : null,
          labelledNonAutomation: botdNonAutomation.length,
          nonAutomationDetected: botdDetected(botdNonAutomation),
          falsePositiveRatePercent: botdNonAutomation.length
            ? Math.round((botdDetected(botdNonAutomation) / botdNonAutomation.length) * 100)
            : null,
        },
        verifiedKnownGoodAutomation: labelledAutomation.filter((observation) => observation.verifiedAgent).length,
      },
      interpretation: 'Declared context is used only to evaluate the score, never as a score input. No request is blocked or challenged.',
    };
  };

  const tag = (scope, value) => createHmac('sha256', secret)
    .update(`${scope}:${String(value)}`)
    .digest('hex')
    .slice(0, 16);

  const clientKey = (request) => {
    const cloudflareAddress = request.headers['cf-connecting-ip'];
    const address = trustCloudflare && typeof cloudflareAddress === 'string'
      ? cloudflareAddress
      : request.socket.remoteAddress || 'unknown';
    return tag('rate', address);
  };

  const server = createServer(async (request, response) => {
    addSecurityHeaders(response);
    const requestUrl = new URL(request.url || '/', 'http://bot-lab.invalid');
    const requestNow = now();
    const requester = clientKey(request);

    try {
      if (request.method === 'GET' && requestUrl.pathname === '/healthz') {
        return json(response, 200, { status: 'ok', storage: 'ephemeral' });
      }

      if (request.method === 'GET' && requestUrl.pathname === '/api/config') {
        return json(response, 200, {
          turnstile: {
            enabled: Boolean(turnstileSitekey && turnstileSecretKey),
            sitekey: turnstileSitekey || null,
            action: turnstileAction,
            disclosure: 'Loads Cloudflare only after explicit activation.',
          },
        });
      }

      if (request.method === 'GET' && requestUrl.pathname === '/api/session') {
        if (!fixedWindowAllowed(rateBuckets, `session:${requester}`, 30, 60_000, requestNow)) {
          response.setHeader('retry-after', '60');
          return json(response, 429, { error: 'session rate limit reached' });
        }
        const token = issueSession(requestNow);
        response.setHeader('set-cookie', [
          `bot_lab_session=${token}`,
          'HttpOnly',
          'SameSite=Strict',
          'Path=/',
          `Max-Age=${SESSION_TTL_MS / 1000}`,
          ...(trustCloudflare ? ['Secure'] : []),
        ].join('; '));
        return json(response, 200, {
          issued: true,
          expiresInSeconds: SESSION_TTL_MS / 1000,
          storage: 'signed HttpOnly cookie',
        });
      }

      if (request.method === 'GET' && requestUrl.pathname === '/api/challenge') {
        if (!fixedWindowAllowed(rateBuckets, `challenge:${requester}`, 30, 60_000, requestNow)) {
          response.setHeader('retry-after', '60');
          return json(response, 429, { error: 'challenge rate limit reached' });
        }
        pruneMap(issued, requestNow);
        const challenge = await createChallenge({
          algorithm: 'PBKDF2/SHA-256',
          cost: challengeCost,
          counter: randomInt(counterMin, counterMax + 1),
          deriveKey,
          expiresAt: new Date(requestNow + 120_000),
          hmacSignatureSecret: secret,
          hmacKeySignatureSecret: keySecret,
        });
        capMap(issued, MAX_ISSUED_CHALLENGES);
        issued.set(challenge.signature, { expiresAt: requestNow + 120_000 });
        counters.challenges += 1;
        response.setHeader('cache-control', 'no-store');
        return json(response, 200, challenge);
      }

      if (request.method === 'POST' && requestUrl.pathname === '/api/verify') {
        if (!fixedWindowAllowed(rateBuckets, `verify:${requester}`, 30, 60_000, requestNow)) {
          response.setHeader('retry-after', '60');
          return json(response, 429, { error: 'verification rate limit reached' });
        }
        const body = await readJson(request);
        const payload = decodePayload(body.payload);
        const signature = payload.challenge.signature;
        pruneMap(issued, requestNow);
        const record = issued.get(signature);
        if (!record) {
          counters.rejected += 1;
          return json(response, 409, { verified: false, reason: 'unknown, expired, or replayed challenge' });
        }
        const result = await verifySolution({
          challenge: payload.challenge,
          solution: payload.solution,
          deriveKey,
          hmacSignatureSecret: secret,
          hmacKeySignatureSecret: keySecret,
        });
        issued.delete(signature);
        if (!result.verified) {
          counters.rejected += 1;
          return json(response, 400, { verified: false, reason: 'invalid proof' });
        }
        counters.verified += 1;
        return json(response, 200, {
          verified: true,
          verificationMs: safeNumber(result.time, 0, 30_000),
          replayProtected: true,
        });
      }

      if (request.method === 'POST' && requestUrl.pathname === '/api/turnstile/verify') {
        if (!turnstileSitekey || !turnstileSecretKey) {
          return json(response, 503, { verified: false, reason: 'Turnstile comparison is not configured' });
        }
        if (!fixedWindowAllowed(rateBuckets, `turnstile:${requester}`, 20, 60_000, requestNow)) {
          response.setHeader('retry-after', '60');
          return json(response, 429, { verified: false, reason: 'Turnstile verification rate limit reached' });
        }
        readSession(request, requestNow);
        const body = await readJson(request);
        if (typeof body.token !== 'string' || body.token.length < 8 || body.token.length > 2_048) {
          throw error(400, 'invalid Turnstile token');
        }
        const startedAt = now();
        const result = await turnstileVerify(body.token);
        const hostnameMatched = result.hostname === turnstileExpectedHostname;
        const actionMatched = result.action === turnstileAction;
        const verified = result.success === true && hostnameMatched && actionMatched;
        if (verified) counters.turnstileVerified += 1;
        else counters.turnstileRejected += 1;
        return json(response, verified ? 200 : 400, {
          verified,
          hostnameMatched,
          actionMatched,
          validationMs: Math.round(safeNumber(now() - startedAt, 0, 30_000)),
          errors: verified ? [] : (Array.isArray(result['error-codes']) ? result['error-codes'].slice(0, 8) : []),
          enforcement: false,
        });
      }

      if (request.method === 'POST' && requestUrl.pathname === '/api/observe') {
        if (!fixedWindowAllowed(rateBuckets, `observe:${requester}`, 20, 60_000, requestNow)) {
          response.setHeader('retry-after', '60');
          return json(response, 429, { error: 'observation rate limit reached' });
        }
        const session = readSession(request, requestNow);
        const body = await readJson(request);
        if (typeof body.visitorId !== 'string' || !/^[a-f0-9]{16,128}$/i.test(body.visitorId)) {
          throw error(400, 'invalid fingerprint identifier');
        }
        const observation = {
          recordedAt: new Date(requestNow).toISOString(),
          expiresAt: requestNow + OBSERVATION_TTL_MS,
          sessionTag: tag('session', session.nonce),
          fingerprintTag: tag('fingerprint', body.visitorId),
          componentCount: Math.round(safeNumber(body.componentCount, 0, 256)),
          collectionMs: Math.round(safeNumber(body.collectionMs, 0, 30_000)),
          webdriver: body.webdriver === true,
          touchPoints: Math.round(safeNumber(body.touchPoints, 0, 32)),
          context: EXPERIMENT_CONTEXTS.includes(body.context) ? body.context : 'unlabelled',
          botd: {
            available: body.botd?.available === true,
            bot: body.botd?.available === true && body.botd?.bot === true,
            kind: body.botd?.available === true && body.botd?.bot === true
              ? (BOTD_KINDS.has(body.botd?.kind) ? body.botd.kind : 'unknown')
              : null,
          },
          verifiedAgent: verifyAgentProof(request, requestUrl.pathname, requestNow),
          interaction: {
            pageAgeMs: Math.round(safeNumber(body.interaction?.pageAgeMs, 0, 3_600_000)),
            pointerEvents: Math.round(safeNumber(body.interaction?.pointerEvents, 0, 10_000)),
            keyEvents: Math.round(safeNumber(body.interaction?.keyEvents, 0, 10_000)),
          },
          runtimeEvidence: {
            navigationProtocolCategory: ['recognised', 'opaque'].includes(
              body.runtimeEvidence?.navigationProtocolCategory,
            ) ? body.runtimeEvidence.navigationProtocolCategory : 'unavailable',
          },
          requestEvidence: requestEvidence(request),
          viewport: typeof body.viewport === 'string' && /^\d{2,5}x\d{2,5}$/.test(body.viewport)
            ? body.viewport
            : 'unknown',
        };
        const shadow = scoreObservation(observation);
        observation.shadowScore = shadow.score;
        observation.shadowRules = shadow.rules;
        observations.push(observation);
        while (observations.length > MAX_OBSERVATIONS) observations.shift();
        while (observations[0]?.expiresAt <= requestNow) observations.shift();
        counters.observations += 1;
        return json(response, 201, {
          stored: true,
          retentionSeconds: OBSERVATION_TTL_MS / 1000,
          observation: { ...observation, expiresAt: undefined, sessionTag: undefined },
        });
      }

      if (request.method === 'GET' && requestUrl.pathname === '/api/stats') {
        pruneObservations(requestNow);
        response.setHeader('cache-control', 'no-store');
        return json(response, 200, {
          windowMinutes: OBSERVATION_TTL_MS / 60_000,
          activeObservations: observations.length,
          ...counters,
        });
      }

      if (request.method === 'GET' && requestUrl.pathname === '/api/report') {
        return json(response, 200, experimentReport(requestNow));
      }

      if (request.method === 'GET' && requestUrl.pathname === '/api/shadow-report') {
        return json(response, 200, shadowReport(requestNow));
      }

      if (request.method === 'GET' || request.method === 'HEAD') {
        const file = staticPath(requestUrl.pathname);
        if (file && existsSync(file) && statSync(file).isFile()) {
          const extension = path.extname(file);
          response.setHeader('content-type', MIME.get(extension) || 'application/octet-stream');
          response.setHeader('cache-control', requestUrl.pathname.startsWith('/assets/')
            ? 'public, max-age=31536000, immutable'
            : 'no-store');
          response.writeHead(200);
          if (request.method === 'HEAD') return response.end();
          return createReadStream(file).pipe(response);
        }
      }

      return json(response, 404, { error: 'not found' });
    } catch (caught) {
      const status = Number.isInteger(caught?.status) ? caught.status : 500;
      if (status === 500) console.error('request failed', caught);
      return json(response, status, { error: status === 500 ? 'internal error' : caught.message });
    }
  });

  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 8080);
  const host = process.env.HOST || '0.0.0.0';
  const server = createBotLab();
  server.listen(port, host, () => console.log(`bot-lab listening on http://${host}:${port}`));
}
