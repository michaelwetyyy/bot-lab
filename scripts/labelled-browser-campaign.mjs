import { spawn } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';

import { chromium } from 'playwright-core';

import { assertAggregateOnly, plateauReached } from './campaign-aggregate.mjs';

const MIN_RUNS = 3;
const MAX_RUNS = 5;
const PLATEAU_WINDOW = 3;
const chromeCandidates = [
  process.env.BOT_LAB_CHROME,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
].filter(Boolean);
const chromePath = chromeCandidates.find((candidate) => existsSync(candidate));
if (!chromePath) throw new Error('Chrome or Chromium is required; set BOT_LAB_CHROME to its executable path');

const browserTargets = [
  { name: 'Google Chrome', executablePath: chromePath, required: true },
  {
    name: 'Opera GX',
    executablePath: process.env.BOT_LAB_OPERA || '/Applications/Opera GX.app/Contents/MacOS/Opera',
    required: false,
  },
].filter((target) => {
  if (existsSync(target.executablePath)) return true;
  if (target.required) throw new Error(`${target.name} executable is unavailable`);
  return false;
});

const conditions = [
  {
    name: 'chrome-desktop-baseline',
    browser: 'Google Chrome',
    profile: 'desktop baseline',
    context: { viewport: { width: 1280, height: 720 } },
  },
  {
    name: 'chrome-mobile-touch-emulation',
    browser: 'Google Chrome',
    profile: 'explicit mobile and touch emulation',
    context: {
      viewport: { width: 390, height: 844 },
      deviceScaleFactor: 3,
      hasTouch: true,
      isMobile: true,
      userAgent: 'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36',
    },
  },
  {
    name: 'chrome-interaction-shaped',
    browser: 'Google Chrome',
    profile: 'synthetic pointer and keyboard activity',
    context: { viewport: { width: 1280, height: 720 } },
    interaction: true,
  },
  {
    name: 'chrome-webdriver-signal-suppressed',
    browser: 'Google Chrome',
    profile: 'owned-localhost weak-signal test',
    context: { viewport: { width: 1280, height: 720 } },
    suppressWebdriver: true,
  },
  {
    name: 'opera-gx-desktop-baseline',
    browser: 'Opera GX',
    profile: 'ephemeral desktop baseline',
    context: { viewport: { width: 1280, height: 720 } },
  },
];

let application;
const openBrowsers = [];
const verifiedAgentSecret = randomBytes(32).toString('hex');

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitFor(url, attempts = 40) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // The local application may still be starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Bot Lab did not become ready');
}

function proofHeaders(request) {
  const timestamp = String(Date.now());
  const nonce = randomBytes(16).toString('hex');
  const agent = 'bot-lab-playwright';
  const pathname = new URL(request.url()).pathname;
  const signature = createHmac('sha256', verifiedAgentSecret)
    .update(`${agent}:${timestamp}:${nonce}:${request.method()}:${pathname}`)
    .digest('hex');
  return {
    ...request.headers(),
    'x-bot-lab-agent': agent,
    'x-bot-lab-agent-timestamp': timestamp,
    'x-bot-lab-agent-nonce': nonce,
    'x-bot-lab-agent-signature': signature,
  };
}

async function collectObservation(page) {
  return page.evaluate(() => {
    const facts = Object.fromEntries([...document.querySelectorAll('#fingerprint-output .result-item')]
      .map((item) => [item.querySelector('dt')?.textContent.trim(), item.querySelector('dd')?.textContent.trim()]));
    const scoreMatch = facts['Shadow score']?.match(/^(\d+)\s*(.*)$/s);
    const botdText = facts['Open-source BotD'] || '';
    const history = JSON.parse(sessionStorage.getItem('botLabHistory') || '[]');
    return {
      componentCount: Number.parseInt(facts.Components, 10),
      shadowScore: Number.parseInt(scoreMatch?.[1] || '0', 10),
      shadowRules: (scoreMatch?.[2] || '').replace(/no rules triggered/, '').trim()
        .split(/,\s*/).filter(Boolean).sort(),
      botd: botdText.startsWith('Detected:')
        ? { available: true, detected: true, kind: botdText.slice(9).split(/\s/)[0] || 'unknown' }
        : { available: !botdText.startsWith('Unavailable'), detected: false },
      webdriverReported: navigator.webdriver === true,
      stableFingerprint: new Set(history.map((entry) => entry.visitorId)).size === 1,
      verifiedKnownGood: facts['Known-good proof']?.startsWith('Verified first-party automation') === true,
    };
  });
}

async function runCondition(base, browser, condition) {
  const context = await browser.newContext(condition.context);
  if (condition.suppressWebdriver) {
    await context.addInitScript(() => {
      Object.defineProperty(Navigator.prototype, 'webdriver', { configurable: true, get: () => false });
    });
  }
  await context.route('**/*', async (route) => {
    await route.continue({ headers: proofHeaders(route.request()) });
  });
  const page = await context.newPage();
  await page.goto(base, { waitUntil: 'domcontentloaded' });
  await page.getByRole('button', { name: 'I understand — enter the lab' }).click();
  await page.getByLabel('How are you running this test?').selectOption('authorised-automation');

  const observations = [];
  const signatures = [];
  for (let run = 1; run <= MAX_RUNS; run += 1) {
    if (condition.interaction) {
      await page.mouse.move(80 + (run * 17), 100 + (run * 11));
      await page.keyboard.press('Tab');
      await page.waitForTimeout(175);
    }
    await page.getByRole('button', { name: 'Run fingerprint' }).click();
    await page.locator('#history-body tr').nth(run - 1).waitFor();
    await page.waitForFunction(() => document.querySelector('#run-fingerprint')?.disabled === false);
    const observation = await collectObservation(page);
    if (!observation.verifiedKnownGood) throw new Error(`${condition.name} run ${run} lacked its known-good proof`);
    observations.push(observation);
    signatures.push(JSON.stringify({
      componentCount: observation.componentCount,
      shadowScore: observation.shadowScore,
      shadowRules: observation.shadowRules,
      botd: observation.botd,
      webdriverReported: observation.webdriverReported,
    }));
    if (run >= MIN_RUNS && plateauReached(signatures, PLATEAU_WINDOW)) break;
  }

  const finalObservation = observations.at(-1);
  const plateau = plateauReached(signatures, PLATEAU_WINDOW);
  await context.close();
  return {
    name: condition.name,
    browser: condition.browser,
    profile: condition.profile,
    viewport: `${condition.context.viewport.width}x${condition.context.viewport.height}`,
    runs: observations.length,
    plateau,
    stopReason: plateau ? `last ${PLATEAU_WINDOW} aggregate signatures matched` : `maximum ${MAX_RUNS} runs reached`,
    stableFingerprint: observations.every((observation) => observation.stableFingerprint),
    observation: {
      componentCount: finalObservation.componentCount,
      shadowScore: finalObservation.shadowScore,
      shadowRules: finalObservation.shadowRules,
      botd: finalObservation.botd,
      webdriverReported: finalObservation.webdriverReported,
      verifiedKnownGood: finalObservation.verifiedKnownGood,
    },
  };
}

async function stopApplication() {
  if (!application || application.exitCode !== null) return;
  application.kill('SIGTERM');
  await Promise.race([
    new Promise((resolve) => application.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 1_000)),
  ]);
  if (application.exitCode === null) application.kill('SIGKILL');
}

try {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  application = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(port),
      BOT_LAB_VERIFIED_AGENT_SECRET: verifiedAgentSecret,
    },
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  await waitFor(`${base}/healthz`);

  const launched = new Map();
  for (const target of browserTargets) {
    const browser = await chromium.launch({ executablePath: target.executablePath, headless: true });
    openBrowsers.push(browser);
    launched.set(target.name, browser);
  }

  const results = [];
  for (const condition of conditions.filter((item) => launched.has(item.browser))) {
    results.push(await runCondition(base, launched.get(condition.browser), condition));
  }

  const comparison = await fetch(`${base}/api/report`).then((response) => response.json());
  const shadow = await fetch(`${base}/api/shadow-report`).then((response) => response.json());
  const automation = comparison.contexts.find((context) => context.context === 'authorised-automation');
  const expectedObservations = results.reduce((total, result) => total + result.runs, 0);
  if (!automation?.ready || automation.observations !== expectedObservations
    || automation.botdAvailable !== expectedObservations
    || automation.verifiedAgentObservations !== expectedObservations) {
    throw new Error('campaign aggregate did not match the BotD-evaluated, verified observations');
  }
  if (shadow.enforcement !== false) throw new Error('campaign must remain shadow-only');

  const output = {
    campaign: 'repeatable authorised browser-security matrix',
    scope: 'public-safe synthetic traffic against an ephemeral localhost Bot Lab only',
    declaredContext: 'authorised-automation',
    plateauPolicy: { minimumRuns: MIN_RUNS, maximumRuns: MAX_RUNS, identicalTrailingSignatures: PLATEAU_WINDOW },
    conditions: results,
    aggregate: {
      conditionCount: results.length,
      plateauConditions: results.filter((result) => result.plateau).length,
      observations: automation.observations,
      botdAvailable: automation.botdAvailable,
      verifiedKnownGoodAutomation: automation.verifiedAgentObservations,
      stableRepeatedSessionsPercent: automation.repeatStabilityPercent,
      customShadow: {
        automationWouldReview: shadow.evaluation.automationWouldReview,
        automationRecallPercent: shadow.evaluation.automationRecallPercent,
      },
      openSourceBotd: shadow.evaluation.openSourceBotd,
    },
    enforcement: shadow.enforcement,
    identifiersExported: false,
    interpretation: 'Results describe only these installed browser versions, profiles and Bot Lab controls. They are not a general bot-detection accuracy claim.',
  };
  assertAggregateOnly(output);
  console.log(JSON.stringify(output, null, 2));
} finally {
  await Promise.all(openBrowsers.map((browser) => browser.close().catch(() => {})));
  await stopApplication();
}
