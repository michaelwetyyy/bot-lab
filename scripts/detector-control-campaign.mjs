import { once } from 'node:events';
import { existsSync } from 'node:fs';

import { chromium } from 'playwright-core';

import { createBotLab } from '../src/server.mjs';
import { assertAggregateOnly, plateauReached } from './campaign-aggregate.mjs';

const RUNS = 3;
const executables = {
  'headed-unbranded-chromium': chromium.executablePath(),
  'headed-google-chrome': '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  'headed-opera-gx': '/Applications/Opera GX.app/Contents/MacOS/Opera',
};

function parseAdapter(value) {
  const status = ['detected', 'clean', 'unavailable'].find((candidate) => value.startsWith(candidate))
    || 'unavailable';
  const categories = value.split(/\s+/).slice(1).join(' ').split('·')[0].trim()
    .replace('no categories triggered', '').split(/,\s*/).filter(Boolean).sort();
  return { status, categories };
}

async function collect(browser, target, browserName, mobile = false) {
  const browserMajor = /^\d{1,3}/.exec(browser.version())?.[0];
  const context = await browser.newContext({
    locale: 'en-US',
    viewport: mobile ? { width: 390, height: 844 } : { width: 1440, height: 900 },
    ...(mobile ? {
      isMobile: true,
      hasTouch: true,
      deviceScaleFactor: 3,
      userAgent: `Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserMajor}.0.0.0 Mobile Safari/537.36`,
    } : {}),
  });
  let externalRequests = 0;
  context.on('request', (request) => {
    if (new URL(request.url()).origin !== target) externalRequests += 1;
  });
  try {
    const page = await context.newPage();
    await page.goto(target, { waitUntil: 'domcontentloaded' });
    await page.getByRole('button', { name: 'I understand — enter the lab' }).click();
    await page.getByLabel('How are you running this test?').selectOption('ordinary');
    await page.getByRole('button', { name: 'Run fingerprint' }).click();
    await page.waitForFunction(() => document.querySelector('#run-fingerprint')?.disabled === false);
    const values = Object.fromEntries(await page.locator('#fingerprint-output .result-item').evaluateAll((items) => (
      items.map((item) => [
        item.querySelector('dt')?.textContent.trim(),
        item.querySelector('dd')?.textContent.trim(),
      ])
    )));
    const rules = values['Shadow score'].replace(/^\d{1,3}\s*/, '').replace('no rules triggered', '')
      .split(/,\s*/).filter(Boolean).sort();
    return {
      browser: browserName,
      customShadow: Number.parseInt(values['Shadow score'], 10) >= 40 ? 'detected' : 'clean',
      customCategories: rules,
      botd: values['Open-source BotD'].startsWith('Detected:') ? 'detected'
        : values['Open-source BotD'].startsWith('Unavailable') ? 'unavailable' : 'clean',
      botSignalInstant: parseAdapter(values['bot-signal instant']),
      externalRequests,
    };
  } finally {
    await context.close();
  }
}

const app = createBotLab({ secret: '1'.repeat(64), keySecret: '2'.repeat(64) });
app.listen(0, '127.0.0.1');
await once(app, 'listening');
const target = `http://127.0.0.1:${app.address().port}`;
const browsers = new Map();

try {
  for (const [name, executablePath] of Object.entries(executables)) {
    if (!existsSync(executablePath)) continue;
    browsers.set(name, await chromium.launch({
      executablePath,
      headless: false,
      args: ['--disable-blink-features=AutomationControlled'],
      ignoreDefaultArgs: ['--enable-automation'],
    }));
  }
  const conditions = [
    { name: 'headed-unbranded-chromium', browser: 'headed-unbranded-chromium', mobile: false },
    { name: 'headed-google-chrome', browser: 'headed-google-chrome', mobile: false },
    { name: 'headed-opera-gx', browser: 'headed-opera-gx', mobile: false },
    { name: 'mobile-shaped-google-chrome', browser: 'headed-google-chrome', mobile: true },
  ].filter((condition) => browsers.has(condition.browser));
  const results = [];
  for (const condition of conditions) {
    const outcomes = [];
    for (let run = 0; run < RUNS; run += 1) {
      outcomes.push(await collect(browsers.get(condition.browser), target, condition.name, condition.mobile));
    }
    results.push({
      name: condition.name,
      declaredContext: 'ordinary',
      runs: outcomes.length,
      freshContexts: outcomes.length,
      plateau: plateauReached(outcomes.map((outcome) => JSON.stringify(outcome)), RUNS),
      outcome: outcomes.at(-1),
    });
  }
  const report = await fetch(`${target}/api/detector-report`).then((response) => response.json());
  const output = {
    campaign: 'headed and mobile-shaped ordinary detector controls',
    scope: 'ephemeral localhost only',
    runsPerControl: RUNS,
    controls: results,
    independentAdapters: report.mode === 'independent-adapters',
    enforcement: report.enforcement,
    rawIdentifiersExported: false,
    interpretation: 'These local controls expose observed misses and false positives; they are not a general accuracy claim.',
  };
  assertAggregateOnly(output);
  console.log(JSON.stringify(output, null, 2));
  if (!results.length || results.some((result) => !result.plateau || result.outcome.externalRequests !== 0)
    || !output.independentAdapters || output.enforcement !== false) process.exitCode = 1;
} finally {
  await Promise.all([...browsers.values()].map((browser) => browser.close().catch(() => {})));
  app.close();
  await once(app, 'close').catch(() => {});
}
