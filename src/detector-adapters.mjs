export const DETECTOR_STATUSES = new Set(['detected', 'clean', 'unavailable']);

export const BOT_SIGNAL_INSTANT_CATEGORIES = new Set([
  'isWebDriver', 'isPlaywright', 'isPuppeteer', 'isChromeDriver',
  'isAutomationArtifacts', 'isSelenium', 'isPhantomJS', 'isNightmare',
  'isDomAutomation', 'isHeadless', 'isSuspiciousWebDriverDescriptor',
  'isSuspiciousResolution', 'isUserAgentValid', 'isSoftwareRenderer',
  'isUserAgentDataMismatch', 'isNativeFunctionTampered',
  'isNavigatorIdentityInconsistent', 'isPluginArrayInconsistent',
  'isIframeInconsistent', 'isErrorStackAutomation', 'isEngineInconsistent',
  'isGpuPlatformMismatch', 'isMediaQueryInconsistent', 'isLanguageInconsistent',
  'isScreenGeometryInconsistent', 'isTimezoneInconsistent',
  'isMissingProprietaryCodecs', 'isMissingGreaseBrand', 'isCanvasNoiseInjected',
  'isPluginMimeTypeInconsistent', 'isMissingChromeObject', 'isWebGLSupported',
  'isSuspiciousWindowDimensions', 'isModern', 'isEmptyPlugins',
  'isSuspiciousHardware', 'isZeroConnectionRtt', 'isDefaultAutomationViewport',
  'isCanvasTampered',
]);

export const BOT_SIGNAL_BEHAVIOR_CATEGORIES = new Set([
  'no-mouse-activity', 'click-without-mouse-movement', 'linear-mouse-movement',
  'zero-mouse-movement-deltas', 'cdp-input-coordinate-leak', 'teleport-mouse',
  'linear-touch-movement', 'teleport-touch', 'linear-tap-rhythm', 'linear-scroll',
  'linear-typing', 'synthetic-events',
]);

const adapterDefinitions = Object.freeze([
  {
    id: 'custom-shadow',
    name: 'Bot Lab custom shadow',
    layer: 'browser and request summaries',
    version: '0.6.13',
    provenance: 'Bot Lab source',
    availability: 'available',
    limitations: ['Lab-derived rules; review threshold is experimental and never enforcement.'],
  },
  {
    id: 'botd',
    name: 'FingerprintJS BotD',
    layer: 'browser instant',
    version: '2.0.0',
    provenance: 'exact npm package bundled and self-hosted',
    availability: 'available',
    limitations: ['Stability-only open-source baseline; separate from the custom score.'],
  },
  {
    id: 'bot-signal-instant',
    name: 'bot-signal instant',
    layer: 'browser instant',
    version: '2.0.14 (31381f93de291f2ae894e385014df01cf0f0437f)',
    provenance: 'okasi/bot-signal exact npm package bundled and self-hosted',
    availability: 'available',
    limitations: [
      'Independent baseline only; never contributes to Bot Lab custom score.',
      'Validation missed frozen CDP-guarded Red 3/3 and false-positive detected the mobile-shaped ordinary control 3/3.',
      'Server, IP, TLS, reputation, GeoIP and external-service layers are disabled.',
    ],
  },
  {
    id: 'bot-signal-behavior',
    name: 'bot-signal behavior',
    layer: 'browser behavior',
    version: '2.0.14 (31381f93de291f2ae894e385014df01cf0f0437f)',
    provenance: 'okasi/bot-signal exact npm package bundled and self-hosted',
    availability: 'optional',
    limitations: [
      'Starts only after explicit activation; raw movement and typing-event samples stay in memory locally.',
      'Only the final tri-state and closed triggered categories are reported; observation-only and never scored.',
    ],
  },
  {
    id: 'rebrowser-compatibility-oracle',
    name: 'Rebrowser compatibility oracle',
    layer: 'offline compatibility evaluation',
    version: 'e1a25b1ff264cc9a5b5ea7fe8a6dfc26e3b1c718',
    provenance: 'rebrowser/rebrowser-bot-detector source review only',
    availability: 'unavailable',
    limitations: [
      'Not shipped: no LICENSE file, package, release, lockfile or safe distributable build; upstream runtime uses remote ChromiumDash/W3Schools assets and a permissive CSP/telemetry boundary.',
    ],
  },
  {
    id: 'crowdsec',
    name: 'CrowdSec',
    layer: 'gateway history',
    version: 'deployment-managed',
    provenance: 'aggregate output from npm run evaluate:defenses',
    availability: 'evaluation-only',
    limitations: ['No browser JavaScript; live IP evidence remains at the gateway and never enters this report.'],
  },
  {
    id: 'coraza-crs',
    name: 'Coraza with OWASP CRS',
    layer: 'gateway request inspection',
    version: 'coraza-crs@sha256:f7a92973e92f89c13d20e7c0915ada9e77513b3d9a4094306bc3453e8cd2f59f',
    provenance: 'pinned local synthetic campaign',
    availability: 'evaluation-only',
    limitations: ['Consumes aggregate synthetic rule outcomes only; request headers and payloads are not browser-report fields.'],
  },
  {
    id: 'anubis',
    name: 'Anubis',
    layer: 'gateway challenge',
    version: 'deployment-managed',
    provenance: 'aggregate output from npm run evaluate:defenses',
    availability: 'evaluation-only',
    limitations: ['Reports aggregate challenge-tier outcomes; no browser components are imported.'],
  },
  {
    id: 'turnstile',
    name: 'Cloudflare Turnstile',
    layer: 'optional managed comparator',
    version: 'provider-managed',
    provenance: 'loaded only after explicit participant action',
    availability: 'optional',
    limitations: ['External managed service; excluded from every local detector score and disabled unless configured.'],
  },
]);

const CATEGORY_VOCABULARIES = Object.freeze({
  'custom-shadow': [
    'webdriver-reported', 'same-viewport-tag-drift', 'atypical-signal-count',
    'small-viewport-no-touch', 'missing-user-agent', 'missing-accept-language',
    'missing-fetch-metadata', 'cross-site-observation', 'implausibly-fast-action',
    'no-interaction-before-run', 'client-hint-platform-mismatch',
    'client-hint-mobile-mismatch', 'client-hint-browser-version-mismatch',
    'client-hint-browser-family-mismatch', 'navigation-protocol-opaque',
  ],
  botd: [
    'awesomium', 'cef', 'cefsharp', 'coachjs', 'electron', 'fminer', 'geb',
    'nightmarejs', 'phantomas', 'phantomjs', 'rhino', 'selenium', 'sequentum',
    'slimerjs', 'webdriverio', 'webdriver', 'headless_chrome', 'unknown',
  ],
  'bot-signal-instant': [...BOT_SIGNAL_INSTANT_CATEGORIES],
  'bot-signal-behavior': [...BOT_SIGNAL_BEHAVIOR_CATEGORIES],
  'rebrowser-compatibility-oracle': [],
  crowdsec: ['synthetic-local-decision-blocked'],
  'coraza-crs': ['synthetic-sqli-blocked'],
  anubis: ['challenge-tiers-observed'],
  turnstile: ['verification-passed', 'verification-rejected'],
});

export function sanitizeAdapterResult(value, categories) {
  if (!value || !DETECTOR_STATUSES.has(value.status)) {
    return { status: 'unavailable', categories: [] };
  }
  if (!Array.isArray(value.categories) || value.categories.some((category) => !categories.has(category))) {
    return { status: 'unavailable', categories: [] };
  }
  return { status: value.status, categories: [...new Set(value.categories)].slice(0, categories.size) };
}

function summarize(entries, contexts) {
  const byContext = contexts.map((context) => {
    const cohort = entries.filter((entry) => entry.context === context);
    return {
      context,
      observations: cohort.length,
      detected: cohort.filter((entry) => entry.result.status === 'detected').length,
      clean: cohort.filter((entry) => entry.result.status === 'clean').length,
      unavailable: cohort.filter((entry) => entry.result.status === 'unavailable').length,
      categoryHits: Object.fromEntries([...new Set(cohort.flatMap((entry) => entry.result.categories))]
        .sort().map((category) => [category, cohort.filter((entry) => entry.result.categories.includes(category)).length])),
    };
  });
  return {
    observations: entries.length,
    detected: entries.filter((entry) => entry.result.status === 'detected').length,
    clean: entries.filter((entry) => entry.result.status === 'clean').length,
    unavailable: entries.filter((entry) => entry.result.status === 'unavailable').length,
    contexts: byContext,
  };
}

export function buildDetectorReport({ observations, behaviorObservations, contexts, turnstileEnabled }) {
  const perAdapter = {
    'custom-shadow': observations.map((observation) => ({
      context: observation.context,
      result: {
        status: observation.shadowScore >= 40 ? 'detected' : 'clean',
        categories: observation.shadowRules,
      },
    })),
    botd: observations.map((observation) => ({
      context: observation.context,
      result: observation.botd.available
        ? { status: observation.botd.bot ? 'detected' : 'clean', categories: observation.botd.bot ? [observation.botd.kind] : [] }
        : { status: 'unavailable', categories: [] },
    })),
    'bot-signal-instant': observations.map((observation) => ({
      context: observation.context,
      result: observation.botSignalInstant,
    })),
    'bot-signal-behavior': behaviorObservations.map((observation) => ({
      context: observation.context,
      result: observation.result,
    })),
  };
  return {
    schemaVersion: 1,
    mode: 'independent-adapters',
    enforcement: false,
    adapters: adapterDefinitions.map((definition) => ({
      ...definition,
      resultContract: {
        statuses: [...DETECTOR_STATUSES],
        categoryVocabulary: CATEGORY_VOCABULARIES[definition.id],
      },
      availability: definition.id === 'turnstile' && !turnstileEnabled ? 'unavailable' : definition.availability,
      result: perAdapter[definition.id]
        ? summarize(perAdapter[definition.id], contexts)
        : { observations: 0, detected: 0, clean: 0, unavailable: 0, contexts: [] },
      currentStatus: perAdapter[definition.id]?.at(-1)?.result.status ?? 'unavailable',
      enforcement: false,
    })),
    privacy: 'Only tri-state outcomes and closed categories are reported. Raw browser values, paths, typing events, headers, addresses, TLS data and identifiers are excluded.',
    interpretation: 'Declared context groups already-produced predictions for evaluation; it is never a detector input. Compare adapters independently.',
  };
}

export function gatewayAdapterResults({ corazaPassed, crowdsecPassed, anubisPassed }) {
  const result = (passed, category) => ({
    status: passed ? 'detected' : 'clean',
    categories: passed ? [category] : [],
  });
  return {
    'coraza-crs': result(corazaPassed, 'synthetic-sqli-blocked'),
    crowdsec: result(crowdsecPassed, 'synthetic-local-decision-blocked'),
    anubis: result(anubisPassed, 'challenge-tiers-observed'),
  };
}
