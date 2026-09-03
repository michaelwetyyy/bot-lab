import FingerprintJS from '@fingerprintjs/fingerprintjs';
import { load as loadBotD } from '@fingerprintjs/botd';
import 'altcha';

const $ = (selector) => document.querySelector(selector);
const output = $('#fingerprint-output');
const componentExplorer = $('#component-explorer');
const historyBody = $('#history-body');
const runButton = $('#run-fingerprint');
const challengeForm = $('#challenge-form');
const challengeOutput = $('#challenge-output');
const statsOutput = $('#stats-output');
const reportBody = $('#report-body');
const reportStatus = $('#report-status');
const contextSelect = $('#experiment-context');
const shadowBody = $('#shadow-body');
const shadowStatus = $('#shadow-status');
const loadTurnstileButton = $('#load-turnstile');
const verifyTurnstileButton = $('#verify-turnstile');
const turnstileOutput = $('#turnstile-output');
const entryGate = $('#entry-gate');
const enterLabButton = $('#enter-lab');
const gatedRegions = [...document.querySelectorAll('header, main, footer')];
let turnstileToken = '';
let turnstileConfig;

function setEntryGate(open) {
  entryGate.hidden = !open;
  document.body.classList.toggle('entry-gated', open);
  for (const region of gatedRegions) region.inert = open;
  if (open) queueMicrotask(() => enterLabButton.focus());
}

let entryAcknowledged = false;
try {
  entryAcknowledged = sessionStorage.getItem('botLabEntryAcknowledged') === 'true';
} catch {
  entryAcknowledged = false;
}
setEntryGate(!entryAcknowledged);

enterLabButton.addEventListener('click', () => {
  try {
    sessionStorage.setItem('botLabEntryAcknowledged', 'true');
  } catch {
    // The notice can still close for this page view when storage is unavailable.
  }
  setEntryGate(false);
  const pageHeading = document.querySelector('.hero-copy h1');
  pageHeading?.setAttribute('tabindex', '-1');
  pageHeading?.focus({ preventScroll: true });
});

const sessionId = sessionStorage.getItem('botLabSession') || crypto.randomUUID();
sessionStorage.setItem('botLabSession', sessionId);
const pageStartedAt = performance.now();
const interaction = { pointerEvents: 0, keyEvents: 0 };
document.addEventListener('pointerdown', () => { interaction.pointerEvents += 1; }, { capture: true });
document.addEventListener('keydown', () => { interaction.keyEvents += 1; }, { capture: true });

function navigationProtocolCategory() {
  try {
    const navigation = performance.getEntriesByType('navigation')[0];
    if (!navigation || typeof navigation.nextHopProtocol !== 'string') return 'unavailable';
    const protocol = navigation.nextHopProtocol.trim().toLowerCase();
    if (!protocol) return 'opaque';
    return /^(?:http\/(?:0\.9|1\.0|1\.1)|h2|h3(?:-\d+)?|quic)$/.test(protocol)
      ? 'recognised'
      : 'opaque';
  } catch {
    return 'unavailable';
  }
}

let sessionExpiresAt = 0;

const COMPONENT_GUIDE = Object.freeze({
  userAgentData: ['Browser & OS', 'Browser brands, platform, device class and selected User-Agent Client Hints.'],
  fonts: ['Rendering', 'Fonts the browser can detect as available through local rendering checks.'],
  domBlockers: ['Browser behaviour', 'Whether test elements associated with common content blockers are hidden.'],
  fontPreferences: ['Rendering', 'Measured sizes of browser default and preferred font families.'],
  audio: ['Rendering', 'A result produced by the browser audio-processing pipeline.'],
  screenFrame: ['Display', 'The measured frame between the physical screen and the browser\'s available screen area.'],
  canvas: ['Rendering', 'How this browser draws fixed text and geometry on a 2D canvas.'],
  osCpu: ['Hardware & OS', 'Legacy operating-system CPU information when the browser exposes it.'],
  languages: ['Locale', 'The browser\'s ordered preferred language settings.'],
  colorDepth: ['Display', 'The number of colour bits the screen reports for each pixel.'],
  deviceMemory: ['Hardware & OS', 'The approximate device-memory class reported by the browser.'],
  screenResolution: ['Display', 'The screen dimensions reported by the browser.'],
  hardwareConcurrency: ['Hardware & OS', 'The number of logical processor threads exposed to web pages.'],
  timezone: ['Locale', 'The browser\'s resolved time-zone name.'],
  sessionStorage: ['Storage support', 'Whether session-scoped web storage is available.'],
  localStorage: ['Storage support', 'Whether persistent local web storage is available.'],
  indexedDB: ['Storage support', 'Whether the IndexedDB browser database API is available.'],
  openDatabase: ['Storage support', 'Whether the legacy Web SQL database API is available.'],
  cpuClass: ['Hardware & OS', 'A legacy browser CPU-class value when available.'],
  platform: ['Browser & OS', 'The operating-system platform string exposed by the browser.'],
  plugins: ['Browser capabilities', 'Metadata for browser plugins the page is allowed to enumerate.'],
  touchSupport: ['Input', 'Reported touch points and touch-event capability.'],
  vendor: ['Browser & OS', 'The browser vendor string.'],
  vendorFlavors: ['Browser & OS', 'Recognised browser-vendor features and runtime flavours.'],
  cookiesEnabled: ['Storage support', 'Whether the browser reports cookies as enabled.'],
  colorGamut: ['Display', 'The widest colour gamut matched by the current display.'],
  invertedColors: ['Accessibility', 'Whether the browser reports an inverted-colour preference.'],
  forcedColors: ['Accessibility', 'Whether the browser is forcing a limited system colour palette.'],
  monochrome: ['Display', 'The reported monochrome pixel depth, if any.'],
  contrast: ['Accessibility', 'The user\'s reported contrast preference.'],
  reducedMotion: ['Accessibility', 'Whether reduced motion is preferred.'],
  reducedTransparency: ['Accessibility', 'Whether reduced transparency is preferred.'],
  hdr: ['Display', 'Whether the display environment reports high dynamic range.'],
  math: ['Rendering', 'Results from selected floating-point math operations that may vary by engine or architecture.'],
  pdfViewerEnabled: ['Browser capabilities', 'Whether the browser reports an integrated PDF viewer.'],
  architecture: ['Hardware & OS', 'A small runtime test that helps distinguish processor architecture behaviour.'],
  applePay: ['Browser capabilities', 'The Apple Pay capability state exposed to this browser context.'],
  privateClickMeasurement: ['Browser capabilities', 'Whether Safari\'s privacy-preserving click-measurement API is exposed.'],
  audioBaseLatency: ['Rendering', 'The base latency reported by the browser audio context.'],
  dateTimeLocale: ['Locale', 'How the browser formats a fixed date and time for its locale.'],
  webGlBasics: ['Rendering', 'Basic WebGL renderer, vendor and graphics capability information.'],
  webGlExtensions: ['Rendering', 'Supported WebGL extensions and selected graphics limits.'],
});

const history = JSON.parse(sessionStorage.getItem('botLabHistory') || '[]');
let fingerprintPromise;
let botdPromise;

function escapeText(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function renderHistory() {
  historyBody.innerHTML = history.length
    ? history.map((item, index) => `
      <tr>
        <td>${index + 1}</td>
        <td><code>${escapeText(item.visitorId.slice(0, 16))}…</code></td>
        <td>${escapeText(item.context)}</td>
        <td>${item.componentCount}</td>
        <td>${item.collectionMs} ms</td>
        <td>${index === 0 ? 'baseline' : item.visitorId === history[0].visitorId ? 'same' : 'changed'}</td>
      </tr>`).join('')
    : '<tr><td colspan="6">No runs in this browser tab yet.</td></tr>';
}

function componentValue(name, component) {
  if (component?.error) return `error: ${component.error.name || 'unavailable'}`;
  if (name === 'canvas' && component?.value && typeof component.value === 'object') {
    const checks = Object.keys(component.value).length;
    return `${checks} rendering checks · image data hidden in preview`;
  }
  const raw = typeof component?.value === 'string'
    ? component.value
    : JSON.stringify(component?.value);
  return raw && raw.length > 180 ? `${raw.slice(0, 177)}…` : raw || 'empty';
}

function componentFullValue(component) {
  if (component?.error) {
    return `error: ${component.error.name || 'unavailable'}${component.error.message ? ` — ${component.error.message}` : ''}`;
  }
  if (component?.value === undefined) return 'unsupported or unavailable';
  if (typeof component.value === 'string') return component.value || 'empty string';
  try {
    return JSON.stringify(component.value, null, 2) ?? String(component.value);
  } catch {
    return String(component.value);
  }
}

async function detectBasicAutomation() {
  try {
    botdPromise ||= loadBotD();
    const detector = await botdPromise;
    const result = detector.detect();
    return {
      available: true,
      bot: result.bot === true,
      kind: result.bot === true ? result.botKind : null,
    };
  } catch {
    return { available: false, bot: false, kind: null };
  }
}

function renderComponentRows(components) {
  return components.map(([name, component], index) => {
    const [group, description] = COMPONENT_GUIDE[name]
      || ['Other browser signal', 'A FingerprintJS component not yet described by this Bot Lab release.'];
    const detailId = `component-detail-${index}`;
    return `
      <tr class="component-summary-row" data-component-name="${escapeText(name.toLowerCase())}" data-component-group="${escapeText(group)}" data-detail-id="${detailId}">
        <td>
          <button class="component-toggle" type="button" aria-expanded="false" aria-controls="${detailId}" data-component-target="${detailId}">
            <span>${escapeText(name)}</span><span class="component-toggle-icon" aria-hidden="true">+</span>
          </button>
        </td>
        <td><code>${escapeText(componentValue(name, component))}</code></td>
        <td>${Math.round(component.duration || 0)} ms</td>
      </tr>
      <tr id="${detailId}" class="component-detail-row" hidden>
        <td colspan="3">
          <div class="component-detail">
            <p><strong>${escapeText(group)}</strong> — ${escapeText(description)}</p>
            <dl class="component-facts">
              <dt>Included in visitor ID</dt><dd>Yes, as one input to the local hash.</dd>
              <dt>Raw value sent to Bot Lab</dt><dd>No. The server receives the completed visitor ID and total component count.</dd>
            </dl>
            <p class="component-value-label">Full local value</p>
            <pre class="component-value"><code>${escapeText(componentFullValue(component))}</code></pre>
          </div>
        </td>
      </tr>`;
  }).join('');
}

function renderComponentExplorer(components) {
  const groups = [...new Set(components.map(([name]) => COMPONENT_GUIDE[name]?.[0] || 'Other browser signal'))]
    .sort((left, right) => left.localeCompare(right));
  componentExplorer.hidden = false;
  componentExplorer.innerHTML = `
    <div class="component-explorer-head">
      <div>
        <p class="mini-label">Local component explorer</p>
        <h3>What this browser reveals</h3>
        <p>Search all ${components.length} locally collected signals. Select a row to see its complete value and how Bot Lab handles it.</p>
      </div>
      <span class="privacy-chip">Raw values stay here</span>
    </div>
    <div class="component-tools">
      <label>
        <span>Search signals</span>
        <input class="component-search" type="search" placeholder="Try canvas, fonts, screen…" autocomplete="off">
      </label>
      <label>
        <span>Category</span>
        <select class="component-filter">
          <option value="all">All categories</option>
          ${groups.map((group) => `<option value="${escapeText(group)}">${escapeText(group)}</option>`).join('')}
        </select>
      </label>
      <p class="component-match-count" aria-live="polite">${components.length} of ${components.length} shown</p>
    </div>
    <div class="table-wrap component-table-wrap">
      <table class="components"><thead><tr><th>Signal</th><th>Value preview</th><th>Time</th></tr></thead>
      <tbody>${renderComponentRows(components)}</tbody></table>
    </div>`;
}

function filterComponentRows() {
  const query = componentExplorer.querySelector('.component-search')?.value.trim().toLowerCase() || '';
  const selectedGroup = componentExplorer.querySelector('.component-filter')?.value || 'all';
  const rows = [...componentExplorer.querySelectorAll('.component-summary-row')];
  let shown = 0;
  for (const row of rows) {
    const matchesSearch = !query || row.dataset.componentName.includes(query) || row.dataset.componentGroup.toLowerCase().includes(query);
    const matchesGroup = selectedGroup === 'all' || row.dataset.componentGroup === selectedGroup;
    const visible = matchesSearch && matchesGroup;
    row.hidden = !visible;
    const detail = document.getElementById(row.dataset.detailId);
    if (detail) {
      detail.hidden = !visible || row.querySelector('.component-toggle')?.getAttribute('aria-expanded') !== 'true';
    }
    if (visible) shown += 1;
  }
  const count = componentExplorer.querySelector('.component-match-count');
  if (count) count.textContent = `${shown} of ${rows.length} shown`;
}

componentExplorer.addEventListener('click', (event) => {
  const toggle = event.target.closest('.component-toggle');
  if (!toggle || !componentExplorer.contains(toggle)) return;
  const detail = document.getElementById(toggle.dataset.componentTarget);
  if (!detail) return;
  const expanded = toggle.getAttribute('aria-expanded') === 'true';
  toggle.setAttribute('aria-expanded', String(!expanded));
  detail.hidden = expanded;
  toggle.querySelector('.component-toggle-icon').textContent = expanded ? '+' : '−';
});

componentExplorer.addEventListener('input', (event) => {
  if (event.target.matches('.component-search')) filterComponentRows();
});

componentExplorer.addEventListener('change', (event) => {
  if (event.target.matches('.component-filter')) filterComponentRows();
});

async function postJson(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || data.reason || `request failed (${response.status})`);
  return data;
}

async function ensureBrowserSession() {
  if (sessionExpiresAt > Date.now() + 30_000) return;
  let response;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      response = await fetch('/api/session', { cache: 'no-store', credentials: 'same-origin' });
      break;
    } catch {
      if (attempt === 1) {
        throw new Error('Bot Lab session fetch failed twice. Reload the page and check Safari content blockers or Private Relay.');
      }
      await new Promise((resolve) => setTimeout(resolve, 600));
    }
  }
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `session request failed (${response.status})`);
  sessionExpiresAt = Date.now() + (data.expiresInSeconds * 1000);
}

async function loadScript(source) {
  if (window.turnstile) return;
  const stale = [...document.scripts].find((script) => script.src === source);
  if (stale) stale.remove();
  await new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = source;
    script.async = true;
    script.defer = true;
    script.addEventListener('load', resolve, { once: true });
    script.addEventListener('error', () => {
      script.remove();
      reject(new Error('Cloudflare Turnstile script could not be fetched. Reload and check Safari content blockers or Private Relay.'));
    }, { once: true });
    document.head.append(script);
  });
  for (let attempt = 0; attempt < 40 && !window.turnstile; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!window.turnstile) {
    throw new Error('Cloudflare script loaded but Turnstile did not initialize. Reload the page and retry.');
  }
}

async function configureTurnstile() {
  const response = await fetch('/api/config', { cache: 'no-store' });
  const config = await response.json();
  turnstileConfig = config.turnstile;
  loadTurnstileButton.disabled = !turnstileConfig.enabled;
  turnstileOutput.textContent = turnstileConfig.enabled
    ? 'Ready. Cloudflare has not been contacted.'
    : 'Turnstile comparison is not configured yet.';
}

async function refreshStats() {
  const response = await fetch('/api/stats', { cache: 'no-store' });
  const stats = await response.json();
  statsOutput.textContent = JSON.stringify(stats, null, 2);
}

async function fetchReport() {
  const response = await fetch('/api/report', { cache: 'no-store' });
  if (!response.ok) throw new Error(`report request failed (${response.status})`);
  return response.json();
}

async function refreshReport() {
  const report = await fetchReport();
  reportBody.innerHTML = report.contexts.map((context) => context.ready ? `
    <tr>
      <td>${escapeText(context.context)}</td>
      <td>${context.observations}</td>
      <td>${context.sessions}</td>
      <td>${context.distinctFingerprintTags}</td>
      <td>${context.repeatStabilityPercent === null ? 'need repeat runs' : `${context.repeatStabilityPercent}%`}</td>
      <td>${context.medianCollectionMs} ms</td>
      <td>${context.webdriverReported}</td>
      <td>${context.botdAvailable ? `${context.botdDetected}/${context.botdAvailable}` : 'n/a'}</td>
      <td>${context.verifiedAgentObservations}</td>
    </tr>` : `
    <tr>
      <td>${escapeText(context.context)}</td>
      <td>${context.observations}</td>
      <td colspan="7">collect ${context.minimumObservations - context.observations} more</td>
    </tr>`).join('');
  reportStatus.textContent = `${report.windowMinutes}-minute aggregate window · minimum ${report.minimumPerContext} runs per context · no tags exported`;
  return report;
}

async function fetchShadowReport() {
  const response = await fetch('/api/shadow-report', { cache: 'no-store' });
  if (!response.ok) throw new Error(`shadow report request failed (${response.status})`);
  return response.json();
}

function formatRuleHits(ruleHits) {
  const hits = Object.entries(ruleHits)
    .filter(([, count]) => count > 0)
    .map(([rule, count]) => `${rule}: ${count}`);
  return hits.length ? hits.join(', ') : 'none';
}

async function refreshShadowReport() {
  const report = await fetchShadowReport();
  shadowBody.innerHTML = report.contexts.map((context) => context.ready ? `
    <tr>
      <td>${escapeText(context.context)}</td>
      <td>${context.observations}</td>
      <td>${context.meanScore}</td>
      <td>${context.maximumScore}</td>
      <td>${context.wouldReview}</td>
      <td>${escapeText(formatRuleHits(context.ruleHits))}</td>
    </tr>` : `
    <tr>
      <td>${escapeText(context.context)}</td>
      <td>${context.observations}</td>
      <td colspan="4">collect ${context.minimumObservations - context.observations} more</td>
    </tr>`).join('');
  const recall = report.evaluation.automationRecallPercent;
  const falsePositiveRate = report.evaluation.falsePositiveRatePercent;
  const botd = report.evaluation.openSourceBotd;
  shadowStatus.textContent = `custom shadow: recall ${recall === null ? 'n/a' : `${recall}%`}, false positives ${falsePositiveRate === null ? 'n/a' : `${falsePositiveRate}%`} · open-source BotD: recall ${botd.automationRecallPercent === null ? 'n/a' : `${botd.automationRecallPercent}%`}, false positives ${botd.falsePositiveRatePercent === null ? 'n/a' : `${botd.falsePositiveRatePercent}%`} · cryptographically verified automation: ${report.evaluation.verifiedKnownGoodAutomation} · enforcement off`;
  return report;
}

runButton.addEventListener('click', async () => {
  runButton.disabled = true;
  output.textContent = 'Collecting locally…';
  const started = performance.now();
  try {
    await ensureBrowserSession();
    fingerprintPromise ||= FingerprintJS.load();
    const agent = await fingerprintPromise;
    const [result, botd] = await Promise.all([agent.get(), detectBasicAutomation()]);
    const collectionMs = Math.round(performance.now() - started);
    const components = Object.entries(result.components)
      .sort(([left], [right]) => left.localeCompare(right));
    const summary = {
      visitorId: result.visitorId,
      componentCount: components.length,
      collectionMs,
      confidence: result.confidence?.score ?? null,
      botd,
      webdriver: navigator.webdriver === true,
      touchPoints: navigator.maxTouchPoints || 0,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      context: contextSelect.value,
      interaction: {
        pageAgeMs: Math.round(performance.now() - pageStartedAt),
        pointerEvents: interaction.pointerEvents,
        keyEvents: interaction.keyEvents,
      },
      runtimeEvidence: {
        navigationProtocolCategory: navigationProtocolCategory(),
      },
    };
    history.push(summary);
    if (history.length > 6) history.shift();
    sessionStorage.setItem('botLabHistory', JSON.stringify(history));
    renderHistory();

    const stored = await postJson('/api/observe', { sessionId, ...summary });
    output.innerHTML = `
      <dl class="result-grid">
        <div class="result-item"><dt>Visitor ID</dt><dd><code>${escapeText(result.visitorId)}</code></dd></div>
        <div class="result-item"><dt>Library heuristic</dt><dd>${escapeText(summary.confidence)} <small>rough platform estimate—not identity or bot confidence</small></dd></div>
        <div class="result-item"><dt>Components</dt><dd>${components.length}</dd></div>
        <div class="result-item"><dt>Collection</dt><dd>${collectionMs} ms</dd></div>
        <div class="result-item"><dt>Temporary server tag</dt><dd><code>${escapeText(stored.observation.fingerprintTag)}</code></dd></div>
        <div class="result-item"><dt>Shadow score</dt><dd>${stored.observation.shadowScore} <small>${escapeText(stored.observation.shadowRules.join(', ') || 'no rules triggered')}</small></dd></div>
        <div class="result-item"><dt>Open-source BotD</dt><dd>${botd.available ? (botd.bot ? `Detected: ${escapeText(botd.kind || 'unknown')}` : 'No basic automation detected') : 'Unavailable'} <small>Client-reported baseline—not identity or enforcement</small></dd></div>
        <div class="result-item"><dt>Known-good proof</dt><dd>${stored.observation.verifiedAgent ? 'Verified first-party automation' : 'Not presented'} <small>Short-lived HMAC proof, separate from detection</small></dd></div>
        <div class="result-item"><dt>Session protection</dt><dd>Signed HttpOnly cookie</dd></div>
        <div class="result-item"><dt>Retention</dt><dd>${stored.retentionSeconds / 60} minutes</dd></div>
      </dl>`;
    renderComponentExplorer(components);
    await refreshStats();
    await refreshReport();
    await refreshShadowReport();
  } catch (caught) {
    output.textContent = `Fingerprint run failed: ${caught.message}`;
  } finally {
    runButton.disabled = false;
  }
});

challengeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  challengeOutput.textContent = 'Checking the proof on the server…';
  try {
    const payload = new FormData(challengeForm).get('altcha');
    if (!payload) throw new Error('Complete the proof-of-work challenge first.');
    const result = await postJson('/api/verify', { payload, sessionId });
    challengeOutput.textContent = `Verified. Server check: ${result.verificationMs} ms. Replay protection: ${result.replayProtected ? 'on' : 'off'}.`;
    await refreshStats();
  } catch (caught) {
    challengeOutput.textContent = caught.message;
    await refreshStats().catch(() => {});
  }
});

$('#clear-local').addEventListener('click', () => {
  history.splice(0, history.length);
  sessionStorage.removeItem('botLabHistory');
  output.textContent = 'Local run data cleared.';
  componentExplorer.hidden = true;
  componentExplorer.replaceChildren();
  renderHistory();
});

$('#export-report').addEventListener('click', async () => {
  reportStatus.textContent = 'Preparing aggregate JSON…';
  try {
    const report = await fetchReport();
    const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `bot-lab-report-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    reportStatus.textContent = 'Aggregate report exported. It contains no fingerprint or session tags.';
  } catch (caught) {
    reportStatus.textContent = caught.message;
  }
});

$('#export-shadow-report').addEventListener('click', async () => {
  shadowStatus.textContent = 'Preparing shadow report…';
  try {
    const report = await fetchShadowReport();
    const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `bot-lab-shadow-report-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    shadowStatus.textContent = 'Shadow report exported. No request was blocked or challenged.';
  } catch (caught) {
    shadowStatus.textContent = caught.message;
  }
});

loadTurnstileButton.addEventListener('click', async () => {
  loadTurnstileButton.disabled = true;
  turnstileOutput.textContent = 'Loading Cloudflare Turnstile…';
  try {
    await ensureBrowserSession();
    await loadScript('https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit');
    const tokenTimeout = setTimeout(() => {
      if (!turnstileToken) {
        turnstileOutput.textContent = 'Turnstile timed out before returning a token. Reload and check Safari content blockers or Private Relay.';
      }
    }, 15_000);
    window.turnstile.render('#turnstile-widget', {
      sitekey: turnstileConfig.sitekey,
      action: turnstileConfig.action,
      theme: 'dark',
      callback(token) {
        clearTimeout(tokenTimeout);
        turnstileToken = token;
        verifyTurnstileButton.disabled = false;
        turnstileOutput.textContent = 'Cloudflare returned a token. It has not yet been verified by Bot Lab.';
      },
      'expired-callback'() {
        clearTimeout(tokenTimeout);
        turnstileToken = '';
        verifyTurnstileButton.disabled = true;
        turnstileOutput.textContent = 'Turnstile token expired. Reload the comparison.';
      },
      'error-callback'(code) {
        clearTimeout(tokenTimeout);
        turnstileOutput.textContent = `Turnstile reported client error ${String(code || 'unknown')}. Reload and check Safari content blockers or Private Relay.`;
      },
    });
  } catch (caught) {
    turnstileOutput.textContent = caught.message;
    loadTurnstileButton.disabled = false;
  }
});

verifyTurnstileButton.addEventListener('click', async () => {
  verifyTurnstileButton.disabled = true;
  turnstileOutput.textContent = 'Validating the token server-side…';
  try {
    await ensureBrowserSession();
    const result = await postJson('/api/turnstile/verify', { token: turnstileToken });
    turnstileOutput.textContent = `Verified by Siteverify. Hostname: ${result.hostnameMatched ? 'matched' : 'mismatch'}. Action: ${result.actionMatched ? 'matched' : 'mismatch'}. Enforcement: ${result.enforcement ? 'on' : 'off'}.`;
    await refreshStats();
  } catch (caught) {
    turnstileOutput.textContent = caught.message;
    verifyTurnstileButton.disabled = !turnstileToken;
  }
});

renderHistory();
refreshStats().catch(() => { statsOutput.textContent = 'Stats unavailable.'; });
refreshReport().catch(() => { reportStatus.textContent = 'Comparison report unavailable.'; });
refreshShadowReport().catch(() => { shadowStatus.textContent = 'Shadow report unavailable.'; });
configureTurnstile().catch(() => { turnstileOutput.textContent = 'Turnstile configuration unavailable.'; });
