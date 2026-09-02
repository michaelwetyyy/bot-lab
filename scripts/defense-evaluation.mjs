import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { assertAggregateOnly, plateauReached } from './campaign-aggregate.mjs';

const execFileAsync = promisify(execFile);
const context = process.env.BOT_LAB_KUBE_CONTEXT || 'homelab';
if (context !== 'homelab') throw new Error('BOT_LAB_KUBE_CONTEXT must be homelab');
const namespace = 'bot-lab';
const MIN_RUNS = 3;
const MAX_RUNS = 5;
const PLATEAU_WINDOW = 3;
const testAddresses = {
  normal: '192.0.2.140',
  attack: ['192.0.2.141', '192.0.2.142', '192.0.2.143', '192.0.2.144', '192.0.2.145'],
  browser: '192.0.2.146',
  crawler: '192.0.2.147',
  crowdsec: '192.0.2.148',
};

let portForward;
const cleanupFailures = [];
const decisionsToRemove = new Set(testAddresses.attack);
decisionsToRemove.add(testAddresses.crowdsec);

async function kubectl(args) {
  return execFileAsync('kubectl', ['--context', context, '-n', namespace, ...args], { maxBuffer: 4 * 1024 * 1024 });
}

async function podFor(selector) {
  const { stdout } = await kubectl(['get', 'pod', '-l', selector, '-o', 'jsonpath={.items[0].metadata.name}']);
  const pod = stdout.trim();
  if (!/^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/.test(pod)) {
    throw new Error(`invalid or missing pod name for ${selector}`);
  }
  return pod;
}

async function requestStatus(pod, { path, address, userAgent }) {
  if (!/^192\.0\.2\.(?:1[4-9]\d|2\d\d)$/.test(address)) throw new Error('request address is outside the test range');
  if (!/^\/[a-z0-9/_?=&%.-]*$/i.test(path)) throw new Error('request path is outside the synthetic allow-list');
  if (userAgent && (/[\r\n]/.test(userAgent) || userAgent.length > 200)) throw new Error('invalid synthetic user agent');
  const args = [
    'exec', pod, '--', 'wget', '-qS', '-O', '/dev/null',
    `--header=CF-Connecting-IP: ${address}`,
  ];
  if (userAgent) args.push(`--user-agent=${userAgent}`);
  args.push(`http://bot-lab.bot-lab.svc.cluster.local${path}`);
  try {
    const result = await kubectl(args);
    const match = `${result.stdout}\n${result.stderr}`.match(/HTTP\/\S+\s+(\d{3})/);
    if (!match) throw new Error('gateway response did not include an HTTP status');
    return Number.parseInt(match[1], 10);
  } catch (caught) {
    const match = `${caught.stdout || ''}\n${caught.stderr || ''}`.match(/HTTP\/\S+\s+(\d{3})/);
    if (match) return Number.parseInt(match[1], 10);
    throw caught;
  }
}

async function runStatusPlateau({ name, layer, expectedStatus, execute }) {
  const statuses = [];
  for (let run = 0; run < MAX_RUNS; run += 1) {
    statuses.push(await execute(run));
    if (statuses.length >= MIN_RUNS && plateauReached(statuses.map(String), PLATEAU_WINDOW)) break;
  }
  const plateau = plateauReached(statuses.map(String), PLATEAU_WINDOW);
  return {
    name,
    layer,
    runs: statuses.length,
    plateau,
    expectedStatus,
    observedStatus: statuses.at(-1),
    passed: plateau && statuses.at(-1) === expectedStatus,
  };
}

async function startMetricsForward(pod) {
  portForward = spawn('kubectl', [
    '--context', context, '-n', namespace, 'port-forward', `pod/${pod}`, ':9090',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Anubis metrics port-forward timed out')), 10_000);
    const inspect = (chunk) => {
      const text = chunk.toString();
      const match = text.match(/Forwarding from 127\.0\.0\.1:(\d+) -> 9090/);
      if (match) {
        clearTimeout(timer);
        resolve(Number.parseInt(match[1], 10));
      }
      if (/error|unable/i.test(text)) {
        clearTimeout(timer);
        reject(new Error('Anubis metrics port-forward failed'));
      }
    };
    portForward.stdout.on('data', inspect);
    portForward.stderr.on('data', inspect);
    portForward.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Anubis metrics port-forward exited (${code})`));
    });
  });
  return `http://127.0.0.1:${port}/metrics`;
}

async function fetchMetrics(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(5_000) });
  if (!response.ok) throw new Error(`Anubis metrics returned ${response.status}`);
  return response.text();
}

function metricValue(metrics, rule) {
  const line = metrics.split('\n').find((entry) => (
    entry.startsWith('anubis_policy_results{') && entry.includes(`rule="${rule}"`)
  ));
  return line ? Number.parseFloat(line.trim().split(/\s+/).at(-1)) : 0;
}

async function waitForDecision(pod, appsecPod) {
  await kubectl([
    'exec', pod, '--', 'cscli', 'decisions', 'add', '--ip', testAddresses.crowdsec,
    '--duration', '2m', '--reason', 'bot-lab-synthetic-evaluation', '--type', 'ban',
  ]);
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const status = await requestStatus(appsecPod, {
      path: '/healthz', address: testAddresses.crowdsec, userAgent: 'Mozilla/5.0 Chrome/152.0',
    });
    if (status === 403) return;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error('CrowdSec bouncer did not observe the synthetic decision');
}

try {
  const [appsecPod, lapiPod, anubisPod] = await Promise.all([
    podFor('k8s-app=crowdsec,type=appsec'),
    podFor('k8s-app=crowdsec,type=lapi'),
    podFor('app.kubernetes.io/name=bot-lab-anubis'),
  ]);
  const metricsUrl = await startMetricsForward(anubisPod);
  const beforeMetrics = await fetchMetrics(metricsUrl);

  const scenarios = [];
  scenarios.push(await runStatusPlateau({
    name: 'ordinary-root', layer: 'Coraza and Anubis bypass', expectedStatus: 200,
    execute: () => requestStatus(appsecPod, {
      path: '/', address: testAddresses.normal, userAgent: 'Mozilla/5.0 Chrome/152.0',
    }),
  }));
  scenarios.push(await runStatusPlateau({
    name: 'synthetic-sqli', layer: 'Coraza OWASP CRS', expectedStatus: 403,
    execute: (run) => requestStatus(appsecPod, {
      path: '/?id=1%20AND%201=1', address: testAddresses.attack[run], userAgent: 'Mozilla/5.0 Chrome/152.0',
    }),
  }));
  scenarios.push(await runStatusPlateau({
    name: 'browser-demo-challenge', layer: 'Anubis browser tier', expectedStatus: 200,
    execute: () => requestStatus(appsecPod, {
      path: '/protected-demo', address: testAddresses.browser,
      userAgent: 'Mozilla/5.0 Chrome/152.0 Safari/537.36',
    }),
  }));
  scenarios.push(await runStatusPlateau({
    name: 'crawler-demo-challenge', layer: 'Anubis crawler-labelled tier', expectedStatus: 200,
    execute: () => requestStatus(appsecPod, {
      path: '/protected-demo', address: testAddresses.crawler, userAgent: 'SyntheticCrawler/1.0',
    }),
  }));

  await waitForDecision(lapiPod, appsecPod);
  scenarios.push(await runStatusPlateau({
    name: 'synthetic-local-decision', layer: 'CrowdSec bouncer', expectedStatus: 403,
    execute: () => requestStatus(appsecPod, {
      path: '/healthz', address: testAddresses.crowdsec, userAgent: 'Mozilla/5.0 Chrome/152.0',
    }),
  }));

  const afterMetrics = await fetchMetrics(metricsUrl);
  const browserMetricDelta = metricValue(afterMetrics, 'threshold/challenge-demo-browser')
    - metricValue(beforeMetrics, 'threshold/challenge-demo-browser');
  const crawlerMetricDelta = metricValue(afterMetrics, 'threshold/challenge-demo-automation')
    - metricValue(beforeMetrics, 'threshold/challenge-demo-automation');
  if (browserMetricDelta < MIN_RUNS || crawlerMetricDelta < MIN_RUNS) {
    throw new Error('Anubis did not record both expected challenge tiers');
  }

  const capi = await kubectl(['exec', lapiPod, '--', 'cscli', 'capi', 'status']);
  const capiText = `${capi.stdout}\n${capi.stderr}`;
  const crowdsecMode = {
    authenticated: capiText.includes('successfully interact with Central API'),
    sharing: !capiText.includes('Sharing signals is disabled'),
    communityPull: capiText.includes('Pulling community blocklist is enabled'),
    subscribedPull: capiText.includes('Pulling blocklists from the console is enabled'),
  };
  if (!crowdsecMode.authenticated || crowdsecMode.sharing || !crowdsecMode.communityPull) {
    throw new Error('CrowdSec CAPI boundary did not match pull-only policy');
  }

  const browserCampaign = JSON.parse((await execFileAsync(
    process.execPath,
    ['scripts/labelled-browser-campaign.mjs'],
    { cwd: fileURLToPath(new URL('..', import.meta.url)), maxBuffer: 8 * 1024 * 1024 },
  )).stdout);
  const browserSummary = {
    conditions: browserCampaign.aggregate.conditionCount,
    observations: browserCampaign.aggregate.observations,
    plateauConditions: browserCampaign.aggregate.plateauConditions,
    botdAvailable: browserCampaign.aggregate.botdAvailable,
    botdDetected: browserCampaign.aggregate.openSourceBotd.automationDetected,
    customShadowWouldReview: browserCampaign.aggregate.customShadow.automationWouldReview,
    enforcement: browserCampaign.enforcement,
  };

  const output = {
    evaluation: 'Bot Lab unified defensive-layer campaign',
    scope: 'synthetic localhost and RFC 5737 in-cluster traffic only',
    plateauPolicy: { minimumRuns: MIN_RUNS, maximumRuns: MAX_RUNS, identicalTrailingOutcomes: PLATEAU_WINDOW },
    scenarios,
    layers: {
      botd: browserSummary,
      coraza: { inBand: true, syntheticRule: '942100' },
      anubis: { browserTierObservations: browserMetricDelta, crawlerTierObservations: crawlerMetricDelta },
      crowdsec: crowdsecMode,
    },
    passedScenarios: scenarios.filter((scenario) => scenario.passed).length,
    totalScenarios: scenarios.length,
    passed: scenarios.every((scenario) => scenario.passed),
    identifiersExported: false,
    interpretation: 'Results describe this installed configuration and synthetic corpus only; they are not general detection accuracy.',
  };
  assertAggregateOnly(output);
  console.log(JSON.stringify(output, null, 2));
} finally {
  if (portForward && portForward.exitCode === null) {
    const closed = once(portForward, 'close').catch(() => null);
    portForward.kill('SIGTERM');
    await Promise.race([closed, new Promise((resolve) => setTimeout(resolve, 2_000))]);
    if (portForward.exitCode === null) portForward.kill('SIGKILL');
  }
  const lapiPod = await podFor('k8s-app=crowdsec,type=lapi').catch(() => null);
  if (lapiPod) {
    for (const address of decisionsToRemove) {
      await kubectl(['exec', lapiPod, '--', 'cscli', 'decisions', 'delete', '--ip', address])
        .catch(() => cleanupFailures.push(address));
    }
  } else {
    cleanupFailures.push(...decisionsToRemove);
  }
  if (cleanupFailures.length) {
    console.error(`failed to verify cleanup for ${cleanupFailures.length} synthetic decision target(s)`);
    process.exitCode = 1;
  }
}
