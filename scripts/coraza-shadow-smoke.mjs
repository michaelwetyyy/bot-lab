import { execFile, spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const image = 'ghcr.io/coreruleset/coraza-crs@sha256:f7a92973e92f89c13d20e7c0915ada9e77513b3d9a4094306bc3453e8cd2f59f';
const ruleEngine = process.env.BOT_LAB_CORAZA_MODE === 'On' ? 'On' : 'DetectionOnly';
const containerName = `bot-lab-coraza-${ruleEngine.toLowerCase()}-${process.pid}`;
let application;
let containerStarted = false;

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
      if (response.ok) return response;
    } catch {
      // The process may still be starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('shadow proxy did not become ready');
}

async function waitForRule(ruleId, attempts = 20) {
  const observedRuleIds = new Set();
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const logs = await execFileAsync('docker', ['logs', containerName]);
    const output = `${logs.stdout}\n${logs.stderr}`;
    const normalized = output.replaceAll(String.raw`\"`, '"');
    for (const match of normalized.matchAll(/\[id "(\d+)"\]/g)) observedRuleIds.add(match[1]);
    if (normalized.includes(`[id "${ruleId}"]`)) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Coraza did not report expected synthetic rule ${ruleId}; observed ${[...observedRuleIds].join(', ') || 'none'}`);
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
  const backendPort = await freePort();
  application = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, HOST: '0.0.0.0', PORT: String(backendPort) },
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  await waitFor(`http://127.0.0.1:${backendPort}/healthz`);

  await execFileAsync('docker', [
    'run', '--rm', '-d', '--name', containerName,
    '-p', '127.0.0.1::8080',
    '-e', `BACKEND=host.docker.internal:${backendPort}`,
    '-e', `CORAZA_RULE_ENGINE=${ruleEngine}`,
    '-e', 'CORAZA_AUDIT_ENGINE=RelevantOnly',
    '-e', 'CORAZA_AUDIT_LOG=/dev/stdout',
    '-e', 'CORAZA_AUDIT_LOG_PARTS=AHZ',
    '-e', 'ACCESSLOG=/dev/null',
    image,
  ]);
  containerStarted = true;

  const portResult = await execFileAsync('docker', ['port', containerName, '8080/tcp']);
  const proxyPort = Number.parseInt(portResult.stdout.trim().split(':').at(-1), 10);
  if (!Number.isInteger(proxyPort)) throw new Error('unable to resolve shadow proxy port');
  const base = `http://127.0.0.1:${proxyPort}`;
  await waitFor(`${base}/healthz`);

  const normal = await fetch(base);
  const health = await fetch(`${base}/healthz`);
  const stats = await fetch(`${base}/api/stats`);
  const syntheticAttack = await fetch(`${base}/?id=1%20AND%201=1`);
  await waitForRule('942100');
  if (normal.status !== 200 || health.status !== 200 || stats.status !== 200) {
    throw new Error(`${ruleEngine} rejected an ordinary Bot Lab route`);
  }
  const expectedAttackStatus = ruleEngine === 'On' ? 403 : 200;
  if (syntheticAttack.status !== expectedAttackStatus) {
    throw new Error(`${ruleEngine} returned ${syntheticAttack.status} for the synthetic attack; expected ${expectedAttackStatus}`);
  }

  console.log(JSON.stringify({
    image,
    ruleEngine,
    normalStatus: normal.status,
    healthStatus: health.status,
    statsStatus: stats.status,
    syntheticAttackStatus: syntheticAttack.status,
    detectedRule: '942100',
    enforcement: ruleEngine === 'On',
    persistentAuditLog: false,
  }, null, 2));
} finally {
  if (containerStarted) {
    await execFileAsync('docker', ['stop', containerName]).catch(() => {});
  }
  await stopApplication();
}
