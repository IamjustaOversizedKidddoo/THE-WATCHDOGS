'use strict';

/**
 * Addition 1: Continuous Recon Mode for /jonathan Tests
 *
 * Verifies:
 *  1. Target whitelist & configurable per-target interval (defaulting to 6 hours).
 *  2. Strict guardrail: unlisted targets are rejected and never scanned.
 *  3. Workspace persistence: snapshots stored in hive/agents/jonathan/recon/<target>/<date>.json.
 *  4. Diff computation: computes newly discovered subdomains, endpoints, and changed tech signals.
 *  5. Delta-only alerting:
 *     - Run 1 (initial assets): delivers delta summary to /michael.
 *     - Run 2 (identical static assets): delta is empty -> ZERO alerts to /michael.
 *     - Run 3 (new asset discovered): delivers delta containing ONLY the newly discovered asset.
 *  6. On-demand single-run mode remains completely untouched and independent.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');
const {
  JonathanContinuousReconService,
  DEFAULT_RECON_INTERVAL_MS
} = loadTs('src/main/jonathanContinuousRecon.ts');

async function createWatchdogsFloor(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-recon-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);

  await hive.ensureAgent({ id: 'michael', name: 'Michael', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'jonathan', name: 'Jonathan', provider: 'hackergpt', cwd: home });

  return { home, hive };
}

test('Continuous Recon: Default 6-hour interval and per-target interval configuration', () => {
  assert.equal(DEFAULT_RECON_INTERVAL_MS, 6 * 60 * 60 * 1000, 'Default interval must be 6 hours (21600000 ms)');

  const service = new JonathanContinuousReconService(() => null);

  // Target 1: Unspecified interval -> defaults to 6 hours
  service.addTarget({ target: 'example.com' });
  const cfg1 = service.getTargetConfig('example.com');
  assert.notEqual(cfg1, null);
  assert.equal(cfg1.intervalMs, 21600000);

  // Target 2: Explicitly configured interval (e.g. 2 hours)
  service.addTarget({ target: 'fast-churn.org', intervalMs: 2 * 60 * 60 * 1000 });
  const cfg2 = service.getTargetConfig('fast-churn.org');
  assert.notEqual(cfg2, null);
  assert.equal(cfg2.intervalMs, 7200000);

  // Listing targets
  const all = service.listTargets();
  assert.equal(all.length, 2);
});

test('Continuous Recon: Strict guardrail prevents scanning unlisted targets', async (t) => {
  const { hive } = await createWatchdogsFloor(t);
  const service = hive.jonathanReconService;

  // Authorize only 'authorized-scope.com'
  service.setTargetWhitelist([{ target: 'authorized-scope.com' }]);

  assert.equal(service.isTargetAuthorized('authorized-scope.com'), true);
  assert.equal(service.isTargetAuthorized('unauthorized-target.com'), false);

  // Attempt to scan unlisted target must throw
  await assert.rejects(
    async () => {
      await service.executeScheduledRun('unauthorized-target.com');
    },
    /not on the human-provided continuous recon whitelist/
  );

  // No messages sent to Michael
  assert.equal(hive.inbox('michael').length, 0);
});

test('Continuous Recon: Snapshots are persisted in hive agent workspace keyed by date and timestamp', async (t) => {
  const { home, hive } = await createWatchdogsFloor(t);
  const service = hive.jonathanReconService;

  service.addTarget({ target: 'store-test.lab' });

  await service.executeScheduledRun('store-test.lab', {
    timestamp: '2026-09-13T10:00:00.000Z',
    subdomains: ['api.store-test.lab'],
    endpoints: ['/health'],
    techSignals: { server: 'nginx/1.24' }
  });

  const reconDir = service.getTargetReconDir('store-test.lab');
  assert.notEqual(reconDir, null);
  assert.equal(fs.existsSync(reconDir), true, 'Recon directory must exist in Jonathan workspace');

  const files = fs.readdirSync(reconDir);
  assert.equal(files.length, 1);
  assert.match(files[0], /2026-09-13/);

  const snapshot = JSON.parse(fs.readFileSync(path.join(reconDir, files[0]), 'utf8'));
  assert.equal(snapshot.target, 'store-test.lab');
  assert.equal(snapshot.dateKey, '2026-09-13');
  assert.deepEqual(snapshot.subdomains, ['api.store-test.lab']);
});

test('Continuous Recon: Delta computation diffs newly discovered assets and tech changes', () => {
  const service = new JonathanContinuousReconService(() => null);

  const prior = {
    target: 'diff-test.lab',
    timestamp: '2026-09-13T06:00:00.000Z',
    dateKey: '2026-09-13',
    subdomains: ['www.diff-test.lab', 'api.diff-test.lab'],
    endpoints: ['/login', '/v1/users'],
    techSignals: { server: 'nginx/1.24', 'x-powered-by': 'Express' }
  };

  const current = {
    target: 'diff-test.lab',
    timestamp: '2026-09-13T12:00:00.000Z',
    dateKey: '2026-09-13',
    subdomains: ['www.diff-test.lab', 'api.diff-test.lab', 'staging.diff-test.lab'],
    endpoints: ['/login', '/v1/users', '/v1/metrics'],
    techSignals: { server: 'nginx/1.26', 'x-powered-by': 'Express', 'x-env': 'staging' }
  };

  const delta = service.computeDelta(current, prior);

  assert.equal(delta.isEmpty, false);
  assert.deepEqual(delta.newSubdomains, ['staging.diff-test.lab']);
  assert.deepEqual(delta.newEndpoints, ['/v1/metrics']);
  assert.equal(delta.changedTechSignals.length, 2);

  const serverSignal = delta.changedTechSignals.find((s) => s.signal === 'server');
  assert.equal(serverSignal.oldVal, 'nginx/1.24');
  assert.equal(serverSignal.newVal, 'nginx/1.26');

  const envSignal = delta.changedTechSignals.find((s) => s.signal === 'x-env');
  assert.equal(envSignal.newVal, 'staging');
});

test('Continuous Recon: Delta-only alerting — consecutive runs on static target produce NO alert on second run', async (t) => {
  const { hive } = await createWatchdogsFloor(t);
  const service = hive.jonathanReconService;

  const target = 'static-bounty.target';
  service.addTarget({ target, intervalMs: 21600000 });

  // ── Run 1: Initial Discovery ───────────────────────────────────────────────
  const run1Snapshot = {
    timestamp: '2026-09-13T00:00:00.000Z',
    subdomains: ['app.static-bounty.target'],
    endpoints: ['/api/v1/status'],
    techSignals: { server: 'cloudflare' }
  };

  const delta1 = await service.executeScheduledRun(target, run1Snapshot);
  assert.equal(delta1.isEmpty, false, 'Run 1 has initial discovered assets');

  // Verify /michael receives Run 1 alert
  const michaelInboxAfterRun1 = hive.inbox('michael');
  assert.equal(michaelInboxAfterRun1.length, 1, 'Michael must receive initial delta report');
  assert.equal(michaelInboxAfterRun1[0].from, 'jonathan');
  assert.equal(michaelInboxAfterRun1[0].act, 'inform');
  assert.match(michaelInboxAfterRun1[0].subject, /static-bounty\.target/);
  assert.match(michaelInboxAfterRun1[0].body, /app\.static-bounty\.target/);

  // ── Run 2: Consecutive run on static target (identical assets) ─────────────
  const run2Snapshot = {
    timestamp: '2026-09-13T06:00:00.000Z',
    subdomains: ['app.static-bounty.target'],
    endpoints: ['/api/v1/status'],
    techSignals: { server: 'cloudflare' }
  };

  const delta2 = await service.executeScheduledRun(target, run2Snapshot);
  assert.equal(delta2.isEmpty, true, 'Run 2 against static target must produce an empty delta');

  // CRITICAL REQUIREMENT: Empty delta must do NOTHING (no new message to /michael)
  const michaelInboxAfterRun2 = hive.inbox('michael');
  assert.equal(
    michaelInboxAfterRun2.length,
    1,
    'Michael inbox MUST STILL have exactly 1 message — zero alerts sent for static delta!'
  );

  // ── Run 3: New asset appears on target ─────────────────────────────────────
  const run3Snapshot = {
    timestamp: '2026-09-13T12:00:00.000Z',
    subdomains: ['app.static-bounty.target', 'admin-internal.static-bounty.target'],
    endpoints: ['/api/v1/status', '/admin/debug'],
    techSignals: { server: 'cloudflare' }
  };

  const delta3 = await service.executeScheduledRun(target, run3Snapshot);
  assert.equal(delta3.isEmpty, false, 'Run 3 has newly discovered assets');
  assert.deepEqual(delta3.newSubdomains, ['admin-internal.static-bounty.target']);
  assert.deepEqual(delta3.newEndpoints, ['/admin/debug']);

  // Michael receives Run 3 alert with ONLY the new items
  const michaelInboxAfterRun3 = hive.inbox('michael');
  assert.equal(michaelInboxAfterRun3.length, 2, 'Michael must receive alert for Run 3');
  const alertMsg = michaelInboxAfterRun3[1];
  assert.match(alertMsg.body, /admin-internal\.static-bounty\.target/);
  assert.match(alertMsg.body, /\/admin\/debug/);
  // Must NOT list old assets as new
  assert.doesNotMatch(alertMsg.body, /Newly Discovered Subdomains.*app\.static-bounty\.target/s);
});

test('Continuous Recon: On-demand single-run mode is untouched and functions independently', async (t) => {
  const { hive } = await createWatchdogsFloor(t);

  // On-demand message sent directly to Jonathan
  const onDemandMsg = {
    id: 'ondemand-recon-01',
    conversation: 'conv-recon-1',
    in_reply_to: null,
    to: 'jonathan',
    act: 'request',
    subject: 'Perform single-run OSINT against target.lab',
    body: 'Run passive subdomain enumeration and return raw findings'
  };

  hive.send(onDemandMsg, 'michael');

  const jonathanInbox = hive.inbox('jonathan');
  assert.equal(jonathanInbox.length, 1, 'Jonathan receives standard on-demand request');
  assert.equal(jonathanInbox[0].id, 'ondemand-recon-01');
  assert.equal(jonathanInbox[0].from, 'michael');
});
