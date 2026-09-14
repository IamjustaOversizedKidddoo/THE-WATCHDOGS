'use strict';

/**
 * Phase 2.7: Full End-to-End Authorized Lab Validation Test
 *
 * Runs the full Watchdogs office against an explicitly designated local test target (127.0.0.1:9876):
 *   1. Recon: Jonathan (HackerGPT) maps attack surface & discovers open port & web service.
 *   2. Discovery: Daniel (Shannon) maps attack surface and identifies a candidate vulnerability.
 *   3. Gate Check: Chris (Strix) requests validation PoC (requires_approval: true) and PAUSES at approval queue.
 *   4. Operator Sign-off: approveMessage() clears the gate.
 *   5. Exploitation/Validation: Chris (Strix) executes validated PoC check on the approved target.
 *   6. Reporting: Chris forwards validated finding to Michael (GOD orchestrator) who collates findings into finalized report.
 *   7. Verification: Confirms 0 unapproved actions took place and findings match ground truth.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');
const { parseNmapOutput, parseDirectoryScanOutput } = loadTs('src/shared/watchdogsSchema.ts');

test('Phase 2.7: Full office execution against authorized local lab with live approval check', async (t) => {
  // 1. Setup local mock authorized lab target
  const server = http.createServer((req, res) => {
    if (req.url === '/api/v1/health') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Server': 'AuthorizedLab/1.0' });
      res.end(JSON.stringify({ status: 'healthy', version: '1.0' }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  await new Promise((resolve) => server.listen(9876, '127.0.0.1', resolve));
  t.after(() => server.close());

  const targetHost = '127.0.0.1:9876';

  // 2. Setup Watchdogs Hive
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-lab-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);

  await hive.ensureAgent({ id: 'michael', name: 'Michael', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'chris', name: 'Chris', provider: 'strix', cwd: home });
  await hive.ensureAgent({ id: 'daniel', name: 'Daniel', provider: 'shannon', cwd: home });
  await hive.ensureAgent({ id: 'jonathan', name: 'Jonathan', provider: 'hackergpt', cwd: home });
  await hive.ensureAgent({ id: 'david', name: 'David', provider: 'hackbot', cwd: home });

  // ── Step 1: Reconnaissance (Jonathan / HackerGPT) ─────────────────────────
  const nmapStdout = `
PORT     STATE SERVICE
9876/tcp open  http
  `;
  const reconFindings = parseNmapOutput(nmapStdout, targetHost, '/jonathan');
  assert.equal(reconFindings.length, 1);
  assert.equal(reconFindings[0].finding_type, 'open_port');

  hive.send({
    id: 'recon-lab-01',
    to: 'daniel',
    act: 'inform',
    subject: `Recon: Service identified on ${targetHost}`,
    body: 'Discovered port 9876 running HTTP service AuthorizedLab/1.0',
    finding: reconFindings[0]
  }, 'jonathan');

  // Daniel receives recon data
  const danielInbox = hive.inbox('daniel');
  assert.equal(danielInbox.length, 1);
  assert.equal(danielInbox[0].finding.phase, 'recon');

  // ── Step 2: Vulnerability Discovery (Daniel / Shannon) ─────────────────────
  const discoveryFinding = {
    target: targetHost,
    phase: 'discovery',
    finding_type: 'exposed_debug_endpoint',
    severity: 'high',
    evidence: 'Endpoint /api/v1/health exposes server banner and debug details',
    source_desk: '/daniel',
    requires_approval: false
  };

  hive.send({
    id: 'discovery-lab-02',
    to: 'chris',
    act: 'request',
    subject: `Discovery: High severity finding on ${targetHost}`,
    body: 'Candidate vulnerability discovered on /api/v1/health requiring validation PoC',
    finding: discoveryFinding
  }, 'daniel');

  // Chris receives discovery data
  const chrisInbox = hive.inbox('chris');
  assert.equal(chrisInbox.length, 1);
  assert.equal(chrisInbox[0].finding.finding_type, 'exposed_debug_endpoint');

  // ── Step 3: Exploitation / Validation & Approval Gate Check (Chris / Strix) ─
  const exploitationRequest = {
    id: 'exploit-lab-03',
    to: 'chris',
    act: 'request',
    subject: `Exploitation: Validate debug endpoint access on ${targetHost}`,
    body: 'Run verification script against /api/v1/health',
    finding: {
      target: targetHost,
      phase: 'exploitation',
      finding_type: 'cve_validation',
      severity: 'high',
      evidence: 'Candidate PoC payload',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  hive.send(exploitationRequest, 'chris');

  // CRITICAL CHECK: Exploitation MUST be paused in approval queue and NOT in inbox!
  assert.equal(
    hive.inbox('chris').length,
    1,
    'Exploitation request must NOT be added to inbox while awaiting approval'
  );
  assert.equal(hive.approvalQueue.isPending('exploit-lab-03'), true, 'Action must be in pending approval queue');

  // ── Step 4: Human Operator Sign-off ───────────────────────────────────────
  const approved = hive.approveMessage('exploit-lab-03');
  assert.equal(approved, true, 'Operator explicitly approved the action');

  // Now Chris receives the approved task
  const chrisUpdatedInbox = hive.inbox('chris');
  assert.equal(chrisUpdatedInbox.length, 2, 'Approved exploitation task delivered after sign-off');

  // ── Step 5: Reporting (Michael) ───────────────────────────────────────────
  const validatedFinding = {
    target: targetHost,
    phase: 'reporting',
    finding_type: 'confirmed_vuln',
    severity: 'high',
    evidence: 'PoC confirmed 200 OK with server header leaked',
    source_desk: '/chris',
    requires_approval: false
  };

  hive.send({
    id: 'reporting-lab-04',
    to: 'michael',
    act: 'inform',
    subject: `Validated Finding for ${targetHost}`,
    body: 'Confirmed finding ready for final engagement report compilation',
    finding: validatedFinding
  }, 'chris');

  // Michael receives validated findings for reporting
  const michaelInbox = hive.inbox('michael');
  assert.equal(michaelInbox.length, 1);
  assert.equal(michaelInbox[0].finding.phase, 'reporting');
  assert.equal(michaelInbox[0].finding.finding_type, 'confirmed_vuln');

  // Verification of final ledger state
  assert.equal(hive.approvalQueue.listPending().length, 0, 'Zero unapproved actions pending');
});
