'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');

async function createFloor(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-bypass-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);

  await hive.ensureAgent({ id: 'michael', name: 'Michael', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'chris', name: 'Chris', provider: 'strix', cwd: home });
  await hive.ensureAgent({ id: 'daniel', name: 'Daniel', provider: 'shannon', cwd: home });
  await hive.ensureAgent({ id: 'jonathan', name: 'Jonathan', provider: 'hackergpt', cwd: home });
  await hive.ensureAgent({ id: 'david', name: 'David', provider: 'hackbot', cwd: home });
  await hive.ensureAgent({ id: 'hexstrike', name: 'HexStrike', provider: 'hexstrike', cwd: home });

  return { home, hive };
}

test('Bypass Attempt 1: State machine exploitation message MUST pause at approval queue', async (t) => {
  const { hive } = await createFloor(t);

  const exploitMsg = {
    id: 'exploit-msg-1',
    to: 'chris',
    act: 'request',
    subject: 'Run exploit PoC',
    body: 'Trigger payload on authorized target',
    finding: {
      target: 'authorized.lab',
      phase: 'exploitation',
      finding_type: 'cve_poc',
      severity: 'critical',
      evidence: 'Validated candidate',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  hive.send(exploitMsg, 'daniel');

  // Must NOT reach Chris's inbox!
  assert.equal(hive.inbox('chris').length, 0, 'Exploitation message MUST NOT reach recipient inbox');

  // Must be in pending approval queue
  const pending = hive.approvalQueue.listPending();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].id, 'exploit-msg-1');
});

test('Bypass Attempt 2: Direct callsign addressing (/chris) with requires_approval MUST NOT bypass queue', async (t) => {
  const { hive } = await createFloor(t);

  const directMsg = {
    id: 'direct-exploit-2',
    to: 'michael', // Initially addressed to Michael or system
    act: 'request',
    subject: '/chris launch active exploit against authorized.lab',
    body: '/chris launch active exploit against authorized.lab',
    finding: {
      target: 'authorized.lab',
      phase: 'exploitation',
      finding_type: 'cve_poc',
      severity: 'critical',
      evidence: 'Operator direct address',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  hive.send(directMsg, 'operator');

  // Must NOT reach Chris's inbox directly!
  assert.equal(hive.inbox('chris').length, 0, 'Direct-addressed exploitation MUST NOT reach recipient inbox');

  // Must be paused in pending approvals
  assert.equal(hive.approvalQueue.isPending('direct-exploit-2'), true);
});

test('Bypass Attempt 3: Outbox routing through routeOnce MUST stop at approval queue', async (t) => {
  const { home, hive } = await createFloor(t);

  const jonathanOutbox = path.join(home, 'hive', 'agents', 'jonathan', 'outbox');
  const outboxFile = path.join(jonathanOutbox, 'exploit-drop.json');

  const fileMsg = {
    id: 'outbox-drop-3',
    to: 'chris',
    act: 'request',
    subject: 'Outbox drop exploit attempt',
    body: 'Run exploitation payload',
    finding: {
      target: 'authorized.lab',
      phase: 'exploitation',
      finding_type: 'cve_poc',
      severity: 'critical',
      evidence: 'Outbox dropped payload',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  fs.writeFileSync(outboxFile, JSON.stringify(fileMsg), 'utf8');

  // Route passes
  hive.routeOnce();

  // Chris's inbox must be empty
  assert.equal(hive.inbox('chris').length, 0, 'Outbox-dropped exploitation MUST NOT reach recipient inbox');

  // Must be in pending queue
  assert.equal(hive.approvalQueue.isPending('outbox-drop-3'), true);
});

test('Approval Execution: Approved message delivers, Rejected message drops', async (t) => {
  const { hive } = await createFloor(t);

  const approvedMsg = {
    id: 'approved-msg-4',
    to: 'chris',
    act: 'request',
    subject: 'Authorized test',
    body: 'Run approved validation test',
    finding: {
      target: 'authorized.lab',
      phase: 'exploitation',
      finding_type: 'cve_poc',
      severity: 'high',
      evidence: 'Approved evidence',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  hive.send(approvedMsg, 'system');
  assert.equal(hive.inbox('chris').length, 0);

  // Human approves
  const approved = hive.approveMessage('approved-msg-4');
  assert.equal(approved, true);

  // Now Chris receives the message!
  const chrisInbox = hive.inbox('chris');
  assert.equal(chrisInbox.length, 1);
  assert.equal(chrisInbox[0].id, 'approved-msg-4');

  // Second test: rejection
  const rejectedMsg = {
    id: 'rejected-msg-5',
    to: 'chris',
    act: 'request',
    subject: 'Unapproved test',
    body: 'Run unapproved test',
    finding: {
      target: 'authorized.lab',
      phase: 'exploitation',
      finding_type: 'cve_poc',
      severity: 'high',
      evidence: 'Unapproved evidence',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  hive.send(rejectedMsg, 'system');
  assert.equal(hive.approvalQueue.isPending('rejected-msg-5'), true);

  // Human rejects
  const rejected = hive.rejectMessage('rejected-msg-5', 'Denied by operator');
  assert.equal(rejected, true);

  // Still not in inbox
  assert.equal(hive.inbox('chris').length, 1, 'Rejected message must NEVER enter recipient inbox');
  assert.equal(hive.approvalQueue.isPending('rejected-msg-5'), false);
});
