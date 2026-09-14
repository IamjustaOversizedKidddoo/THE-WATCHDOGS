'use strict';

/**
 * Addition 6: /michael Parallel-Program Mode Tests
 *
 * Verifies:
 *  1. Every task carries an explicit program_id; unscheduled/uncertain program_id is refused.
 *  2. Approval gate cross-checks program_id against specific registry entry's in_scope list;
 *     deliberately mismatched program_id/target pair is strictly blocked.
 *  3. Individual approval presentation with prominent program_id; zero batch-approval paths exist.
 *  4. Per-task testing restrictions checked at scheduling time (time windows, prohibited methods).
 *  5. Concurrency architecture: /jonathan runs in genuine parallel across programs;
 *     /chris, /daniel, /david run in strictly single-concurrency FIFO queues (sequential).
 *  6. Configurable per-program pacing.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');
const { ApprovalQueue } = loadTs('src/main/approvalQueue.ts');
const {
  ProgramRegistryService,
  evaluateTestingRestrictions
} = loadTs('src/main/programRegistry.ts');
const { MichaelSchedulerService } = loadTs('src/main/michaelScheduler.ts');

function setupTestPrograms(registryDir) {
  fs.mkdirSync(registryDir, { recursive: true });

  // Program 1: Authorized Lab (24/7 testing, standard local lab)
  fs.writeFileSync(
    path.join(registryDir, 'authorized-lab.json'),
    JSON.stringify({
      program: 'authorized-lab',
      platform: 'local',
      in_scope: ['authorized.lab', '*.authorized.lab', '127.0.0.1'],
      excluded: ['*.authorized.lab/restricted/*'],
      testing_restrictions: 'Authorized local lab testing only',
      last_verified: '2026-09-13',
      verified_by: 'human'
    }, null, 2)
  );

  // Program 2: TargetCorp (Restricted testing window & no bruteforce)
  fs.writeFileSync(
    path.join(registryDir, 'targetcorp.json'),
    JSON.stringify({
      program: 'targetcorp',
      platform: 'hackerone',
      in_scope: ['targetcorp.com', '*.targetcorp.com'],
      excluded: ['payment.targetcorp.com'],
      testing_restrictions: 'time_window: 08:00-18:00 UTC. no_bruteforce. no_dos.',
      last_verified: '2026-09-13',
      verified_by: 'human'
    }, null, 2)
  );
}

test('Addition 6 — Every task carries an explicit program_id; unscheduled/missing is rejected', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-prog-id-'));
  try {
    const regDir = path.join(tmpDir, 'registry');
    setupTestPrograms(regDir);
    const regService = new ProgramRegistryService(regDir);
    const scheduler = new MichaelSchedulerService(regService);

    // 1. Valid task with confirmed program_id
    const validTask = scheduler.scheduleTask({
      program_id: 'authorized-lab',
      target: 'api.authorized.lab',
      targetDesk: '/jonathan',
      phase: 'recon',
      action: 'subdomain_enumeration'
    });
    assert.equal(validTask.success, true);
    assert.equal(validTask.task.program_id, 'authorized-lab');

    // 2. Task with second active program
    const validTask2 = scheduler.scheduleTask({
      program_id: 'targetcorp',
      target: 'api.targetcorp.com',
      targetDesk: '/jonathan',
      phase: 'recon',
      action: 'port_scan'
    }, { currentTime: new Date('2026-09-13T12:00:00Z') }); // within 08:00-18:00 UTC
    assert.equal(validTask2.success, true);
    assert.equal(validTask2.task.program_id, 'targetcorp');

    // 3. Attempt to schedule task WITHOUT program_id
    const missingTask = scheduler.scheduleTask({
      target: 'api.authorized.lab',
      targetDesk: '/jonathan',
      phase: 'recon',
      action: 'subdomain_enumeration'
    });
    assert.equal(missingTask.success, false);
    assert.match(missingTask.reason, /Missing or uncertain program_id/);

    // 4. Attempt to schedule task with unregistered program_id
    const unknownTask = scheduler.scheduleTask({
      program_id: 'unknown-corp-bounty',
      target: 'api.unknown.com',
      targetDesk: '/jonathan',
      phase: 'recon',
      action: 'subdomain_enumeration'
    });
    assert.equal(unknownTask.success, false);
    assert.match(unknownTask.reason, /not registered in program registry/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Addition 6 — Approval gate cross-checks program_id against specific registry scope; blocks mismatch', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-mismatch-'));
  try {
    const regDir = path.join(tmpDir, 'registry');
    setupTestPrograms(regDir);
    const regService = new ProgramRegistryService(regDir);
    const hive = new HiveManager(() => tmpDir, undefined, regService);

    // 1. Deliberately MISMATCHED pair:
    // Target is 'api.targetcorp.com' (valid for targetcorp), but tagged with program_id: 'authorized-lab'!
    const mismatchedMsg = {
      id: 'exploit-mismatch-01',
      conversation: 'conv-mismatch',
      in_reply_to: null,
      to: 'chris',
      from: 'michael',
      act: 'request',
      subject: 'Exploit SQLi on target',
      body: 'Verify injection on api.targetcorp.com',
      program_id: 'authorized-lab', // MISMATCH!
      finding: {
        target: 'api.targetcorp.com',
        program_id: 'authorized-lab', // MISMATCH!
        phase: 'exploitation',
        finding_type: 'sqli_poc',
        severity: 'critical',
        evidence: "1' OR 1=1--",
        source_desk: '/chris',
        requires_approval: true
      }
    };

    hive.approvalQueue.enqueue(mismatchedMsg);

    // Attempting to approve the mismatched action MUST be strictly blocked
    const approveResult = hive.approveMessage('exploit-mismatch-01');
    assert.equal(approveResult, false, 'Approval gate MUST BLOCK mismatched program_id and target');

    // 2. Properly matched pair:
    // Target is 'api.targetcorp.com' tagged with program_id: 'targetcorp'
    const matchedMsg = {
      id: 'exploit-matched-02',
      conversation: 'conv-matched',
      in_reply_to: null,
      to: 'chris',
      from: 'michael',
      act: 'request',
      subject: 'Exploit SQLi on target',
      body: 'Verify injection on api.targetcorp.com',
      program_id: 'targetcorp',
      finding: {
        target: 'api.targetcorp.com',
        program_id: 'targetcorp',
        phase: 'exploitation',
        finding_type: 'sqli_poc',
        severity: 'critical',
        evidence: "1' OR 1=1--",
        source_desk: '/chris',
        requires_approval: true
      }
    };

    hive.approvalQueue.enqueue(matchedMsg);

    // Properly matched action clears approval gate
    const matchedApproveResult = hive.approveMessage('exploit-matched-02');
    assert.equal(matchedApproveResult, true, 'Properly matched program_id and target must clear gate');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Addition 6 — No batch approval: individual presentation with prominent program_id; zero bulk methods', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-nobatch-'));
  try {
    const queue = new ApprovalQueue(() => tmpDir);

    const msg1 = {
      id: 'appr-01',
      program_id: 'program-alpha',
      finding: {
        target: 'alpha.corp.com',
        program_id: 'program-alpha',
        finding_type: 'rce',
        requires_approval: true
      },
      from: 'michael',
      to: 'chris',
      subject: 'RCE PoC execution',
      body: 'Testing command execution'
    };

    const msg2 = {
      id: 'appr-02',
      program_id: 'program-beta',
      finding: {
        target: 'beta.corp.com',
        program_id: 'program-beta',
        finding_type: 'ssrf',
        requires_approval: true
      },
      from: 'michael',
      to: 'chris',
      subject: 'SSRF PoC execution',
      body: 'Testing metadata access'
    };

    queue.enqueue(msg1);
    queue.enqueue(msg2);

    const pending = queue.listPending();
    assert.equal(pending.length, 2);

    // Check individual presentation highlights program_id prominently
    const p1 = pending.find(p => p.id === 'appr-01');
    assert.ok(p1.formattedDisplay.includes('[PROGRAM: program-alpha]'));
    assert.ok(p1.formattedDisplay.includes('Target: alpha.corp.com'));

    const p2 = pending.find(p => p.id === 'appr-02');
    assert.ok(p2.formattedDisplay.includes('[PROGRAM: program-beta]'));
    assert.ok(p2.formattedDisplay.includes('Target: beta.corp.com'));

    // Verify absence of any batch / bulk approval API on queue
    assert.equal(typeof queue.approveAll, 'undefined', 'ApprovalQueue MUST NOT have an approveAll method');
    assert.equal(typeof queue.bulkApprove, 'undefined', 'ApprovalQueue MUST NOT have a bulkApprove method');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Addition 6 — Per-program testing restrictions checked at scheduling time (windows & methods)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-restr-'));
  try {
    const regDir = path.join(tmpDir, 'registry');
    setupTestPrograms(regDir);
    const regService = new ProgramRegistryService(regDir);
    const scheduler = new MichaelSchedulerService(regService);

    // TargetCorp has: 'time_window: 08:00-18:00 UTC. no_bruteforce. no_dos.'

    // 1. Task outside time window (e.g. 23:00 UTC) -> MUST BE BLOCKED
    const lateNightTask = scheduler.scheduleTask({
      program_id: 'targetcorp',
      target: 'api.targetcorp.com',
      targetDesk: '/chris',
      phase: 'discovery',
      action: 'endpoint_check'
    }, { currentTime: new Date('2026-09-13T23:00:00Z') });

    assert.equal(lateNightTask.success, false, 'Must block task outside testing window');
    assert.match(lateNightTask.reason, /outside permitted testing window/);

    // 2. Task inside time window (e.g. 14:00 UTC) with forbidden method ('bruteforce') -> MUST BE BLOCKED
    const bruteforceTask = scheduler.scheduleTask({
      program_id: 'targetcorp',
      target: 'api.targetcorp.com',
      targetDesk: '/chris',
      phase: 'discovery',
      action: 'dir_bruteforce',
      method: 'bruteforce'
    }, { currentTime: new Date('2026-09-13T14:00:00Z') });

    assert.equal(bruteforceTask.success, false, 'Must block task with prohibited method');
    assert.match(bruteforceTask.reason, /forbids "bruteforce"/);

    // 3. Authorized lab task scheduled at the same time (no time restrictions) -> MUST PROCEED
    const labTask = scheduler.scheduleTask({
      program_id: 'authorized-lab',
      target: 'api.authorized.lab',
      targetDesk: '/chris',
      phase: 'discovery',
      action: 'validate_endpoint'
    }, { currentTime: new Date('2026-09-13T23:00:00Z') });

    assert.equal(labTask.success, true, 'Authorized lab task must proceed normally');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Addition 6 — Concurrency: /jonathan runs parallel; /chris is single-concurrency sequential queue', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-concurrency-'));
  try {
    const regDir = path.join(tmpDir, 'registry');
    setupTestPrograms(regDir);
    const regService = new ProgramRegistryService(regDir);
    const scheduler = new MichaelSchedulerService(regService);

    const validTime = new Date('2026-09-13T12:00:00Z');

    // ── Part A: /jonathan (recon) runs in genuine parallel ────────────────────
    const recon1 = scheduler.scheduleTask({
      id: 'recon-lab-01',
      program_id: 'authorized-lab',
      target: 'authorized.lab',
      targetDesk: '/jonathan',
      phase: 'recon',
      action: 'subfinder_scan'
    }, { currentTime: validTime });

    const recon2 = scheduler.scheduleTask({
      id: 'recon-targetcorp-02',
      program_id: 'targetcorp',
      target: 'targetcorp.com',
      targetDesk: '/jonathan',
      phase: 'recon',
      action: 'dns_enumeration'
    }, { currentTime: validTime });

    assert.equal(recon1.task.status, 'running', 'Recon Task 1 must start immediately');
    assert.equal(recon2.task.status, 'running', 'Recon Task 2 must also start immediately (parallel)');
    assert.equal(recon1.startedImmediately, true);
    assert.equal(recon2.startedImmediately, true);

    // ── Part B: /chris (validation/exploit) runs in single-concurrency queue ──
    const exploit1 = scheduler.scheduleTask({
      id: 'exploit-lab-01',
      program_id: 'authorized-lab',
      target: 'api.authorized.lab',
      targetDesk: '/chris',
      phase: 'exploitation',
      action: 'sqlmap_validation'
    }, { currentTime: validTime });

    const exploit2 = scheduler.scheduleTask({
      id: 'exploit-targetcorp-02',
      program_id: 'targetcorp',
      target: 'api.targetcorp.com',
      targetDesk: '/chris',
      phase: 'exploitation',
      action: 'ssrf_validation'
    }, { currentTime: validTime });

    // Exploit 1 starts immediately
    assert.equal(exploit1.task.status, 'running', 'Task 1 on /chris must start running');
    assert.equal(exploit1.startedImmediately, true);
    assert.equal(scheduler.getActiveTaskForDesk('/chris').id, 'exploit-lab-01');

    // Exploit 2 MUST wait in queue (sequential, NOT concurrent)
    assert.equal(exploit2.task.status, 'queued', 'Task 2 on /chris MUST WAIT in queue');
    assert.equal(exploit2.startedImmediately, false);
    assert.equal(exploit2.queued, true);

    const chrisQueue = scheduler.getQueueForDesk('/chris');
    assert.equal(chrisQueue.length, 1);
    assert.equal(chrisQueue[0].id, 'exploit-targetcorp-02');
    assert.equal(chrisQueue[0].program_id, 'targetcorp');

    // Complete Task 1 at T + 5000ms
    const completeTime = new Date('2026-09-13T12:00:05Z');
    const completionResult = scheduler.completeTask('exploit-lab-01', completeTime);

    assert.equal(completionResult.completedTask.status, 'completed');
    assert.equal(completionResult.completedTask.durationMs, 5000);

    // Exploit 2 automatically starts now that Task 1 is finished
    assert.ok(completionResult.nextTaskStarted);
    assert.equal(completionResult.nextTaskStarted.id, 'exploit-targetcorp-02');
    assert.equal(completionResult.nextTaskStarted.status, 'running');
    assert.equal(completionResult.nextTaskStarted.startedAt, completeTime.toISOString());
    assert.equal(scheduler.getActiveTaskForDesk('/chris').id, 'exploit-targetcorp-02');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Addition 6 — Conservative, configurable pacing per program throttles rapid automated actions', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-pacing-'));
  try {
    const regDir = path.join(tmpDir, 'registry');
    setupTestPrograms(regDir);
    const regService = new ProgramRegistryService(regDir);
    const scheduler = new MichaelSchedulerService(regService, 1000); // 1000ms minimum interval

    const t0 = new Date('2026-09-13T12:00:00.000Z');
    // Task 1 scheduled at T0
    scheduler.scheduleTask({
      program_id: 'authorized-lab',
      target: 'authorized.lab',
      targetDesk: '/jonathan',
      phase: 'recon',
      action: 'scan_1'
    }, { currentTime: t0 });

    // Action attempted 200ms later (< 1000ms pacing)
    const tEarly = new Date('2026-09-13T12:00:00.200Z');
    const paceCheck1 = scheduler.checkPacing('authorized-lab', tEarly);
    assert.equal(paceCheck1.allowed, false, 'Should not allow automated action before pacing interval');
    assert.equal(paceCheck1.waitMs, 800, 'Must report remaining wait time (800ms)');

    // Different program at the same time is NOT throttled (per-program pacing)
    const paceCheckOtherProg = scheduler.checkPacing('targetcorp', tEarly);
    assert.equal(paceCheckOtherProg.allowed, true, 'Different program must not be throttled');

    // Action attempted 1200ms later (> 1000ms pacing) -> Allowed
    const tAllowed = new Date('2026-09-13T12:00:01.200Z');
    const paceCheck2 = scheduler.checkPacing('authorized-lab', tAllowed);
    assert.equal(paceCheck2.allowed, true);
    assert.equal(paceCheck2.waitMs, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
