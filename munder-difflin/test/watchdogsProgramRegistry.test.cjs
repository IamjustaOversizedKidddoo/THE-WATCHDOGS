'use strict';

/**
 * Addition 2: Program Registry (Scope Source of Truth) Tests
 *
 * Verifies:
 *  1. Registry file structure & human-write-only security enforcement.
 *  2. Exact domain-suffix matching (strictly fails example.com.attacker.net).
 *  3. Exclusion-wins-on-conflict resolution.
 *  4. Recon findings land in `candidates: []` and are NEVER auto-merged into in_scope.
 *  5. Staleness gate: Phase 2.5 approval blocks on stale (>7 days) last_verified.
 *  6. Registry requirement: Phase 2.5 approval blocks on unregistered program.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');
const {
  ProgramRegistryService,
  matchDomainPattern
} = loadTs('src/main/programRegistry.ts');

async function createRegistryFloor(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-registry-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));

  const registryDir = path.join(home, 'config', 'program-registry');
  fs.mkdirSync(registryDir, { recursive: true });

  const programRegistry = new ProgramRegistryService(registryDir);
  const hive = new HiveManager(() => home, undefined, programRegistry);

  await hive.ensureAgent({ id: 'michael', name: 'Michael', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'chris', name: 'Chris', provider: 'strix', cwd: home });
  await hive.ensureAgent({ id: 'jonathan', name: 'Jonathan', provider: 'hackergpt', cwd: home });

  return { home, registryDir, programRegistry, hive };
}

test('Program Registry: Exact domain-suffix matching blocks attacker.net substring bypass', () => {
  const inScopeExact = 'example.com';
  const inScopeWildcard = '*.example.com';

  // ── Attack Vector 1: Attacker appends legitimate domain as subdomain of attacker.net ──
  const bypassTarget1 = 'example.com.attacker.net';
  const matchExact1 = matchDomainPattern(bypassTarget1, inScopeExact);
  const matchWildcard1 = matchDomainPattern(bypassTarget1, inScopeWildcard);

  assert.equal(
    matchExact1,
    false,
    `CRITICAL BYPASS BLOCKED: "${bypassTarget1}" must NOT match exact pattern "${inScopeExact}"`
  );
  assert.equal(
    matchWildcard1,
    false,
    `CRITICAL BYPASS BLOCKED: "${bypassTarget1}" must NOT match wildcard pattern "${inScopeWildcard}"`
  );

  // ── Attack Vector 2: Attacker prefixes legitimate domain without dot separator ──
  const bypassTarget2 = 'fakeexample.com';
  assert.equal(matchDomainPattern(bypassTarget2, inScopeExact), false);
  assert.equal(matchDomainPattern(bypassTarget2, inScopeWildcard), false);

  const bypassTarget3 = 'notexample.com';
  assert.equal(matchDomainPattern(bypassTarget3, inScopeExact), false);
  assert.equal(matchDomainPattern(bypassTarget3, inScopeWildcard), false);

  // ── Legitimate Targets: Genuine domain and subdomains must pass ──
  assert.equal(matchDomainPattern('example.com', inScopeExact), true, 'Apex matches exact');
  assert.equal(matchDomainPattern('example.com', inScopeWildcard), true, 'Apex matches wildcard');
  assert.equal(matchDomainPattern('api.example.com', inScopeWildcard), true, 'Subdomain matches wildcard');
  assert.equal(matchDomainPattern('dev.staging.example.com', inScopeWildcard), true, 'Nested subdomain matches wildcard');
  assert.equal(matchDomainPattern('api.example.com', inScopeExact), false, 'Subdomain does not match exact pattern');
});

test('Program Registry: Exclusion-wins-on-conflict resolution', () => {
  const registry = new ProgramRegistryService();

  const program = {
    program: 'conflict-test',
    platform: 'hackerone',
    in_scope: ['*.example.com', 'api.example.com'],
    excluded: ['status.example.com', '*.example.com/legacy-portal/*'],
    last_verified: '2026-09-13',
    verified_by: 'human',
    candidates: []
  };

  // Case 1: Target matches in_scope (*.example.com) AND excluded (status.example.com)
  const resultStatus = registry.checkScope('status.example.com', program);
  assert.equal(resultStatus.inScope, false, 'Exclusion must win over in_scope wildcard');
  assert.equal(resultStatus.matchedExcludedPattern, 'status.example.com');
  assert.match(resultStatus.reason, /matches excluded pattern/);

  // Case 2: Target path matches in_scope (*.example.com) AND path exclusion (*.example.com/legacy-portal/*)
  const resultPath = registry.checkScope('admin.example.com/legacy-portal/login', program);
  assert.equal(resultPath.inScope, false, 'Path exclusion must win over in_scope');
  assert.equal(resultPath.matchedExcludedPattern, '*.example.com/legacy-portal/*');

  // Case 3: Target matches in_scope and has no exclusion match
  const resultAllowed = registry.checkScope('admin.example.com/modern-portal/login', program);
  assert.equal(resultAllowed.inScope, true);
  assert.equal(resultAllowed.matchedInScopePattern, '*.example.com');
});

test('Program Registry: Human-write-only security rules enforced', async (t) => {
  const { programRegistry } = await createRegistryFloor(t);

  const entry = {
    program: 'sec-test',
    platform: 'bugcrowd',
    in_scope: ['sec-test.org'],
    excluded: [],
    last_verified: '2026-09-13',
    verified_by: 'human',
    candidates: []
  };

  // Human save succeeds
  programRegistry.saveProgram(entry, 'human');
  const loaded = programRegistry.getProgram('sec-test');
  assert.notEqual(loaded, null);

  // Agent attempt to modify or save must throw
  assert.throws(
    () => {
      programRegistry.saveProgram(entry, 'agent');
    },
    /Security Guardrail Violation: Program registry entries can only be created or modified by "human"/
  );

  // Attempt to save with verified_by not "human" must throw
  assert.throws(
    () => {
      programRegistry.saveProgram({ ...entry, verified_by: 'agent' }, 'human');
    },
    /Security Guardrail: verified_by must strictly read "human"/
  );
});

test('Program Registry: Recon candidates land in candidates list, NEVER auto-merged into in_scope', async (t) => {
  const { programRegistry, hive } = await createRegistryFloor(t);

  const target = 'bounty-recon.lab';

  // Seed program registry entry with verified scope
  programRegistry.saveProgram(
    {
      program: 'bounty-recon',
      platform: 'hackerone',
      in_scope: ['bounty-recon.lab', '*.bounty-recon.lab'],
      excluded: [],
      last_verified: '2026-09-13',
      verified_by: 'human',
      candidates: []
    },
    'human'
  );

  // Configure Jonathan continuous recon for this target
  const service = hive.jonathanReconService;
  service.addTarget({ target });

  // Run continuous recon: discovers 2 subdomains and 1 endpoint
  await service.executeScheduledRun(target, {
    subdomains: ['api.bounty-recon.lab', 'dev.bounty-recon.lab'],
    endpoints: ['/api/v1/health'],
    techSignals: { server: 'nginx' }
  });

  // Load program from disk
  const updatedProgram = programRegistry.getProgram('bounty-recon');
  assert.notEqual(updatedProgram, null);

  // 1. Candidates array MUST receive discovered items
  assert.equal(updatedProgram.candidates.includes('api.bounty-recon.lab'), true);
  assert.equal(updatedProgram.candidates.includes('dev.bounty-recon.lab'), true);
  assert.equal(updatedProgram.candidates.includes('bounty-recon.lab/api/v1/health'), true);

  // 2. CRITICAL: in_scope MUST NOT be modified or contain the candidates directly
  assert.deepEqual(
    updatedProgram.in_scope,
    ['bounty-recon.lab', '*.bounty-recon.lab'],
    'in_scope must remain strictly unmodified by automated recon runs'
  );

  // 3. Human promotion step: Human explicitly promotes api.bounty-recon.lab
  programRegistry.promoteCandidate('bounty-recon', 'api.bounty-recon.lab', 'human');
  const postPromotion = programRegistry.getProgram('bounty-recon');
  assert.equal(postPromotion.in_scope.includes('api.bounty-recon.lab'), true, 'Promoted asset added to in_scope');
  assert.equal(postPromotion.candidates.includes('api.bounty-recon.lab'), false, 'Removed from candidates');
});

test('Program Registry: Approval gate blocks on stale (>7 days) last_verified and unblocks on re-confirmation', async (t) => {
  const { programRegistry, hive } = await createRegistryFloor(t);

  const target = 'stale-program.com';

  // Seed program with last_verified older than 7 days (e.g. 14 days ago)
  programRegistry.saveProgram(
    {
      program: 'stale-program',
      platform: 'intigriti',
      in_scope: ['stale-program.com', '*.stale-program.com'],
      excluded: [],
      last_verified: '2026-08-20', // ~24 days stale
      verified_by: 'human',
      candidates: []
    },
    'human'
  );

  // Enqueue exploitation-class message requiring approval
  const exploitMsg = {
    id: 'stale-exploit-01',
    to: 'chris',
    act: 'request',
    subject: 'Run exploit against stale target',
    body: 'Exploit attempt',
    finding: {
      target,
      phase: 'exploitation',
      finding_type: 'rce_poc',
      severity: 'critical',
      evidence: 'RCE PoC candidate',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  hive.send(exploitMsg, 'chris');
  assert.equal(hive.approvalQueue.isPending('stale-exploit-01'), true);

  // Attempt to approve: MUST FAIL due to stale verification (> 7 days)
  const approved = hive.approveMessage('stale-exploit-01');
  assert.equal(approved, false, 'Approval gate MUST BLOCK on stale last_verified date');

  // Chris's inbox must STILL be empty (action blocked at gate)
  assert.equal(hive.inbox('chris').length, 0);
  assert.equal(hive.approvalQueue.isPending('stale-exploit-01'), true, 'Message remains pending');

  // Human operator re-confirms scope against program policy page
  programRegistry.reconfirmScope('stale-program', '2026-09-13');

  // Now approval gate clears!
  const approvedAfterReconfirm = hive.approveMessage('stale-exploit-01');
  assert.equal(approvedAfterReconfirm, true, 'Approval gate clears after explicit human re-confirmation');
  assert.equal(hive.inbox('chris').length, 1, 'Message delivered to Chris only after gate cleared');
});

test('Program Registry: Approval gate blocks entirely on unregistered program', async (t) => {
  const { hive } = await createRegistryFloor(t);

  const unregMsg = {
    id: 'unreg-exploit-02',
    to: 'chris',
    act: 'request',
    subject: 'Exploit against completely unlisted target',
    body: 'Exploit payload',
    finding: {
      target: 'completely-unknown-target.net',
      phase: 'exploitation',
      finding_type: 'sqli_poc',
      severity: 'high',
      evidence: 'SQLi evidence',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  hive.send(unregMsg, 'chris');
  assert.equal(hive.approvalQueue.isPending('unreg-exploit-02'), true);

  // Approval gate must block: program not found in registry
  const approved = hive.approveMessage('unreg-exploit-02');
  assert.equal(approved, false, 'Approval gate MUST BLOCK when target has no program registry entry');
  assert.equal(hive.inbox('chris').length, 0);
});

test('Program Registry: Fresh in-scope target clears gate normally', async (t) => {
  const { programRegistry, hive } = await createRegistryFloor(t);

  programRegistry.saveProgram(
    {
      program: 'fresh-prog',
      platform: 'hackerone',
      in_scope: ['fresh.target.com'],
      excluded: [],
      last_verified: '2026-09-13',
      verified_by: 'human',
      candidates: []
    },
    'human'
  );

  const validMsg = {
    id: 'valid-exploit-03',
    to: 'chris',
    act: 'request',
    subject: 'Valid exploit on fresh in-scope target',
    body: 'Valid exploit payload',
    finding: {
      target: 'fresh.target.com',
      phase: 'exploitation',
      finding_type: 'sqli_poc',
      severity: 'high',
      evidence: 'SQLi verified',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  hive.send(validMsg, 'chris');
  assert.equal(hive.approvalQueue.isPending('valid-exploit-03'), true);

  const approved = hive.approveMessage('valid-exploit-03');
  assert.equal(approved, true, 'Gate clears normally for fresh in-scope target');
  assert.equal(hive.inbox('chris').length, 1);
});
