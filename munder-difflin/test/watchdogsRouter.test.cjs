'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const loadTs = require('./load-ts.cjs');

const {
  parseDirectCallsign,
  routePentestFinding,
  WATCHDOGS_CALLSIGNS
} = loadTs('src/main/watchdogsRouter.ts');

test('Phase 2.4: Trace synthetic finding through Recon -> Discovery -> Exploitation', () => {
  // 1. Recon phase finding
  const reconFinding = {
    target: 'authorized-lab.local',
    phase: 'recon',
    finding_type: 'open_port',
    severity: 'info',
    evidence: 'Port 80 open (Apache 2.4.49)',
    source_desk: '/jonathan',
    requires_approval: false
  };

  const reconDecision = routePentestFinding(reconFinding);
  assert.equal(reconDecision.nextDesk, 'daniel', 'Recon output forwards to discovery desk (Daniel)');
  assert.equal(reconDecision.requiresApproval, false);
  assert.equal(reconDecision.blocked, false);

  // 2. Discovery phase finding (severity: high)
  const discoveryFinding = {
    target: 'authorized-lab.local',
    phase: 'discovery',
    finding_type: 'candidate_cve',
    severity: 'high',
    evidence: 'Candidate CVE-2021-41773 path traversal identified',
    source_desk: '/daniel',
    requires_approval: false
  };

  const discoveryDecision = routePentestFinding(discoveryFinding, 'recon');
  assert.equal(discoveryDecision.nextDesk, 'chris', 'Discovery finding with severity >= medium forwards to validation desk (Chris / Strix)');
  assert.equal(discoveryDecision.requiresApproval, false);
  assert.equal(discoveryDecision.blocked, false);

  // 3. Exploitation phase finding
  const exploitationFinding = {
    target: 'authorized-lab.local',
    phase: 'exploitation',
    finding_type: 'validation_request',
    severity: 'high',
    evidence: 'Trigger PoC for path traversal',
    source_desk: '/chris',
    requires_approval: true
  };

  const exploitationDecision = routePentestFinding(exploitationFinding, 'discovery');
  assert.equal(exploitationDecision.nextDesk, 'chris', 'Exploitation validation targets Chris (Strix)');
  assert.equal(exploitationDecision.requiresApproval, true, 'Exploitation MUST require approval');
  assert.equal(exploitationDecision.blocked, true, 'Exploitation MUST be blocked pending Phase 2.5 approval gate');

  // 4. Reporting phase (approved validated finding)
  const reportingFinding = {
    target: 'authorized-lab.local',
    phase: 'reporting',
    finding_type: 'confirmed_vuln',
    severity: 'high',
    evidence: 'Validated PoC succeeded',
    source_desk: '/chris',
    requires_approval: false
  };

  const reportingDecision = routePentestFinding(reportingFinding, 'exploitation');
  assert.equal(reportingDecision.nextDesk, 'michael', 'Validated finding forwards to Michael for reporting');
  assert.equal(reportingDecision.blocked, false);
});

test('Phase 2.4: Anti-skip rule prevents direct transition from Recon to Exploitation', () => {
  const invalidJumpFinding = {
    target: 'authorized-lab.local',
    phase: 'exploitation',
    finding_type: 'raw_exploit',
    severity: 'high',
    evidence: 'Direct exploit attempt without discovery',
    source_desk: '/chris',
    requires_approval: true
  };

  const decision = routePentestFinding(invalidJumpFinding, 'recon');
  assert.equal(decision.blocked, true);
  assert.match(decision.reason, /Anti-skip violation/);
});

test('Phase 2.4: Low severity discovery findings are logged but not auto-escalated', () => {
  const lowFinding = {
    target: 'authorized-lab.local',
    phase: 'discovery',
    finding_type: 'missing_header',
    severity: 'low',
    evidence: 'X-Frame-Options missing',
    source_desk: '/daniel',
    requires_approval: false
  };

  const decision = routePentestFinding(lowFinding, 'recon');
  assert.equal(decision.nextDesk, null, 'Low severity finding must not auto-escalate');
  assert.equal(decision.blocked, false);
});

test('Phase 2.4b: Direct callsign addressing routes directly to target desk', () => {
  const testGabriel = parseDirectCallsign('/gabriel start port scan on 10.0.0.1');
  assert.notEqual(testGabriel, null);
  assert.equal(testGabriel.targetDesk, 'hexstrike');
  assert.equal(testGabriel.cleanedText, 'start port scan on 10.0.0.1');

  // Verify alias /wrench also routes to hexstrike
  const testWrench = parseDirectCallsign('/wrench start port scan on 10.0.0.1');
  assert.notEqual(testWrench, null);
  assert.equal(testWrench.targetDesk, 'hexstrike');

  const testChris = parseDirectCallsign('/chris validate candidate poc');
  assert.notEqual(testChris, null);
  assert.equal(testChris.targetDesk, 'chris');
  assert.equal(testChris.cleanedText, 'validate candidate poc');

  const testDaniel = parseDirectCallsign('/daniel inspect source tree');
  assert.notEqual(testDaniel, null);
  assert.equal(testDaniel.targetDesk, 'daniel');

  const testJonathan = parseDirectCallsign('/jonathan run passive osint');
  assert.notEqual(testJonathan, null);
  assert.equal(testJonathan.targetDesk, 'jonathan');
  assert.equal(testJonathan.cleanedText, 'run passive osint');

  const testDavid = parseDirectCallsign('/david lookup CVE-2023-38606');
  assert.notEqual(testDavid, null);
  assert.equal(testDavid.targetDesk, 'david');

  const testMichael = parseDirectCallsign('/michael summarize current pentest status');
  assert.notEqual(testMichael, null);
  assert.equal(testMichael.targetDesk, 'michael');

  const testMaverick = parseDirectCallsign('/maverick lookup skill for jwt validation');
  assert.notEqual(testMaverick, null);
  assert.equal(testMaverick.targetDesk, 'maverick');
  assert.equal(testMaverick.cleanedText, 'lookup skill for jwt validation');

  // Non-callsign input falls through (returns null)
  const testStandard = parseDirectCallsign('Please review the latest reports');
  assert.equal(testStandard, null);
});
