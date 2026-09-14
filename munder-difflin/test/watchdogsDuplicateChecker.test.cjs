'use strict';

/**
 * Addition 3: Pre-Submission Duplicate Check Tests
 *
 * Verifies:
 *  1. Official platform API integration (HackerOne) vs graceful skipping (Bugcrowd per ToS).
 *  2. OPSEC-safe query construction: target domain + vuln class ONLY; zero payload/token leakage.
 *  3. Flag, never auto-discard: Flagged matches require human review; finding is never deleted.
 *  4. Rich match detail displayed to human: title, date, summary, matched fields breakdown.
 *  5. Dual-stage execution: Advisory check on entry and mandatory fresh re-run pre-submission (not cached).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');
const {
  DuplicateCheckerService,
  extractTargetDomain,
  normalizeVulnClass
} = loadTs('src/main/duplicateChecker.ts');

test('Duplicate Checker: OPSEC query sanitization strips payloads, credentials, and paths', () => {
  const service = new DuplicateCheckerService();

  const dirtyFinding = {
    target: 'https://admin-internal.targetcorp.com:8443/oauth/token?client_secret=SUPER_SECRET_12345',
    phase: 'reporting',
    finding_type: 'ssrf_poc',
    severity: 'critical',
    evidence: 'curl -s -H "Authorization: Bearer eyJhbGciOi..." http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    source_desk: '/chris',
    requires_approval: false
  };

  const query = service.buildQuery(dirtyFinding);

  // 1. Must extract clean domain and normalized vuln class
  assert.equal(query.targetDomain, 'admin-internal.targetcorp.com');
  assert.equal(query.vulnerabilityClass, 'SSRF');

  // 2. String representation must NOT leak any sensitive data
  const queryStr = JSON.stringify(query);
  assert.equal(queryStr.includes('SUPER_SECRET'), false, 'Must not leak client secrets');
  assert.equal(queryStr.includes('169.254.169.254'), false, 'Must not leak AWS metadata IP');
  assert.equal(queryStr.includes('eyJhbGciOi'), false, 'Must not leak JWT tokens');
  assert.equal(queryStr.includes('/oauth/token'), false, 'Must not leak specific endpoint paths');
  assert.equal(queryStr.includes('8443'), false, 'Must not leak internal port');
});

test('Duplicate Checker: Platform routing — HackerOne official API vs Bugcrowd ToS skipping', async () => {
  const service = new DuplicateCheckerService();

  const finding = {
    target: 'api.example.com',
    phase: 'reporting',
    finding_type: 'sqli_candidate',
    severity: 'high',
    evidence: 'SQL syntax error',
    source_desk: '/chris',
    requires_approval: false
  };

  // Case 1: Bugcrowd — No official unauthenticated search API -> Skipped per ToS (no raw scraping)
  const bugcrowdResult = await service.checkDuplicates(
    finding,
    { platform: 'bugcrowd' },
    'advisory'
  );

  assert.equal(bugcrowdResult.status, 'SKIPPED_NO_API');
  assert.equal(bugcrowdResult.requiresHumanReview, false);
  assert.match(bugcrowdResult.message, /does not provide an official public search API/);
  assert.match(bugcrowdResult.message, /Terms of Service policy \(no scraping\)/);

  // Case 2: Intigriti — Also skipped gracefully per ToS
  const intigritiResult = await service.checkDuplicates(
    finding,
    { platform: 'intigriti' },
    'advisory'
  );
  assert.equal(intigritiResult.status, 'SKIPPED_NO_API');
});

test('Duplicate Checker: Flag, never auto-discard — surfaces full report details for human review', async () => {
  // Mock official HackerOne Hacktivity API response
  const mockFetcher = async (platform, query) => {
    return [
      {
        id: '1849201',
        title: 'SSRF in webhook verification service on api.targetcorp.com',
        disclosedAt: '2026-03-15',
        summary: 'Attacker could trigger out-of-band HTTP requests via unvalidated URL parameter.',
        platform: 'hackerone',
        targetDomain: 'api.targetcorp.com',
        vulnerabilityClass: 'SSRF',
        url: 'https://hackerone.com/reports/1849201'
      }
    ];
  };

  const service = new DuplicateCheckerService(mockFetcher);

  const finding = {
    target: 'api.targetcorp.com',
    phase: 'reporting',
    finding_type: 'ssrf_poc',
    severity: 'critical',
    evidence: 'Confirmed SSRF on metadata endpoint',
    source_desk: '/chris',
    requires_approval: false
  };

  const result = await service.checkOnReportingEntry(finding, { platform: 'hackerone' });

  // 1. Status must be FLAGGED_POSSIBLE_DUPLICATE
  assert.equal(result.status, 'FLAGGED_POSSIBLE_DUPLICATE');
  assert.equal(result.requiresHumanReview, true);
  assert.equal(result.matches.length, 1);

  // 2. Check full detail shown to human
  const match = result.matches[0];
  assert.equal(match.report.id, '1849201');
  assert.equal(match.report.title, 'SSRF in webhook verification service on api.targetcorp.com');
  assert.equal(match.report.disclosedAt, '2026-03-15');
  assert.equal(match.report.url, 'https://hackerone.com/reports/1849201');
  assert.equal(match.matchedFields.sameTarget, true);
  assert.equal(match.matchedFields.sameVulnClass, true);

  // 3. Message presented to operator includes required breakdown and anti-discard guarantee
  assert.match(result.message, /Possible Duplicate Detected/);
  assert.match(result.message, /1849201/);
  assert.match(result.message, /Target Domain \(✓\)/);
  assert.match(result.message, /Vuln Class \(✓\)/);
  assert.match(result.message, /NEVER auto-discard this finding/);

  // 4. CRITICAL: finding object itself is 100% intact and untouched
  assert.equal(finding.finding_type, 'ssrf_poc');
  assert.equal(finding.severity, 'critical');
});

test('Duplicate Checker: Dual-stage execution — re-runs fresh pre-submission and catches newly disclosed report', async () => {
  // Live dynamic mock: simulates no disclosure at T0, but a report disclosed before T1 submission
  let currentDisclosures = [];

  const dynamicFetcher = async (platform, query) => {
    return currentDisclosures.filter((d) => d.targetDomain === query.targetDomain);
  };

  const service = new DuplicateCheckerService(dynamicFetcher);

  const finding = {
    target: 'checkout.shopcorp.com',
    phase: 'reporting',
    finding_type: 'idor',
    severity: 'high',
    evidence: 'IDOR in order receipt endpoint',
    source_desk: '/chris',
    requires_approval: false
  };

  const program = { platform: 'hackerone' };

  // ── Stage 1: Initial Advisory Check upon arriving at reporting desk (T0) ──
  const stage1Advisory = await service.checkOnReportingEntry(finding, program);
  assert.equal(stage1Advisory.stage, 'advisory');
  assert.equal(stage1Advisory.status, 'CLEARED_NO_MATCH', 'At T0 finding appears novel');
  assert.equal(stage1Advisory.matches.length, 0);

  // ── Interim: While report is being drafted, a duplicate report is publicly disclosed on Hacktivity ──
  currentDisclosures.push({
    id: '998877',
    title: 'IDOR in checkout.shopcorp.com order view',
    disclosedAt: '2026-09-13',
    summary: 'Publicly disclosed IDOR allowing order enumeration.',
    platform: 'hackerone',
    targetDomain: 'checkout.shopcorp.com',
    vulnerabilityClass: 'IDOR',
    url: 'https://hackerone.com/reports/998877'
  });

  // ── Stage 2: Mandatory Fresh Re-Run Immediately Prior to Submission (T1) ──
  // MUST NOT return cached Stage 1 result!
  const stage2PreSubmission = await service.checkPreSubmission(finding, program);

  assert.equal(stage2PreSubmission.stage, 'pre-submission');
  assert.equal(
    stage2PreSubmission.status,
    'FLAGGED_POSSIBLE_DUPLICATE',
    'Pre-submission check must be a FRESH network run and catch the newly disclosed report!'
  );
  assert.equal(stage2PreSubmission.matches.length, 1);
  assert.equal(stage2PreSubmission.matches[0].report.id, '998877');
  assert.match(stage2PreSubmission.message, /Pre-Submission Final Check/);
});

test('Duplicate Checker: Integration with HiveManager reporting flow', async (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-dup-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));

  let apiCalls = 0;
  const testFetcher = async (platform, query) => {
    apiCalls++;
    return [
      {
        id: '554433',
        title: 'Known RCE on vulnerable.target.lab',
        disclosedAt: '2026-01-20',
        summary: 'Command injection disclosed.',
        platform: 'hackerone',
        targetDomain: 'vulnerable.target.lab',
        vulnerabilityClass: 'RCE'
      }
    ];
  };

  const dupChecker = new DuplicateCheckerService(testFetcher);
  const hive = new HiveManager(() => home, undefined, undefined, dupChecker);

  await hive.ensureAgent({ id: 'michael', name: 'Michael', provider: 'claude', cwd: home, isGod: true });

  const reportingFinding = {
    target: 'vulnerable.target.lab',
    phase: 'reporting',
    finding_type: 'rce_poc',
    severity: 'critical',
    evidence: 'whoami -> root',
    source_desk: '/chris',
    requires_approval: false
  };

  // Pre-submission direct check via HiveManager
  const result = await hive.checkDuplicatePreSubmission(reportingFinding, 'hackerone');
  assert.equal(result.status, 'FLAGGED_POSSIBLE_DUPLICATE');
  assert.equal(result.matches.length, 1);
  assert.equal(apiCalls, 1);
});
