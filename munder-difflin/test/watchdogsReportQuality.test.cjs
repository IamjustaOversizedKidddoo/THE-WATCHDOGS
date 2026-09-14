'use strict';

/**
 * Addition 4: Report Quality Pass Before Submission Tests
 *
 * Verifies:
 *  1. Evidence tracing: Claims must trace to /chris or /daniel; untraced claims flagged as [HYPOTHESIS / UNVERIFIED].
 *  2. Severity reasoning: Derived CVSS v3.1 vector string with explicit metric-by-metric rationale.
 *  3. Mandatory PII & credential redaction: Real emails, phones, SSNs, credit cards, auth tokens, profile records masked.
 *  4. Originality check: Compares phrasing against disclosed reports from Addition 3 and flags close text overlap.
 *  5. Fixed six-section structure: Summary, Steps, Impact, Components, Severity, Remediation.
 *  6. Human sign-off gate: Draft remains PENDING_HUMAN_APPROVAL and strictly blocks submission until human approval.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');
const {
  ReportQualityService,
  redactUserData,
  deriveCvssReasoning,
  checkOriginalityAgainstDisclosures
} = loadTs('src/main/reportQualityService.ts');
const { DuplicateCheckerService } = loadTs('src/main/duplicateChecker.ts');

test('Addition 4 — PII & Credential Redaction Pass masks sensitive user data and tokens', () => {
  const dirtyPoC = `
HTTP/1.1 200 OK
Set-Cookie: session_id=s%3A7f8a9b0c1d2e; Path=/; HttpOnly
Authorization: Bearer ya29.a0AfH6SMB_secret_access_token_12345
Content-Type: application/json

User verified in backend logs:
Email: sarah.connor@cyberdyne-systems.com
Phone: +1 (555) 234-5678
SSN: 987-65-4321
Credit Card: 4111-2222-3333-4444
JWT Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_secret_signature

Full sensitive customer profile payload returned:
{ "account_profile": "VIP_CUSTOMER", "notes": "internal access" }
`;

  const { redactedText, redactions } = redactUserData(dirtyPoC);

  // Assert all raw sensitive values are masked
  assert.equal(redactedText.includes('sarah.connor@cyberdyne-systems.com'), false, 'Must redact email');
  assert.equal(redactedText.includes('555) 234-5678'), false, 'Must redact phone');
  assert.equal(redactedText.includes('987-65-4321'), false, 'Must redact SSN');
  assert.equal(redactedText.includes('4111-2222-3333-4444'), false, 'Must redact credit card');
  assert.equal(redactedText.includes('Bearer ya29.a0AfH6SMB_secret_access_token_12345'), false, 'Must redact bearer token');
  assert.equal(redactedText.includes('session_id=s%3A7f8a9b0c1d2e'), false, 'Must redact session cookie');
  assert.equal(redactedText.includes('VIP_CUSTOMER'), false, 'Must redact full profile record');
  assert.equal(redactedText.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'), false, 'Must redact JWT token');

  // Assert helpful replacement tags are present
  assert.ok(redactedText.includes('[REDACTED_EMAIL'), 'Must contain email placeholder');
  assert.ok(redactedText.includes('[REDACTED_PHONE'), 'Must contain phone placeholder');
  assert.ok(redactedText.includes('[REDACTED_SSN]'), 'Must contain SSN placeholder');
  assert.ok(redactedText.includes('[REDACTED_AUTH_TOKEN]'), 'Must contain auth token placeholder');
  assert.ok(redactedText.includes('[REDACTED_USER_PROFILE'), 'Must contain user profile placeholder');
  assert.ok(redactions.length >= 6, 'Must record each redaction in the audit log');
});

test('Addition 4 — Severity Reasoning derives CVSS v3.1 vector and full metric justification', () => {
  const rceFinding = {
    target: 'order-service.internal.corp',
    phase: 'reporting',
    finding_type: 'rce',
    severity: 'critical',
    evidence: 'whoami -> uid=0(root) gid=0(root)',
    source_desk: '/chris',
    requires_approval: false
  };

  const cvss = deriveCvssReasoning(rceFinding);

  assert.equal(cvss.baseScore, 9.8);
  assert.equal(cvss.severityRating, 'Critical');
  assert.equal(cvss.vectorString, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(cvss.metrics.length, 8, 'Must provide reasoning for all 8 CVSS base metrics');

  // Verify all 8 metrics have explicit textual justification
  const metricNames = cvss.metrics.map(m => m.metric);
  assert.ok(metricNames.some(n => n.includes('Attack Vector')));
  assert.ok(metricNames.some(n => n.includes('Attack Complexity')));
  assert.ok(metricNames.some(n => n.includes('Privileges Required')));
  assert.ok(metricNames.some(n => n.includes('User Interaction')));
  assert.ok(metricNames.some(n => n.includes('Scope')));
  assert.ok(metricNames.some(n => n.includes('Confidentiality Impact')));
  assert.ok(metricNames.some(n => n.includes('Integrity Impact')));
  assert.ok(metricNames.some(n => n.includes('Availability Impact')));

  for (const m of cvss.metrics) {
    assert.ok(m.reasoning && m.reasoning.length > 10, `Metric ${m.metric} must have substantial reasoning`);
  }

  // SSRF cloud metadata scope change verification
  const ssrfFinding = {
    target: 'proxy.internal.corp/fetch',
    phase: 'reporting',
    finding_type: 'ssrf',
    severity: 'high',
    evidence: 'GET http://169.254.169.254/latest/meta-data/ returned IAM credentials',
    source_desk: '/chris',
    requires_approval: false
  };
  const ssrfCvss = deriveCvssReasoning(ssrfFinding);
  assert.equal(ssrfCvss.baseScore, 8.6);
  assert.equal(ssrfCvss.vectorString, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N');
  assert.ok(ssrfCvss.metrics.find(m => m.metric.includes('Scope')).value.includes('Changed (S:C)'));
});

test('Addition 4 — Evidence Tracing verifies proven claims and flags unverified hypotheses', () => {
  const service = new ReportQualityService();

  // 1. Finding with concrete PoC evidence
  const verifiedFinding = {
    target: 'api.targetcorp.com/v1/users/42',
    phase: 'reporting',
    finding_type: 'idor',
    severity: 'medium',
    evidence: 'GET /v1/users/42 with auth of user 10 returned private profile of user 42',
    source_desk: '/chris',
    requires_approval: false
  };

  const draft1 = service.generateReportDraft(verifiedFinding);
  assert.ok(draft1.evidenceTraces.every(t => t.isVerified));
  assert.ok(draft1.formattedMarkdown.includes('Verified (✓)'));
  assert.equal(draft1.formattedMarkdown.includes('[HYPOTHESIS / UNVERIFIED]'), false);

  // 2. Finding with missing / empty evidence
  const unverifiedFinding = {
    target: 'api.targetcorp.com/v1/debug',
    phase: 'reporting',
    finding_type: 'information_disclosure',
    severity: 'low',
    evidence: '', // No PoC evidence provided
    source_desk: '/daniel',
    requires_approval: false
  };

  const draft2 = service.generateReportDraft(unverifiedFinding);
  const unverifiedTrace = draft2.evidenceTraces.find(t => !t.isVerified);
  assert.ok(unverifiedTrace, 'Must flag unverified claim');
  assert.ok(unverifiedTrace.annotation.includes('HYPOTHESIS / UNVERIFIED'));
  assert.ok(draft2.formattedMarkdown.includes('**[HYPOTHESIS / UNVERIFIED]**'));
});

test('Addition 4 — Originality Check flags overlapping sentences against disclosed reports', () => {
  const disclosedReports = [
    {
      id: '1092345',
      title: 'Server-Side Request Forgery leading to AWS instance metadata disclosure',
      disclosedAt: '2024-03-01',
      summary: 'A validated ssrf vulnerability was identified on target. The issue was verified through reproducible execution.',
      platform: 'hackerone',
      targetDomain: 'target.com',
      vulnerabilityClass: 'SSRF'
    }
  ];

  // 1. Deliberately copied / echoed draft
  const copiedDraft = 'A validated ssrf vulnerability was identified on target. The issue was verified through reproducible execution. Remediation is required.';
  const res1 = checkOriginalityAgainstDisclosures(copiedDraft, disclosedReports);
  assert.equal(res1.hasLanguageOverlap, true);
  assert.equal(res1.matchedReportId, '1092345');
  assert.ok(res1.recommendation.includes('rephrase in your own words'));

  // 2. Completely original phrasing
  const originalDraft = 'We discovered an improper routing condition when issuing HTTP POST payloads to the webhook connector, causing backend services to fetch internal endpoints.';
  const res2 = checkOriginalityAgainstDisclosures(originalDraft, disclosedReports);
  assert.equal(res2.hasLanguageOverlap, false);
});

test('Addition 4 — Fixed Six-Section Structure enforces complete report format', () => {
  const service = new ReportQualityService();

  const finding = {
    target: 'payments.example.com/checkout',
    phase: 'reporting',
    finding_type: 'sqli',
    severity: 'high',
    evidence: "POST /checkout coupon=' OR 1=1-- -> 200 OK discount applied",
    source_desk: '/chris',
    requires_approval: false
  };

  const draft = service.generateReportDraft(finding);

  // Check the six required sections in object and markdown
  assert.ok(draft.sections.summary, 'Must contain Summary section');
  assert.ok(draft.sections.reproductionSteps.length >= 2, 'Must contain concrete Reproduction Steps');
  assert.ok(draft.sections.impactStatement, 'Must contain Impact Statement');
  assert.ok(draft.sections.affectedComponents.length >= 1, 'Must contain Affected Component(s)');
  assert.ok(draft.sections.severityWithReasoning, 'Must contain Severity with Reasoning');
  assert.ok(draft.sections.suggestedRemediation, 'Must contain Suggested Remediation');

  // Verify markdown headings
  assert.ok(draft.formattedMarkdown.includes('## 1. Summary'));
  assert.ok(draft.formattedMarkdown.includes('## 2. Reproduction Steps'));
  assert.ok(draft.formattedMarkdown.includes('## 3. Impact Statement'));
  assert.ok(draft.formattedMarkdown.includes('## 4. Affected Component(s)'));
  assert.ok(draft.formattedMarkdown.includes('## 5. Suggested Severity with Reasoning'));
  assert.ok(draft.formattedMarkdown.includes('## 6. Suggested Remediation'));
  assert.ok(draft.formattedMarkdown.includes('## Evidence Trace Matrix'));
  assert.ok(draft.formattedMarkdown.includes('## Quality & Safety Verification Status'));
});

test('Addition 4 — Human Sign-Off Gate strictly halts submission until human approval', () => {
  const service = new ReportQualityService();

  const finding = {
    target: 'auth.corp.com/login',
    phase: 'reporting',
    finding_type: 'idor',
    severity: 'high',
    evidence: 'PoC verified user auth bypass',
    source_desk: '/chris',
    requires_approval: false
  };

  const draft = service.generateReportDraft(finding, { findingId: 'report-auth-001' });

  // 1. Draft starts as PENDING_HUMAN_APPROVAL
  assert.equal(draft.status, 'PENDING_HUMAN_APPROVAL');

  // 2. Premature submission must be blocked
  const prematureSubmit = service.submitReport('report-auth-001');
  assert.equal(prematureSubmit.submitted, false);
  assert.ok(prematureSubmit.reason.includes('Submission blocked'));
  assert.ok(prematureSubmit.reason.includes('PENDING_HUMAN_APPROVAL'));

  // 3. Human provides explicit approval
  const approvedDraft = service.approveDraft('report-auth-001', 'security-lead@watchdogs');
  assert.equal(approvedDraft.status, 'APPROVED_BY_HUMAN');
  assert.equal(approvedDraft.approvedBy, 'security-lead@watchdogs');
  assert.ok(approvedDraft.approvedAt);

  // 4. Submission succeeds once approved
  const validSubmit = service.submitReport('report-auth-001');
  assert.equal(validSubmit.submitted, true);
});

test('Addition 4 — HiveManager integration generates draft, preserves PII safety, and gates submission', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-hive-quality-test-'));
  try {
    const hive = new HiveManager(() => tmpDir);

    const sensitiveFinding = {
      target: 'api.store.com/orders',
      phase: 'reporting',
      finding_type: 'idor',
      severity: 'high',
      evidence: 'User alice@customer.org accessed order records for bob@victim.com with session_id=abc123456789',
      source_desk: '/chris',
      requires_approval: false
    };

    const draft = hive.generateQualityReport(sensitiveFinding, 'IDOR in Order History');

    assert.equal(draft.status, 'PENDING_HUMAN_APPROVAL');
    assert.equal(draft.redactionsApplied.length >= 2, true, 'Must record redactions for emails and session token');
    assert.equal(draft.formattedMarkdown.includes('alice@customer.org'), false);
    assert.equal(draft.formattedMarkdown.includes('bob@victim.com'), false);
    assert.equal(draft.formattedMarkdown.includes('session_id=abc123456789'), false);

    // Submission blocked
    const resBlocked = hive.submitQualityReport(draft.id);
    assert.equal(resBlocked.submitted, false);

    // Operator approves
    hive.approveQualityReport(draft.id, 'operator-john');
    const resApproved = hive.submitQualityReport(draft.id);
    assert.equal(resApproved.submitted, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
