'use strict';

/**
 * Addition 5: /maverick Disclosure-Learning Loop Tests
 *
 * Verifies:
 *  1. Periodic/On-demand review uses Addition 3's official API integration (0 scraping).
 *  2. Genuine paraphrase: Synthesizes technique into standard 4-section skill format
 *     (When to Use, Prerequisites, Workflow, Verification) with source link; never copies report text.
 *  3. Recency & Relevance: Flags source disclosure date and /maverick's explicit assessment.
 *  4. Hard Caps & Explicit Swaps: Caps at 10/12/8/6 for jonathan/chris/daniel/david; proposes
 *     concrete swap with comparative rationale if at cap; never exceeds cap.
 *  5. Human Approval Gate: Zero manifest writes occur until human explicitly approves.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');
const {
  MaverickSkillsService,
  DESK_MANIFEST_CAPS,
  classifyTargetDesk,
  assessRelevanceAndRecency,
  synthesizeParaphrasedSkill,
  proposeSkillSwap
} = loadTs('src/main/maverick.ts');
const { DuplicateCheckerService } = loadTs('src/main/duplicateChecker.ts');

function setupTestEnvironment() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-maverick-loop-'));
  const manifestsDir = path.join(tmpDir, 'config', 'skill-manifests');
  const skillsLibDir = path.join(tmpDir, 'skills-library');

  fs.mkdirSync(manifestsDir, { recursive: true });
  fs.mkdirSync(path.join(skillsLibDir, 'skills'), { recursive: true });

  // Initialize test manifests matching real project state
  fs.writeFileSync(
    path.join(manifestsDir, 'chris.json'),
    JSON.stringify({
      desk: '/chris',
      skills: [
        'exploiting-sql-injection-vulnerabilities',
        'exploiting-sql-injection-with-sqlmap',
        'exploiting-server-side-request-forgery',
        'performing-blind-ssrf-exploitation',
        'exploiting-idor-vulnerabilities',
        'exploiting-insecure-deserialization',
        'exploiting-jwt-algorithm-confusion-attack',
        'exploiting-template-injection-vulnerabilities',
        'exploiting-prototype-pollution-in-javascript',
        'performing-directory-traversal-testing',
        'bypassing-authentication-with-forced-browsing',
        'exploiting-race-condition-vulnerabilities'
      ]
    }, null, 2)
  );

  fs.writeFileSync(
    path.join(manifestsDir, 'jonathan.json'),
    JSON.stringify({
      desk: '/jonathan',
      skills: [
        'performing-subdomain-enumeration-with-subfinder',
        'scanning-network-with-nmap-advanced',
        'performing-dns-enumeration-and-zone-transfer',
        'performing-osint-with-spiderfoot',
        'conducting-external-reconnaissance-with-osint',
        'performing-ip-reputation-analysis-with-shodan',
        'performing-web-application-scanning-with-nikto',
        'analyzing-certificate-transparency-for-phishing',
        'analyzing-typosquatting-domains-with-dnstwist',
        'building-threat-actor-profile-from-osint'
      ]
    }, null, 2)
  );

  return { tmpDir, manifestsDir, skillsLibDir };
}

test('Addition 5 — Genuine Paraphrase generates standard 4-section skill format without quoting report', () => {
  const disclosedReport = {
    id: '992011',
    title: 'GraphQL Batch Query Injection causing authentication bypass on internal tenant gateway',
    disclosedAt: '2026-02-15',
    summary: 'The attacker was able to batch multiple queries to bypass rate limits and extract auth tokens from tenant endpoint.',
    platform: 'hackerone',
    targetDomain: 'api.targetcorp.com',
    vulnerabilityClass: 'GraphQL Batching Authentication Bypass',
    url: 'https://hackerone.com/reports/992011'
  };

  const { skillName, content } = synthesizeParaphrasedSkill('GraphQL Batching', '/chris', disclosedReport);

  // 1. Check standard skill slug
  assert.equal(skillName, 'exploiting-graphql-batching');

  // 2. Check 4 required sections + reference
  assert.ok(content.includes('## When to Use'), 'Must contain When to Use section');
  assert.ok(content.includes('## Prerequisites'), 'Must contain Prerequisites section');
  assert.ok(content.includes('## Workflow'), 'Must contain Workflow section');
  assert.ok(content.includes('## Verification'), 'Must contain Verification section');
  assert.ok(content.includes('## Reference'), 'Must contain Reference section');
  assert.ok(content.includes('https://hackerone.com/reports/992011'), 'Must link to source report');

  // 3. Must NOT copy the report summary or sentences
  assert.equal(content.includes('The attacker was able to batch multiple queries'), false, 'Must not quote report body');
});

test('Addition 5 — Recency and Relevance notes flag source date and Maverick qualitative assessment', () => {
  const recentReport = {
    id: '782910',
    title: 'SSRF in Webhook Delivery System',
    disclosedAt: '2026-03-01',
    summary: 'Webhook URL parameter allowed internal network scan.',
    platform: 'hackerone',
    targetDomain: 'target.com',
    vulnerabilityClass: 'SSRF',
    url: 'https://hackerone.com/reports/782910'
  };

  const { recencyNote, relevanceAssessment } = assessRelevanceAndRecency(recentReport);

  assert.ok(recencyNote.includes('2026-03-01'), 'Must mention disclosure date');
  assert.ok(relevanceAssessment.includes('[MAVERICK ASSESSMENT:'), 'Must label assessment as Maverick judgment');
  assert.ok(relevanceAssessment.includes('Actively Prevalent'), 'Must identify active prevalence for SSRF');

  const legacyReport = {
    id: '12093',
    title: 'Flash crossdomain.xml misconfiguration',
    disclosedAt: '2015-01-10',
    summary: 'Flash policy file allows universal access.',
    platform: 'hackerone',
    targetDomain: 'target.com',
    vulnerabilityClass: 'Flash XSS',
    url: 'https://hackerone.com/reports/12093'
  };

  const legacyEval = assessRelevanceAndRecency(legacyReport);
  assert.ok(legacyEval.relevanceAssessment.includes('Commonly Patched / Deprecated'));
});

test('Addition 5 — Desk classification routes disclosed patterns to correct desk scopes', () => {
  const reconReport = {
    id: '1',
    title: 'Subdomain takeover via unregistered DNS record',
    summary: 'CNAME pointed to unclaimed bucket',
    vulnerabilityClass: 'DNS Misconfiguration'
  };
  assert.equal(classifyTargetDesk(reconReport), '/jonathan');

  const codeReport = {
    id: '2',
    title: 'Hardcoded secret API token in open source repository',
    summary: 'Secret token found in git commit history',
    vulnerabilityClass: 'Secret Exposure in Code'
  };
  assert.equal(classifyTargetDesk(codeReport), '/daniel');

  const adReport = {
    id: '3',
    title: 'Kerberoasting attack on service account allows domain escalation',
    summary: 'SPN ticket extraction and cracking',
    vulnerabilityClass: 'Kerberoasting'
  };
  assert.equal(classifyTargetDesk(adReport), '/david');

  const webReport = {
    id: '4',
    title: 'Blind SSRF on payment callback endpoint',
    summary: 'Internal gateway access',
    vulnerabilityClass: 'SSRF'
  };
  assert.equal(classifyTargetDesk(webReport), '/chris');
});

test('Addition 5 — Cap enforcement: Addition to full manifest proposes swap and never overflows cap', () => {
  const { tmpDir, manifestsDir, skillsLibDir } = setupTestEnvironment();
  try {
    const service = new MaverickSkillsService(skillsLibDir, manifestsDir);
    const chrisManifest = service.getDeskManifest('/chris');

    assert.equal(chrisManifest.skills.length, 12, 'Chris manifest must be initially at cap (12/12)');
    assert.equal(DESK_MANIFEST_CAPS.chris, 12);

    const report = {
      id: '884120',
      title: 'GraphQL Batching Query Attack',
      disclosedAt: '2026-02-20',
      summary: 'Authentication bypass via GraphQL batching',
      platform: 'hackerone',
      targetDomain: 'targetcorp.com',
      vulnerabilityClass: 'GraphQL Batching',
      url: 'https://hackerone.com/reports/884120'
    };

    const swap = proposeSkillSwap('/chris', chrisManifest.skills, 'exploiting-graphql-batching', report);

    assert.ok(swap.skillToRemove, 'Must specify a skill to remove');
    assert.ok(chrisManifest.skills.includes(swap.skillToRemove), 'Skill to remove must exist in current manifest');
    assert.ok(swap.reasoning.includes('12/12'), 'Reasoning must cite current cap');
    assert.ok(swap.reasoning.includes(swap.skillToRemove), 'Reasoning must mention skill being replaced');
    assert.ok(swap.reasoning.includes('exploiting-graphql-batching'), 'Reasoning must mention proposed skill');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Addition 5 — Human Approval Gate: Zero manifest changes occur until human explicitly approves', async () => {
  const { tmpDir, manifestsDir, skillsLibDir } = setupTestEnvironment();
  try {
    const service = new MaverickSkillsService(skillsLibDir, manifestsDir);

    // Mock API fetcher returning a recently disclosed report
    const mockFetcher = async () => [
      {
        id: '992144',
        title: 'Server-Side Request Forgery via Image Metadata Parser',
        disclosedAt: '2026-03-05',
        summary: 'Exif parser allows SSRF to cloud metadata.',
        platform: 'hackerone',
        targetDomain: 'targetcorp.com',
        vulnerabilityClass: 'SSRF via Image Parser',
        url: 'https://hackerone.com/reports/992144'
      }
    ];

    const duplicateChecker = new DuplicateCheckerService(mockFetcher);

    const activePrograms = [
      {
        name: 'TargetCorp Bug Bounty',
        platform: 'hackerone',
        in_scope: ['targetcorp.com']
      }
    ];

    // 1. Run review loop
    const proposals = await service.reviewDisclosedReports(activePrograms, duplicateChecker, {
      targetDeskOverride: '/chris'
    });

    assert.equal(proposals.length, 1, 'Must generate 1 candidate proposal');
    const proposal = proposals[0];
    assert.equal(proposal.status, 'PENDING_HUMAN_APPROVAL');
    assert.equal(proposal.isAtCap, true, 'Chris is at 12/12 cap');
    assert.ok(proposal.swap, 'Must contain swap proposal');

    // CRITICAL: Manifest on disk MUST BE UNTOUCHED before approval
    const manifestBefore = JSON.parse(fs.readFileSync(path.join(manifestsDir, 'chris.json'), 'utf8'));
    assert.equal(manifestBefore.skills.length, 12);
    assert.equal(manifestBefore.skills.includes(proposal.proposedSkillName), false, 'New skill must NOT be on disk yet');
    assert.equal(manifestBefore.skills.includes(proposal.swap.skillToRemove), true, 'Old skill must NOT be removed yet');

    // 2. Human explicitly approves the proposal
    const result = service.approveProposal(proposal.id, 'lead-security-officer');
    assert.equal(result.success, true);
    assert.ok(result.message.includes('lead-security-officer'));

    // 3. Verify manifest on disk is now safely updated within cap
    const manifestAfter = JSON.parse(fs.readFileSync(path.join(manifestsDir, 'chris.json'), 'utf8'));
    assert.equal(manifestAfter.skills.length, 12, 'Cap (12/12) must be preserved');
    assert.equal(manifestAfter.skills.includes(proposal.proposedSkillName), true, 'New skill is now present');
    assert.equal(manifestAfter.skills.includes(proposal.swap.skillToRemove), false, 'Old skill was removed');

    // 4. Verify skill file was written to skills library
    const writtenSkillPath = path.join(skillsLibDir, 'skills', proposal.proposedSkillName, 'SKILL.md');
    assert.ok(fs.existsSync(writtenSkillPath), 'SKILL.md must be written to skills library');
    const skillContent = fs.readFileSync(writtenSkillPath, 'utf8');
    assert.ok(skillContent.includes('## When to Use'));
    assert.ok(skillContent.includes('https://hackerone.com/reports/992144'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Addition 5 — HiveManager integration triggers review and exposes approval gate', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-hive-maverick-'));
  try {
    const mockFetcher = async () => [
      {
        id: '109923',
        title: 'Bypassing Access Controls with Path Truncation',
        disclosedAt: '2026-02-28',
        summary: 'Path truncation allowed accessing private endpoints.',
        platform: 'hackerone',
        targetDomain: 'authorized-lab.internal',
        vulnerabilityClass: 'Path Truncation Authorization Bypass',
        url: 'https://hackerone.com/reports/109923'
      }
    ];

    const duplicateChecker = new DuplicateCheckerService(mockFetcher);
    const mockProgReg = {
      listPrograms: () => [
        {
          program: 'targetcorp',
          platform: 'hackerone',
          in_scope: ['targetcorp.com'],
          last_verified: '2026-09-13',
          verified_by: 'human'
        }
      ]
    };
    const hive = new HiveManager(() => tmpDir, undefined, mockProgReg, duplicateChecker);

    // Run review
    const proposals = await hive.reviewDisclosedSkills();
    assert.ok(proposals.length >= 1, 'Review must produce candidate proposals');

    const pending = hive.getPendingSkillProposals();
    assert.ok(pending.length >= 1, 'Must show pending proposals');

    const first = pending[0];
    assert.equal(first.status, 'PENDING_HUMAN_APPROVAL');

    // Rejection test
    const rejectRes = hive.rejectSkillProposal(first.id, 'Redundant with existing path traversal skill', 'human-operator');
    assert.equal(rejectRes.success, true);
    assert.equal(hive.getProposal(first.id).status, 'REJECTED');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
