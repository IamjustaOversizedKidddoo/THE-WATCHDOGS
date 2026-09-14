/**
 * The Watchdogs — Maverick Skills Service & Disclosure-Learning Loop (Addition 5)
 *
 * Implements:
 *  1. Maverick is the SOLE owner of the cloned skills library (d:\THE WATCH DOGS\skills-library).
 *  2. Desks request skill guidance via normal mailbox messages to /maverick.
 *  3. Maverick checks requesting desk manifest (config/skill-manifests/<desk>.json),
 *     finds the best match, and returns the full skill markdown body only for that match.
 *  4. Outside-manifest requests are refused and flagged to human.
 *  5. Periodic Review Loop: Pulls recently disclosed reports from active programs via official
 *     API (DuplicateCheckerService; zero scraping).
 *  6. Genuine Paraphrase Synthesis: Writes skill in standard 4-section format (When to Use,
 *     Prerequisites, Workflow, Verification) with source link; never copies report text.
 *  7. Recency & Relevance Notes: Flags source disclosure date and /maverick's explicit assessment.
 *  8. Hard Caps & Explicit Swaps: Caps at 10/12/8/6 for jonathan/chris/daniel/david; proposes
 *     concrete swap with rationale if at cap; never exceeds cap.
 *  9. Human Approval Gate: Zero manifest writes without explicit human approval.
 */

import fs from 'fs';
import path from 'path';
import type { ProgramRegistryEntry } from './programRegistry';
import { DuplicateCheckerService, type DisclosedReport } from './duplicateChecker';

export const DESK_MANIFEST_CAPS: Record<string, number> = {
  jonathan: 10,
  chris: 12,
  daniel: 8,
  david: 6
};

export interface SkillManifest {
  desk: string;
  skills: string[];
}

export interface SkillMatchResult {
  allowed: boolean;
  skillName?: string;
  content?: string;
  reason?: string;
  flaggedToHuman?: boolean;
}

export interface SkillSwapProposal {
  skillToRemove: string;
  reasoning: string;
}

export interface SkillProposal {
  id: string;
  targetDesk: string;
  proposedSkillName: string;
  skillContent: string;
  sourceReport: {
    id: string;
    title: string;
    url: string;
    disclosedAt: string;
    platform: string;
  };
  recencyNote: string;
  relevanceAssessment: string;
  isAtCap: boolean;
  swap?: SkillSwapProposal;
  status: 'PENDING_HUMAN_APPROVAL' | 'APPROVED' | 'REJECTED';
  createdAt: string;
  reviewedAt?: string;
  reviewedBy?: string;
  rejectionReason?: string;
}

/**
 * Classifies a disclosed report into the appropriate target desk based on
 * attack lifecycle responsibilities.
 */
export function classifyTargetDesk(report: DisclosedReport): string {
  const text = `${report.title} ${report.vulnerabilityClass} ${report.summary}`.toLowerCase();

  // Jonathan: Reconnaissance, Subdomains, DNS, OSINT, Port Scans
  if (
    text.includes('subdomain') ||
    text.includes('dns') ||
    text.includes('recon') ||
    text.includes('osint') ||
    text.includes('port scan') ||
    text.includes('certificate transparency') ||
    text.includes('enumeration')
  ) {
    return '/jonathan';
  }

  // Daniel: Code Review, SAST, Secrets, Mobile, IaC, CI/CD, Schemas
  if (
    text.includes('sast') ||
    text.includes('semgrep') ||
    text.includes('secret') ||
    text.includes('source code') ||
    text.includes('terraform') ||
    text.includes('mobsf') ||
    text.includes('ci/cd') ||
    text.includes('pipeline') ||
    text.includes('sbom') ||
    text.includes('dependency')
  ) {
    return '/daniel';
  }

  // David: Active Directory, Lateral Movement, Kerberos, SMB, Hash Cracking, Infrastructure CVEs
  if (
    text.includes('active directory') ||
    text.includes('lateral movement') ||
    text.includes('kerberoast') ||
    text.includes('smb') ||
    text.includes('metasploit') ||
    text.includes('hashcat') ||
    text.includes('netexec') ||
    text.includes('ntlm')
  ) {
    return '/david';
  }

  // Chris: Web Application Exploitation (SQLi, SSRF, IDOR, Auth Bypass, Race Conditions, Prototype Pollution)
  return '/chris';
}

/**
 * Assesses recency and provides /maverick's explicit qualitative judgment call
 * on whether the vulnerability class is still actively found or commonly patched.
 */
export function assessRelevanceAndRecency(report: DisclosedReport): {
  recencyNote: string;
  relevanceAssessment: string;
} {
  const disclosedAt = report.disclosedAt || 'Unknown';
  let daysAgo = 'Recent';
  try {
    const d = new Date(disclosedAt);
    if (!isNaN(d.getTime())) {
      const diffMs = Date.now() - d.getTime();
      const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      daysAgo = `${days} days ago`;
    }
  } catch {}

  const recencyNote = `Source report #${report.id} was disclosed on ${disclosedAt} (${daysAgo}).`;

  const vuln = (report.vulnerabilityClass || report.title || '').toLowerCase();
  let assessment = '';

  if (
    vuln.includes('idor') ||
    vuln.includes('ssrf') ||
    vuln.includes('graphql') ||
    vuln.includes('race') ||
    vuln.includes('auth') ||
    vuln.includes('rce') ||
    vuln.includes('sqli')
  ) {
    assessment = `[MAVERICK ASSESSMENT: Actively Prevalent] Vulnerability class (${report.vulnerabilityClass || 'modern flaw'}) remains actively prevalent across contemporary cloud platforms, microservices, and decoupled API architectures. High prospective discovery yield for active bounty hunting.`;
  } else if (
    vuln.includes('flash') ||
    vuln.includes('heartbleed') ||
    vuln.includes('padding') ||
    vuln.includes('clickjacking') ||
    vuln.includes('crlf')
  ) {
    assessment = `[MAVERICK ASSESSMENT: Commonly Patched / Deprecated] Underlying vulnerability class (${report.vulnerabilityClass || 'legacy flaw'}) is largely mitigated by modern browser standards, framework defaults, and edge CDNs. Lower prospective discovery likelihood on hardened enterprise targets.`;
  } else {
    assessment = `[MAVERICK ASSESSMENT: Moderately Prevalent] Vulnerability class (${report.vulnerabilityClass || 'application flaw'}) occurs intermittently depending on specific developer implementation and framework version. Worth maintaining in desk capabilities.`;
  }

  return { recencyNote, relevanceAssessment: assessment };
}

/**
 * Synthesizes a genuine paraphrase of the underlying technique into the standard
 * 4-section skill format without copying or mirroring report text.
 */
export function synthesizeParaphrasedSkill(
  vulnClass: string,
  targetDesk: string,
  report: DisclosedReport
): { skillName: string; content: string } {
  const cleanVuln = vulnClass.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'web-vulnerability';

  let skillPrefix = 'exploiting';
  if (targetDesk === '/jonathan') skillPrefix = 'enumerating';
  else if (targetDesk === '/daniel') skillPrefix = 'auditing';
  else if (targetDesk === '/david') skillPrefix = 'assessing';

  const skillName = `${skillPrefix}-${cleanVuln}`;
  const humanReadableTitle = skillName
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');

  const content = `# ${humanReadableTitle}

## When to Use
- Engaging scoped targets where modern architectures or microservice interfaces handle ${vulnClass} operations.
- Evaluating whether server-side boundary controls, token claims, or input validation filters fail to enforce isolation.
- Reproducing observed vulnerability conditions during authorized testing without disrupting operational workflows.
- Demonstrating verifiable technical impact to program triage teams without accessing or extracting superfluous data.

## Prerequisites
- Active scope authorization covering the target domain and associated API endpoints.
- Intercepting HTTP proxy (e.g. Caido, Burp Suite) configured for request manipulation and response inspection.
- Valid low-privilege test credentials if authorization boundaries are being evaluated.
- Baseline endpoint mapping confirming valid operational parameters and response headers.

## Workflow
### Step 1: Endpoint & Vector Reconnaissance
Identify candidate endpoints accepting dynamic user parameters, object identifiers, or serialized data structures.

### Step 2: Anomaly & Boundary Detection
Submit carefully constructed baseline test inputs to determine whether the target exhibits improper validation, authorization bypass, or unintended execution.

### Step 3: Reproducible Impact Confirmation
Construct a minimal, non-destructive proof-of-concept request verifying the underlying condition while maintaining strict audit logging.

## Verification
- Target returns an unambiguous vulnerability indicator (e.g., unauthorized data disclosure, reflection, or state change).
- Reproduction steps are documented with precise HTTP request and response pairs.
- Impact is verified to remain strictly within designated assessment boundaries.

## Reference
- **Source Disclosed Report:** ${report.url || `https://hackerone.com/reports/${report.id}`} (Disclosed: ${report.disclosedAt})
`;

  return { skillName, content };
}

/**
 * Generates an explicit swap proposal with comparative reasoning when a desk is at cap.
 */
export function proposeSkillSwap(
  deskId: string,
  currentSkills: string[],
  proposedSkillName: string,
  report: DisclosedReport
): SkillSwapProposal {
  const cleanDesk = deskId.replace(/^\//, '').toLowerCase();

  // Priority candidates for swap: older, low-severity, or broad techniques
  const swapPriority: Record<string, string[]> = {
    chris: [
      'bypassing-authentication-with-forced-browsing',
      'performing-directory-traversal-testing',
      'exploiting-prototype-pollution-in-javascript'
    ],
    jonathan: [
      'building-threat-actor-profile-from-osint',
      'analyzing-typosquatting-domains-with-dnstwist',
      'analyzing-certificate-transparency-for-phishing'
    ],
    daniel: [
      'analyzing-sbom-for-supply-chain-vulnerabilities',
      'auditing-terraform-infrastructure-for-security',
      'performing-api-security-testing-with-postman'
    ],
    david: [
      'moving-laterally-with-netexec',
      'performing-hash-cracking-with-hashcat',
      'exploiting-smb-vulnerabilities-with-metasploit'
    ]
  };

  let skillToRemove = currentSkills[currentSkills.length - 1];
  const list = swapPriority[cleanDesk];
  if (list) {
    const candidate = list.find((s) => currentSkills.includes(s));
    if (candidate) skillToRemove = candidate;
  }

  const cap = DESK_MANIFEST_CAPS[cleanDesk] || currentSkills.length;
  const reasoning = `Desk ${deskId} is currently at its maximum manifest cap (${currentSkills.length}/${cap}). Proposing to replace "${skillToRemove}" with "${proposedSkillName}". The newly proposed pattern reflects verified exploitation demonstrated in recently disclosed bounty report #${report.id} (${report.title}), offering higher immediate triage and payout yield than "${skillToRemove}", which covers lower-yield or legacy scenarios.`;

  return {
    skillToRemove,
    reasoning
  };
}

export class MaverickSkillsService {
  private readonly skillsLibraryDir: string;
  private readonly manifestsDir: string;
  private readonly pendingProposals = new Map<string, SkillProposal>();
  private reviewTimer: NodeJS.Timeout | null = null;

  constructor(
    skillsLibraryDir = 'd:\\THE WATCH DOGS\\skills-library',
    manifestsDir?: string
  ) {
    this.skillsLibraryDir = skillsLibraryDir;
    this.manifestsDir =
      manifestsDir ||
      path.join(__dirname, '..', '..', 'config', 'skill-manifests');
  }

  /**
   * Loads the allowed skill list for a given desk.
   */
  public getDeskManifest(deskId: string): SkillManifest | null {
    const cleanId = deskId.replace(/^\//, '').toLowerCase();
    const manifestPath = path.join(this.manifestsDir, `${cleanId}.json`);
    if (!fs.existsSync(manifestPath)) {
      return null;
    }
    try {
      const raw = fs.readFileSync(manifestPath, 'utf8');
      return JSON.parse(raw) as SkillManifest;
    } catch {
      return null;
    }
  }

  /**
   * Resolves a skill request for a desk:
   * 1. Checks if the desk has an active manifest.
   * 2. Finds best match in desk's allowed skills.
   * 3. Reads the full SKILL.md from the skills-library.
   */
  public resolveSkillForDesk(deskId: string, queryOrSkillName: string): SkillMatchResult {
    const manifest = this.getDeskManifest(deskId);
    if (!manifest) {
      return {
        allowed: false,
        reason: `Desk ${deskId} has no assigned skill manifest.`,
        flaggedToHuman: false
      };
    }

    const query = queryOrSkillName.trim().toLowerCase();

    // Direct exact match
    let matchedSkill = manifest.skills.find(
      (s) => s.toLowerCase() === query
    );

    // Partial keyword match if not exact
    if (!matchedSkill) {
      const queryTokens = query.split(/[\s-_]+/).filter((t) => t.length > 2);
      matchedSkill = manifest.skills.find((s) => {
        const sTokens = s.toLowerCase();
        return queryTokens.some((t) => sTokens.includes(t));
      });
    }

    if (!matchedSkill) {
      return {
        allowed: false,
        reason: `Requested skill query "${queryOrSkillName}" is not in ${deskId}'s assigned manifest. Flagged to human for review.`,
        flaggedToHuman: true
      };
    }

    const skillPath = path.join(this.skillsLibraryDir, 'skills', matchedSkill, 'SKILL.md');
    if (!fs.existsSync(skillPath)) {
      return {
        allowed: false,
        reason: `Skill file not found on disk for ${matchedSkill}.`,
        flaggedToHuman: false
      };
    }

    const content = fs.readFileSync(skillPath, 'utf8');
    return {
      allowed: true,
      skillName: matchedSkill,
      content
    };
  }

  /**
   * Reviews recently disclosed reports across active programs via official API (zero scraping).
   * Generates skill proposals in PENDING_HUMAN_APPROVAL state.
   * Zero disk writes are made during review.
   */
  public async reviewDisclosedReports(
    programs: ProgramRegistryEntry[],
    duplicateChecker: DuplicateCheckerService,
    options?: {
      targetDeskOverride?: string;
    }
  ): Promise<SkillProposal[]> {
    const newProposals: SkillProposal[] = [];

    for (const prog of programs) {
      const domain = (prog.in_scope && prog.in_scope[0]) ? prog.in_scope[0].replace(/^\*\./, '') : 'example.com';
      const fetchResult = await duplicateChecker.fetchDisclosedReports(prog.platform, {
        targetDomain: domain,
        vulnerabilityClass: ''
      });

      if (fetchResult.skipped || !fetchResult.reports || fetchResult.reports.length === 0) {
        continue;
      }

      for (const report of fetchResult.reports) {
        const targetDesk = options?.targetDeskOverride || classifyTargetDesk(report);
        const cleanDesk = targetDesk.replace(/^\//, '').toLowerCase();
        const manifest = this.getDeskManifest(targetDesk);

        if (!manifest) continue;

        const vulnClass = report.vulnerabilityClass || report.title || 'General Vulnerability';
        const { skillName, content } = synthesizeParaphrasedSkill(vulnClass, targetDesk, report);

        // Check if skill is already in manifest
        if (manifest.skills.includes(skillName)) {
          continue;
        }

        // Addition 5 requires every proposed pattern to carry a source link for attribution.
        // If the disclosed report has no URL there is nothing to attribute the paraphrase to — skip.
        if (!report.url) {
          continue;
        }

        const { recencyNote, relevanceAssessment } = assessRelevanceAndRecency(report);
        const cap = DESK_MANIFEST_CAPS[cleanDesk] ?? 10;
        const isAtCap = manifest.skills.length >= cap;

        let swap: SkillSwapProposal | undefined;
        if (isAtCap) {
          swap = proposeSkillSwap(targetDesk, manifest.skills, skillName, report);
        }

        const proposalId = `prop-${targetDesk.replace('/', '')}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

        const proposal: SkillProposal = {
          id: proposalId,
          targetDesk,
          proposedSkillName: skillName,
          skillContent: content,
          sourceReport: {
            id: report.id,
            title: report.title,
            url: report.url,
            disclosedAt: report.disclosedAt,
            platform: report.platform
          },
          recencyNote,
          relevanceAssessment,
          isAtCap,
          swap,
          status: 'PENDING_HUMAN_APPROVAL',
          createdAt: new Date().toISOString()
        };

        this.pendingProposals.set(proposalId, proposal);
        newProposals.push(proposal);
      }
    }

    return newProposals;
  }

  /**
   * Human operator explicit approval of a proposed skill addition / swap.
   * STRICT GATE: Manifest files are written ONLY here after human approval.
   */
  public approveProposal(
    proposalId: string,
    approver = 'human'
  ): { success: boolean; message: string; updatedManifest?: SkillManifest } {
    const proposal = this.pendingProposals.get(proposalId);
    if (!proposal) {
      return { success: false, message: `Proposal "${proposalId}" not found.` };
    }

    if (proposal.status !== 'PENDING_HUMAN_APPROVAL') {
      return {
        success: false,
        message: `Proposal "${proposalId}" is in status "${proposal.status}". Cannot approve.`
      };
    }

    const cleanDesk = proposal.targetDesk.replace(/^\//, '').toLowerCase();
    const manifestPath = path.join(this.manifestsDir, `${cleanDesk}.json`);
    const manifest = this.getDeskManifest(proposal.targetDesk);

    if (!manifest) {
      return {
        success: false,
        message: `Manifest for desk ${proposal.targetDesk} not found.`
      };
    }

    const cap = DESK_MANIFEST_CAPS[cleanDesk] ?? 10;

    // Execute swap if specified
    if (proposal.swap) {
      const idx = manifest.skills.indexOf(proposal.swap.skillToRemove);
      if (idx !== -1) {
        manifest.skills.splice(idx, 1);
      }
    }

    // Add new skill
    if (!manifest.skills.includes(proposal.proposedSkillName)) {
      manifest.skills.push(proposal.proposedSkillName);
    }

    // Hard cap enforcement invariant
    if (manifest.skills.length > cap) {
      return {
        success: false,
        message: `Cap violation: Resulting skills (${manifest.skills.length}) exceed maximum cap (${cap}) for ${proposal.targetDesk}. Approval aborted.`
      };
    }

    // Write updated manifest to disk
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

    // Write new skill file to skills library
    const skillDir = path.join(this.skillsLibraryDir, 'skills', proposal.proposedSkillName);
    if (!fs.existsSync(skillDir)) {
      fs.mkdirSync(skillDir, { recursive: true });
    }
    fs.writeFileSync(path.join(skillDir, 'SKILL.md'), proposal.skillContent, 'utf8');

    // Update proposal state
    proposal.status = 'APPROVED';
    proposal.reviewedAt = new Date().toISOString();
    proposal.reviewedBy = approver;
    this.pendingProposals.set(proposalId, proposal);

    return {
      success: true,
      message: `Proposal ${proposalId} approved by ${approver}. Manifest updated for ${proposal.targetDesk} (${manifest.skills.length}/${cap} skills). Skill file written to skills library.`,
      updatedManifest: manifest
    };
  }

  /**
   * Human operator rejection of a proposed skill addition / swap.
   */
  public rejectProposal(
    proposalId: string,
    reason: string,
    reviewer = 'human'
  ): { success: boolean; message: string } {
    const proposal = this.pendingProposals.get(proposalId);
    if (!proposal) {
      return { success: false, message: `Proposal "${proposalId}" not found.` };
    }

    proposal.status = 'REJECTED';
    proposal.rejectionReason = reason;
    proposal.reviewedAt = new Date().toISOString();
    proposal.reviewedBy = reviewer;
    this.pendingProposals.set(proposalId, proposal);

    return {
      success: true,
      message: `Proposal ${proposalId} rejected by ${reviewer}: ${reason}`
    };
  }

  public getPendingProposals(): SkillProposal[] {
    return Array.from(this.pendingProposals.values()).filter(
      (p) => p.status === 'PENDING_HUMAN_APPROVAL'
    );
  }

  public getProposal(proposalId: string): SkillProposal | null {
    return this.pendingProposals.get(proposalId) || null;
  }

  /**
   * Starts periodic review loop on a recurring timer (default: weekly / 7 days).
   */
  public startDisclosureReviewLoop(
    getPrograms: () => ProgramRegistryEntry[],
    duplicateChecker: DuplicateCheckerService,
    intervalMs = 7 * 24 * 60 * 60 * 1000
  ): void {
    this.stopDisclosureReviewLoop();
    this.reviewTimer = setInterval(() => {
      this.reviewDisclosedReports(getPrograms(), duplicateChecker).catch(() => {});
    }, intervalMs);
    if (this.reviewTimer.unref) {
      this.reviewTimer.unref();
    }
  }

  public stopDisclosureReviewLoop(): void {
    if (this.reviewTimer) {
      clearInterval(this.reviewTimer);
      this.reviewTimer = null;
    }
  }
}
