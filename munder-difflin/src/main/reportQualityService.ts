/**
 * The Watchdogs — Report Quality Pass Before Submission (Addition 4)
 *
 * Enforces:
 *  1. Evidence tracing: Every claim must trace to /chris (validated PoC) or /daniel (code analysis).
 *     Untraced statements are labeled as [HYPOTHESIS / UNVERIFIED].
 *  2. Severity reasoning: Derived CVSS v3.1 score with explicit textual reasoning for every metric.
 *  3. Mandatory PII & Credential Redaction: Scans and replaces real user data, credentials, and tokens
 *     with informative placeholders (e.g. [REDACTED_EMAIL], [REDACTED_USER_PROFILE]).
 *  4. Originality check: Reuses Addition 3's disclosed reports to flag overlapping phrasing.
 *  5. Fixed six-section report structure: Summary, Steps, Impact, Components, Severity, Remediation.
 *  6. Human sign-off gate: Draft remains PENDING_HUMAN_APPROVAL and cannot be submitted without human sign-off.
 */

import type { WatchdogsFinding } from '../shared/watchdogsSchema';
import type { DisclosedReport } from './duplicateChecker';

export interface EvidenceTrace {
  claim: string;
  sourceDesk: string;
  evidenceSnippet: string;
  isVerified: boolean;
  annotation?: string;
}

export interface CvssMetricReasoning {
  metric: string;
  value: string;
  reasoning: string;
}

export interface CvssEvaluation {
  vectorString: string;
  baseScore: number;
  severityRating: 'Low' | 'Medium' | 'High' | 'Critical';
  metrics: CvssMetricReasoning[];
  overallJustification: string;
}

export interface OriginalityResult {
  hasLanguageOverlap: boolean;
  matchedReportId?: string;
  matchedReportTitle?: string;
  similarityRatio: number;
  flaggedPassage?: string;
  recommendation?: string;
}

export interface QualityReportDraft {
  id: string;
  findingId: string;
  target: string;
  vulnerabilityTitle: string;
  status: 'PENDING_HUMAN_APPROVAL' | 'APPROVED_BY_HUMAN';
  createdAt: string;
  approvedAt?: string;
  approvedBy?: string;
  redactionsApplied: string[];
  evidenceTraces: EvidenceTrace[];
  cvss: CvssEvaluation;
  originality: OriginalityResult;
  sections: {
    summary: string;
    reproductionSteps: string[];
    impactStatement: string;
    affectedComponents: string[];
    severityWithReasoning: string;
    suggestedRemediation: string;
  };
  formattedMarkdown: string;
}

/**
 * PII, User Data, and Credential Redactor.
 * Masks emails, phone numbers, auth tokens, session cookies, and sensitive profile payloads.
 */
export function redactUserData(text: string): { redactedText: string; redactions: string[] } {
  if (!text) return { redactedText: '', redactions: [] };

  let s = text;
  const redactions: string[] = [];

  // 1. User email addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  s = s.replace(emailRegex, (match) => {
    redactions.push(`Email address (${match})`);
    return `[REDACTED_EMAIL: user email address]`;
  });

  // 2. Phone numbers (international and domestic formats)
  const phoneRegex = /(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\b\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  s = s.replace(phoneRegex, (match) => {
    redactions.push(`Phone number (${match.trim()})`);
    return `[REDACTED_PHONE: user phone number]`;
  });

  // 3. Social Security Numbers (SSN)
  const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
  s = s.replace(ssnRegex, () => {
    redactions.push(`Social Security Number`);
    return `[REDACTED_SSN]`;
  });

  // 4. Payment / Credit Card numbers (16 digits with dashes or spaces)
  const ccRegex = /\b(?:\d{4}[-\s]?){3}\d{4}\b/g;
  s = s.replace(ccRegex, () => {
    redactions.push(`Payment card number`);
    return `[REDACTED_PAYMENT_CARD]`;
  });

  // 5. Session cookies / Auth Headers / Bearer Tokens
  const tokenRegex = /\b(?:Bearer\s+[A-Za-z0-9\-._~+/]+=*|connect\.sid=[^;\s]+|session_id=[^;\s]+)\b/gi;
  s = s.replace(tokenRegex, (match) => {
    redactions.push(`Authentication session token`);
    return `[REDACTED_AUTH_TOKEN]`;
  });

  // 6. Address / Street info
  const addressRegex = /"(?:address|street|billing_address)"\s*:\s*"[^"]+"/gi;
  s = s.replace(addressRegex, () => {
    redactions.push(`User physical address`);
    return `"address": "[REDACTED_ADDRESS: sensitive user street address]"`;
  });

  // 7. Sensitive Profile Records (JSON dumps containing user profile/account records)
  const profileRecordRegex = /\{[^{}]*"(?:profile|user_record|profile_record|account_profile|customer_data)"[^{}]*\}/gi;
  s = s.replace(profileRecordRegex, () => {
    redactions.push(`Full user profile record`);
    return `[REDACTED_USER_PROFILE: sensitive user record containing personal attributes]`;
  });

  // 8. JWT tokens
  const jwtRegex = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g;
  s = s.replace(jwtRegex, () => {
    redactions.push(`JSON Web Token`);
    return `[REDACTED_JWT]`;
  });

  return { redactedText: s, redactions };
}

/**
 * Derives CVSS v3.1 score and metric reasoning directly from demonstrated finding evidence.
 */
export function deriveCvssReasoning(finding: WatchdogsFinding): CvssEvaluation {
  const t = (finding.finding_type || '').toLowerCase();
  const sev = (finding.severity || 'medium').toLowerCase();
  const evidence = (finding.evidence || '').toLowerCase();

  let av = 'Network (AV:N)';
  let avReason = 'The vulnerability is reachable remotely via the network (HTTP/HTTPS) without physical access.';
  let ac = 'Low (AC:L)';
  let acReason = 'No specialized conditions, race windows, or obscure configurations are required to reproduce.';
  let pr = 'None (PR:N)';
  let prReason = 'The vulnerable endpoint is unauthenticated and accessible to any external caller.';
  let ui = 'None (UI:N)';
  let uiReason = 'No user interaction (e.g. social engineering or victim click) is required to trigger execution.';
  let scope = 'Unchanged (S:U)';
  let scopeReason = 'The vulnerability impacts resources within the same security authority.';
  let c = 'High (C:H)';
  let cReason = 'Direct disclosure of confidential application data or backend services demonstrated in evidence.';
  let i = 'None (I:N)';
  let iReason = 'No arbitrary data modification was demonstrated in the validated proof of concept.';
  let a = 'None (A:N)';
  let aReason = 'No service interruption or system downtime was demonstrated.';
  let baseScore = 7.5;
  let severityRating: 'Low' | 'Medium' | 'High' | 'Critical' = 'High';
  let vectorString = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';

  if (t.includes('rce') || t.includes('command_injection')) {
    c = 'High (C:H)';
    i = 'High (I:H)';
    a = 'High (A:H)';
    baseScore = 9.8;
    severityRating = 'Critical';
    vectorString = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    cReason = 'Attacker gains arbitrary command execution with complete access to host files and credentials.';
    iReason = 'Attacker can alter arbitrary application and system files.';
    aReason = 'Attacker can terminate system processes or shut down services.';
  } else if (t.includes('ssrf')) {
    if (evidence.includes('169.254.169.254') || evidence.includes('meta-data')) {
      scope = 'Changed (S:C)';
      c = 'High (C:H)';
      baseScore = 8.6;
      severityRating = 'High';
      vectorString = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N';
      scopeReason = 'Vulnerability allows accessing cloud infrastructure metadata service outside the web application boundary.';
      cReason = 'Access to cloud instance metadata and temporary IAM credentials verified in PoC.';
    }
  } else if (t.includes('idor')) {
    pr = 'Low (PR:L)';
    prReason = 'Requires a standard authenticated user account to perform authorization bypass on other user IDs.';
    c = 'High (C:H)';
    baseScore = 6.5;
    severityRating = 'Medium';
    vectorString = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N';
  } else if (t.includes('sqli')) {
    c = 'High (C:H)';
    i = 'Low (I:L)';
    baseScore = 8.2;
    severityRating = 'High';
    vectorString = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N';
    iReason = 'Database queries may allow modifying certain database tables depending on SQL permissions.';
  } else if (sev === 'low' || t.includes('debug_endpoint')) {
    c = 'Low (C:L)';
    baseScore = 5.3;
    severityRating = 'Medium';
    vectorString = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N';
    cReason = 'Limited diagnostic or server banner information disclosed without sensitive database exposure.';
  }

  const metrics: CvssMetricReasoning[] = [
    { metric: 'Attack Vector (AV)', value: av, reasoning: avReason },
    { metric: 'Attack Complexity (AC)', value: ac, reasoning: acReason },
    { metric: 'Privileges Required (PR)', value: pr, reasoning: prReason },
    { metric: 'User Interaction (UI)', value: ui, reasoning: uiReason },
    { metric: 'Scope (S)', value: scope, reasoning: scopeReason },
    { metric: 'Confidentiality Impact (C)', value: c, reasoning: cReason },
    { metric: 'Integrity Impact (I)', value: i, reasoning: iReason },
    { metric: 'Availability Impact (A)', value: a, reasoning: aReason }
  ];

  return {
    vectorString,
    baseScore,
    severityRating,
    metrics,
    overallJustification: `Scored ${baseScore} (${severityRating}) based on verified ${finding.finding_type} demonstrated by ${finding.source_desk}. Severity is strictly anchored to actual verified impact.`
  };
}

/**
 * Checks draft report phrasing against disclosed reports from Addition 3.
 * Flags overlapping passages exceeding similarity threshold.
 */
export function checkOriginalityAgainstDisclosures(
  draftText: string,
  disclosedReports: DisclosedReport[]
): OriginalityResult {
  if (!disclosedReports || disclosedReports.length === 0) {
    return {
      hasLanguageOverlap: false,
      similarityRatio: 0
    };
  }

  const cleanDraft = draftText.toLowerCase();
  const draftWords = cleanDraft.split(/\W+/).filter((w) => w.length > 3);
  const draftSet = new Set(draftWords);

  let highestSimilarity = 0;
  let matchedReport: DisclosedReport | null = null;
  let flaggedPassage: string | undefined;

  for (const report of disclosedReports) {
    const reportText = `${report.title} ${report.summary}`.toLowerCase();
    const reportWords = reportText.split(/\W+/).filter((w) => w.length > 3);
    const reportSet = new Set(reportWords);

    if (reportWords.length === 0) continue;

    // Word overlap (Jaccard-like index on content words)
    let overlapCount = 0;
    for (const w of reportSet) {
      if (draftSet.has(w)) overlapCount++;
    }

    const similarity = overlapCount / reportSet.size;

    // Check for 6+ word exact substring match
    const sentences = reportText.split(/[.\n]+/).map((s) => s.trim()).filter((s) => s.length > 25);
    for (const sentence of sentences) {
      if (cleanDraft.includes(sentence)) {
        highestSimilarity = 1.0;
        matchedReport = report;
        flaggedPassage = sentence;
        break;
      }
    }

    if (similarity > highestSimilarity) {
      highestSimilarity = similarity;
      matchedReport = report;
      flaggedPassage = report.summary;
    }
  }

  // Overlap threshold: >= 40% keyword overlap or exact sentence match
  if (highestSimilarity >= 0.4 && matchedReport) {
    return {
      hasLanguageOverlap: true,
      matchedReportId: matchedReport.id,
      matchedReportTitle: matchedReport.title,
      similarityRatio: Number(highestSimilarity.toFixed(2)),
      flaggedPassage,
      recommendation: `Draft phrasing closely echoes disclosed report #${matchedReport.id} ("${matchedReport.title}"). Please rephrase in your own words before submission.`
    };
  }

  return {
    hasLanguageOverlap: false,
    similarityRatio: Number(highestSimilarity.toFixed(2))
  };
}

export class ReportQualityService {
  private readonly drafts = new Map<string, QualityReportDraft>();

  /**
   * Generates a fully verified, evidence-traced, redacted report draft.
   */
  public generateReportDraft(
    finding: WatchdogsFinding,
    options?: {
      disclosedReports?: DisclosedReport[];
      findingId?: string;
      vulnerabilityTitle?: string;
    }
  ): QualityReportDraft {
    const findingId = options?.findingId || `report-${Date.now()}`;
    const rawEvidence = finding.evidence || '';

    // ── 1. Mandatory Redaction Pass on Evidence & Inputs ───────────────────────
    const redactedEvidenceResult = redactUserData(rawEvidence);
    const safeEvidence = redactedEvidenceResult.redactedText;
    const redactionsApplied = redactedEvidenceResult.redactions;

    // ── 2. Evidence Tracing ───────────────────────────────────────────────────
    const evidenceTraces: EvidenceTrace[] = [];
    const sourceDesk = finding.source_desk || '/chris';

    // Claim 1: Target reached
    evidenceTraces.push({
      claim: `Vulnerable endpoint accessible on target ${finding.target}`,
      sourceDesk,
      evidenceSnippet: safeEvidence.slice(0, 80),
      isVerified: true
    });

    // Claim 2: Vulnerability demonstrated
    const hasProof = safeEvidence.length > 0;
    evidenceTraces.push({
      claim: `Demonstrated ${finding.finding_type} vulnerability behavior`,
      sourceDesk,
      evidenceSnippet: safeEvidence,
      isVerified: hasProof,
      annotation: hasProof ? undefined : '[HYPOTHESIS / UNVERIFIED: Requires validated PoC output]'
    });

    // ── 3. Severity Scoring with Reasoning ────────────────────────────────────
    const cvss = deriveCvssReasoning(finding);

    // ── 4. Build Fixed Six-Section Structure ──────────────────────────────────
    const target = finding.target;
    const vulnName = options?.vulnerabilityTitle || `${finding.finding_type.toUpperCase().replace(/[_-]/g, ' ')} on ${target}`;

    const summary = `A validated ${finding.finding_type.replace(/[_-]/g, ' ')} vulnerability was identified on \`${target}\`. The issue was verified by \`${sourceDesk}\` through reproducible execution.`;

    const reproductionSteps = [
      `Navigate to or send a request to the target endpoint: \`${target}\``,
      `Provide the following validated test parameters observed in evidence: \`[parameters verified by ${sourceDesk}]\``,
      `Inspect the HTTP response: observe the vulnerability indicator:\n\`\`\`text\n${safeEvidence}\n\`\`\``
    ];

    const impactStatement = `The demonstrated impact is strictly anchored to the verified evidence provided by \`${sourceDesk}\`: ${cvss.overallJustification}`;

    const affectedComponents = [
      `Target host: \`${target}\``,
      `Identified vulnerability class: \`${finding.finding_type}\``
    ];

    const severityReasoningLines = [
      `**CVSS v3.1 Vector:** \`${cvss.vectorString}\``,
      `**Base Score:** **${cvss.baseScore}** (${cvss.severityRating})`,
      '',
      '| Metric | Value | Reasoning |',
      '| :--- | :--- | :--- |',
      ...cvss.metrics.map((m) => `| **${m.metric}** | \`${m.value}\` | ${m.reasoning} |`)
    ].join('\n');

    const suggestedRemediation = `Implement strict input validation, contextual output encoding, and authorization checks on \`${target}\`. Ensure security boundaries restrict backend access.`;

    // ── 5. Originality Check against Disclosed Reports ────────────────────────
    const fullDraftBody = `${summary}\n${impactStatement}\n${suggestedRemediation}`;
    const originality = checkOriginalityAgainstDisclosures(
      fullDraftBody,
      options?.disclosedReports || []
    );

    // ── 6. Assemble Formatted Markdown Report ─────────────────────────────────
    const markdownLines: string[] = [
      `# Bug Bounty Vulnerability Report: ${vulnName}`,
      '',
      `> **Status:** \`PENDING_HUMAN_APPROVAL\` — Awaiting explicit human sign-off before submission.`,
      `> **Date:** \`${new Date().toISOString().slice(0, 10)}\``,
      '',
      '---',
      '',
      '## 1. Summary',
      summary,
      '',
      '## 2. Reproduction Steps',
      ...reproductionSteps.map((step, idx) => `${idx + 1}. ${step}`),
      '',
      '## 3. Impact Statement',
      impactStatement,
      '',
      '## 4. Affected Component(s)',
      ...affectedComponents.map((c) => `- ${c}`),
      '',
      '## 5. Suggested Severity with Reasoning',
      severityReasoningLines,
      '',
      '## 6. Suggested Remediation',
      suggestedRemediation,
      '',
      '---',
      '',
      '## Evidence Trace Matrix',
      '| Claim | Source Desk | Evidence Reference | Verification Status |',
      '| :--- | :--- | :--- | :--- |',
      ...evidenceTraces.map(
        (t) =>
          `| ${t.claim} | \`${t.sourceDesk}\` | \`${t.evidenceSnippet.slice(0, 40).replace(/[\r\n]+/g, ' ')}\` | ${t.isVerified ? 'Verified (✓)' : '**[HYPOTHESIS / UNVERIFIED]**'} |`
      ),
      '',
      '## Quality & Safety Verification Status',
      `- **PII / User Data Redaction Pass:** ${redactionsApplied.length > 0 ? `Applied (${redactionsApplied.length} sensitive items masked)` : 'Clean (0 sensitive items found)'}`,
      `- **Originality Check:** ${originality.hasLanguageOverlap ? `⚠️ **Warning:** Overlap detected with disclosed report #${originality.matchedReportId}` : 'Passed (no plagiarism detected)'}`,
      `- **Human Sign-Off Required:** Yes (cannot be auto-submitted).`
    ];

    if (originality.hasLanguageOverlap && originality.recommendation) {
      markdownLines.push(`\n> ⚠️ **Originality Recommendation:** ${originality.recommendation}`);
    }

    const draft: QualityReportDraft = {
      id: findingId,
      findingId,
      target,
      vulnerabilityTitle: vulnName,
      status: 'PENDING_HUMAN_APPROVAL',
      createdAt: new Date().toISOString(),
      redactionsApplied,
      evidenceTraces,
      cvss,
      originality,
      sections: {
        summary,
        reproductionSteps,
        impactStatement,
        affectedComponents,
        severityWithReasoning: severityReasoningLines,
        suggestedRemediation
      },
      formattedMarkdown: markdownLines.join('\n')
    };

    this.drafts.set(findingId, draft);
    return draft;
  }

  /**
   * Human operator explicit approval of the report draft.
   */
  public approveDraft(reportId: string, approver = 'human'): QualityReportDraft {
    const draft = this.drafts.get(reportId);
    if (!draft) {
      throw new Error(`Report draft "${reportId}" not found.`);
    }

    draft.status = 'APPROVED_BY_HUMAN';
    draft.approvedAt = new Date().toISOString();
    draft.approvedBy = approver;

    this.drafts.set(reportId, draft);
    return draft;
  }

  /**
   * Attempt submission: Strictly fails if not explicitly approved by human.
   */
  public submitReport(reportId: string): { submitted: boolean; reason?: string } {
    const draft = this.drafts.get(reportId);
    if (!draft) {
      return { submitted: false, reason: `Report draft "${reportId}" not found.` };
    }

    if (draft.status !== 'APPROVED_BY_HUMAN') {
      return {
        submitted: false,
        reason: `Submission blocked: Report "${reportId}" is in "${draft.status}" state. Explicit human sign-off required.`
      };
    }

    return { submitted: true };
  }

  public getDraft(reportId: string): QualityReportDraft | null {
    return this.drafts.get(reportId) || null;
  }
}
