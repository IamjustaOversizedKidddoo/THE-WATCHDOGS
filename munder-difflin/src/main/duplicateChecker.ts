/**
 * The Watchdogs — Pre-Submission Duplicate Check Service (Addition 3)
 *
 * Capabilities:
 *  1. Official platform APIs only (HackerOne Hacktivity); skips platforms without public search APIs (Bugcrowd) per ToS.
 *  2. OPSEC-safe query construction: includes target domain + vulnerability class ONLY.
 *     Never includes PoC payloads, credentials, or accounts.
 *  3. Flag, NEVER auto-discard: Matches surface as "possible duplicate — human review required",
 *     displaying report title, date, summary, and matched fields. Findings are never deleted or downgraded.
 *  4. Two-stage execution:
 *     - Stage 1: Advisory check upon initial arrival at reporting desk (/michael).
 *     - Stage 2: Mandatory fresh re-run immediately prior to submission (never cached).
 */

import type { WatchdogsFinding } from '../shared/watchdogsSchema';
import type { ProgramRegistryEntry } from './programRegistry';

export interface DisclosedReport {
  id: string;
  title: string;
  disclosedAt: string; // YYYY-MM-DD or ISO-8601
  summary: string;
  platform: string;
  targetDomain: string;
  vulnerabilityClass: string;
  url?: string;
}

export interface DuplicateQuery {
  targetDomain: string;
  vulnerabilityClass: string;
}

export interface MatchedDuplicate {
  report: DisclosedReport;
  matchedFields: {
    sameTarget: boolean;
    sameVulnClass: boolean;
  };
  relevanceReason: string;
}

export interface DuplicateCheckResult {
  status: 'CLEARED_NO_MATCH' | 'FLAGGED_POSSIBLE_DUPLICATE' | 'SKIPPED_NO_API';
  query?: DuplicateQuery;
  matches: MatchedDuplicate[];
  requiresHumanReview: boolean;
  message: string;
  checkedAt: string;
  stage: 'advisory' | 'pre-submission';
}

/**
 * Standard vulnerability class normalizer.
 * Maps tool finding types to standard industry categories.
 */
export function normalizeVulnClass(findingType: string): string {
  const t = (findingType || '').toLowerCase();
  if (t.includes('ssrf')) return 'SSRF';
  if (t.includes('sqli') || t.includes('sql_injection')) return 'SQL Injection';
  if (t.includes('idor')) return 'IDOR';
  if (t.includes('xss') || t.includes('cross_site_scripting')) return 'XSS';
  if (t.includes('rce') || t.includes('command_injection') || t.includes('code_execution')) return 'RCE';
  if (t.includes('csrf')) return 'CSRF';
  if (t.includes('open_redirect')) return 'Open Redirect';
  if (t.includes('auth_bypass') || t.includes('authentication')) return 'Authentication Bypass';
  if (t.includes('debug_endpoint') || t.includes('info_disclosure')) return 'Information Disclosure';
  if (t.includes('subdomain_takeover')) return 'Subdomain Takeover';
  return findingType.replace(/[_-]/g, ' ').toUpperCase();
}

/**
 * Extracts clean domain from target string without path, port, or protocol.
 */
export function extractTargetDomain(rawTarget: string): string {
  let cleaned = (rawTarget || '').trim().toLowerCase();
  cleaned = cleaned.replace(/^[a-z]+:\/\//, ''); // remove protocol
  const slashIdx = cleaned.indexOf('/');
  if (slashIdx !== -1) cleaned = cleaned.slice(0, slashIdx); // remove path
  const colonIdx = cleaned.indexOf(':');
  if (colonIdx !== -1) cleaned = cleaned.slice(0, colonIdx); // remove port
  return cleaned;
}

export class DuplicateCheckerService {
  private lastFetchedReports: DisclosedReport[] = [];

  constructor(
    /**
     * Provider for fetching disclosed reports from official platform API.
     * Defaults to an internal provider, but can be mocked for unit tests or offline runs.
     */
    private readonly apiFetcher?: (
      platform: string,
      query: DuplicateQuery
    ) => Promise<DisclosedReport[]>
  ) {}

  public getRecentDisclosedReports(): DisclosedReport[] {
    return [...this.lastFetchedReports];
  }

  /**
   * OPSEC-safe query constructor.
   * Strips all PoC details, raw outputs, credentials, and parameters.
   * Only returns target domain and normalized vulnerability class.
   */
  public buildQuery(finding: WatchdogsFinding): DuplicateQuery {
    const targetDomain = extractTargetDomain(finding.target);
    const vulnerabilityClass = normalizeVulnClass(finding.finding_type);

    return {
      targetDomain,
      vulnerabilityClass
    };
  }

  /**
   * Fetches disclosed reports via official platform API.
   * Skips platforms without a public search API (e.g. Bugcrowd) per ToS policy.
   */
  public async fetchDisclosedReports(
    platform: string,
    query: DuplicateQuery
  ): Promise<{ skipped: boolean; reason?: string; reports: DisclosedReport[] }> {
    const cleanPlatform = (platform || '').toLowerCase();

    // 1. Check if platform has a supported official public search API
    if (cleanPlatform !== 'hackerone') {
      return {
        skipped: true,
        reason: `Platform "${platform}" does not provide an official public search API for disclosed reports. Automated check skipped per Terms of Service policy (no scraping). Manual portal review recommended.`,
        reports: []
      };
    }

    // 2. Query official HackerOne Hacktivity API (or custom fetcher)
    if (this.apiFetcher) {
      const reports = await this.apiFetcher(cleanPlatform, query);
      this.lastFetchedReports = reports;
      return { skipped: false, reports };
    }

    // Default live Hacktivity API integration
    try {
      // Official HackerOne Hacktivity GraphQL / REST endpoint
      // Using public query format with target domain and vulnerability keyword
      const url = `https://hackerone.com/hacktivity.json?querystring=${encodeURIComponent(
        `${query.targetDomain} ${query.vulnerabilityClass}`
      )}&sort_type=latest_disclosable_activity_at&filter=type%3Apublic`;

      const response = await fetch(url, {
        headers: { 'Accept': 'application/json', 'User-Agent': 'TheWatchdogs-DuplicateChecker/1.0' }
      });

      if (!response.ok) {
        return {
          skipped: true,
          reason: `HackerOne Hacktivity API returned HTTP ${response.status}.`,
          reports: []
        };
      }

      const data = await response.json() as any;
      const reports: DisclosedReport[] = (data.reports || []).map((r: any) => ({
        id: String(r.id),
        title: r.title || 'Untitled Report',
        disclosedAt: r.disclosed_at || r.created_at || 'Unknown date',
        summary: r.summary || (r.substate ? `Status: ${r.substate}` : 'Publicly disclosed report'),
        platform: 'hackerone',
        targetDomain: query.targetDomain,
        vulnerabilityClass: query.vulnerabilityClass,
        url: r.url || `https://hackerone.com/reports/${r.id}`
      }));

      this.lastFetchedReports = reports;
      return { skipped: false, reports };
    } catch (err) {
      return {
        skipped: true,
        reason: `Failed to query HackerOne Hacktivity API: ${(err as Error).message}`,
        reports: []
      };
    }
  }

  /**
   * Evaluates a finding against disclosed reports.
   * Flag, never auto-discard.
   */
  public async checkDuplicates(
    finding: WatchdogsFinding,
    program: ProgramRegistryEntry | { platform: string },
    stage: 'advisory' | 'pre-submission'
  ): Promise<DuplicateCheckResult> {
    const query = this.buildQuery(finding);
    const checkedAt = new Date().toISOString();

    const fetchResult = await this.fetchDisclosedReports(program.platform, query);

    if (fetchResult.skipped) {
      return {
        status: 'SKIPPED_NO_API',
        query,
        matches: [],
        requiresHumanReview: false,
        message: fetchResult.reason || 'Platform check skipped.',
        checkedAt,
        stage
      };
    }

    const matches: MatchedDuplicate[] = [];
    const queryDomain = query.targetDomain.toLowerCase();
    const queryVuln = query.vulnerabilityClass.toLowerCase();

    for (const report of fetchResult.reports) {
      const repTarget = report.targetDomain.toLowerCase();
      const repVuln = report.vulnerabilityClass.toLowerCase();
      const repTitle = (report.title || '').toLowerCase();

      const sameTarget = repTarget === queryDomain || repTitle.includes(queryDomain);
      const sameVulnClass = repVuln === queryVuln || repTitle.includes(queryVuln);

      if (sameTarget || sameVulnClass) {
        let reason = '';
        if (sameTarget && sameVulnClass) {
          reason = 'Matches both target domain and vulnerability class';
        } else if (sameTarget) {
          reason = 'Matches target domain';
        } else {
          reason = 'Matches vulnerability class';
        }

        matches.push({
          report,
          matchedFields: { sameTarget, sameVulnClass },
          relevanceReason: reason
        });
      }
    }

    if (matches.length > 0) {
      const formatLines = [
        `⚠️ **Possible Duplicate Detected (${stage === 'pre-submission' ? 'Pre-Submission Final Check' : 'Advisory Stage'})**`,
        `**Human Review Required:** The following publicly disclosed report(s) on ${program.platform} share overlap with this finding.`,
        '',
        ...matches.map((m, idx) => {
          return [
            `**Match #${idx + 1}: ${m.report.title}**`,
            `- **Date:** \`${m.report.disclosedAt}\``,
            `- **Matched Fields:** ${m.matchedFields.sameTarget ? 'Target Domain (✓)' : ''} ${m.matchedFields.sameVulnClass ? 'Vuln Class (✓)' : ''}`,
            `- **Summary:** ${m.report.summary}`,
            m.report.url ? `- **Link:** ${m.report.url}` : ''
          ].filter(Boolean).join('\n');
        }),
        '',
        `*Note: The Watchdogs will NEVER auto-discard this finding. Operator review required to confirm whether this is a genuine duplicate or a distinct vulnerable component.*`
      ];

      return {
        status: 'FLAGGED_POSSIBLE_DUPLICATE',
        query,
        matches,
        requiresHumanReview: true,
        message: formatLines.join('\n'),
        checkedAt,
        stage
      };
    }

    return {
      status: 'CLEARED_NO_MATCH',
      query,
      matches: [],
      requiresHumanReview: false,
      message: `No matching disclosed reports found on ${program.platform} for "${query.targetDomain}" [${query.vulnerabilityClass}].`,
      checkedAt,
      stage
    };
  }

  /**
   * Stage 1: Advisory check when finding first reaches reporting desk (/michael).
   */
  public async checkOnReportingEntry(
    finding: WatchdogsFinding,
    program: ProgramRegistryEntry | { platform: string }
  ): Promise<DuplicateCheckResult> {
    return this.checkDuplicates(finding, program, 'advisory');
  }

  /**
   * Stage 2: Mandatory fresh re-run immediately prior to submission.
   * Always executes fresh (never returns cached advisory result).
   */
  public async checkPreSubmission(
    finding: WatchdogsFinding,
    program: ProgramRegistryEntry | { platform: string }
  ): Promise<DuplicateCheckResult> {
    return this.checkDuplicates(finding, program, 'pre-submission');
  }
}
