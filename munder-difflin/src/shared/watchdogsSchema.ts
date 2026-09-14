/**
 * The Watchdogs — Extended Finding & Message Schema (Phase 2.1 – Addition 7)
 *
 * Provides typed data contracts for findings flowing through the pentest phases:
 *   Recon → Discovery → Exploitation → Reporting
 *
 * Addition 7: Adds the `transcript` evidence type for /rooster AI/chatbot testing,
 * and the `RoosterTestSession` interface for structured conversation-turn evidence.
 */

export type PentestPhase = 'recon' | 'discovery' | 'exploitation' | 'reporting';

export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical' | null;

export interface WatchdogsFinding {
  /** The authorized target this finding or action relates to */
  target: string;

  /** Current engagement lifecycle phase */
  phase: PentestPhase;

  /** Category of finding e.g. 'open_port', 'service_fingerprint', 'endpoint_discovered', 'candidate_cve', 'confirmed_vuln', 'poc_artifact' */
  finding_type: string;

  /** Triage severity: null until assessed or verified */
  severity: FindingSeverity;

  /** Evidence payload, raw tool output, or path to reproducible PoC artifact */
  evidence: string;

  /** Desk call sign that generated this finding: '/michael' | '/chris' | '/daniel' | '/jonathan' | '/david' | '/rooster' */
  source_desk: string;

  /**
   * Addition 7: For /rooster findings, the evidence type can be 'transcript'.
   * Transcript evidence must be PII/secret-redacted before storage.
   * `evidence` will contain the JSON-stringified, redacted RoosterTestSession.
   */
  evidence_type?: 'tool_output' | 'transcript' | 'poc_artifact' | 'raw_output';

  /** Mandatory security gate: MUST be true for any exploitation-class or active intrusive action */
  requires_approval: boolean;

  /** Addition 6: Program registry identifier matching active bounty program entry */
  program_id?: string;
}

// ─── Addition 7: Rooster Transcript Types ───────────────────────────────────

/** A single turn in a conversation with the AI/chatbot target. */
export interface RoosterTranscriptTurn {
  /** 'tester' = the probe sent by /rooster; 'target' = the AI's response */
  role: 'tester' | 'target';
  /** Redacted content — no real PII, secrets, or API keys must appear here */
  content: string;
  /** ISO timestamp of this turn */
  timestamp: string;
}

/**
 * A complete test session against an AI/chatbot target.
 * Must be PII/secret-redacted before being stored as `evidence` in a WatchdogsFinding.
 */
export interface RoosterTestSession {
  /** Unique session identifier */
  session_id: string;
  /** The target AI/chatbot endpoint or name */
  target: string;
  /** The program this test was conducted under */
  program_id: string;
  /** The technique class being tested (e.g. 'prompt_injection', 'jailbreak', 'data_exfiltration_probe') */
  technique: string;
  /** Whether a live tool-invocation was attempted in this session */
  live_tool_invocation_attempted: boolean;
  /** Whether live tool-invocation was explicitly authorized for this program */
  live_tool_invocation_authorized: boolean;
  /** Whether the test was run in non-destructive / observation-only mode */
  non_destructive_mode: boolean;
  /** The ordered conversation turns for this session */
  turns: RoosterTranscriptTurn[];
  /** ISO timestamp when the session started */
  started_at: string;
  /** ISO timestamp when the session ended */
  ended_at: string;
  /** Outcome of the test: 'success' = technique worked, 'fail' = target resisted, 'blocked_by_gate' = pre-execution gate stopped it */
  outcome: 'success' | 'fail' | 'blocked_by_gate' | 'blocked_not_authorized';
  /** Human-readable summary of findings — no raw user data, no real secrets */
  summary: string;
}

export interface WatchdogsHiveMessage {
  id: string;
  conversation: string;
  in_reply_to: string | null;
  from: string;
  to: string;
  act: string;
  subject: string;
  body: string;
  hops: number;
  requires_reply: boolean;
  needs_human: boolean;
  created_at: string;
  finding?: WatchdogsFinding;
  program_id?: string;
}

// ─── CLI Output Parsers for Phase 2.2 ───────────────────────────────────────

/** Parse Nmap stdout into structured Recon findings */
export function parseNmapOutput(stdout: string, target: string, sourceDesk = '/jonathan'): WatchdogsFinding[] {
  const findings: WatchdogsFinding[] = [];
  const lines = stdout.split(/\r?\n/);
  const portRegex = /^(\d+\/(?:tcp|udp))\s+(\w+)\s+(.+)$/;

  for (const line of lines) {
    const match = line.trim().match(portRegex);
    if (match) {
      const [, port, state, service] = match;
      findings.push({
        target,
        phase: 'recon',
        finding_type: 'open_port',
        severity: 'info',
        evidence: `Port: ${port}, State: ${state}, Service: ${service}`,
        source_desk: sourceDesk,
        requires_approval: false
      });
    }
  }

  if (findings.length === 0 && stdout.trim().length > 0) {
    findings.push({
      target,
      phase: 'recon',
      finding_type: 'raw_scan',
      severity: 'info',
      evidence: stdout.trim(),
      source_desk: sourceDesk,
      requires_approval: false
    });
  }

  return findings;
}

/** Parse Nuclei JSON / text output into structured Discovery findings */
export function parseNucleiOutput(stdout: string, target: string, sourceDesk = '/david'): WatchdogsFinding[] {
  const findings: WatchdogsFinding[] = [];
  const lines = stdout.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Try parsing as Nuclei JSON output
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const json = JSON.parse(trimmed);
        const severity = (json.info?.severity || 'info').toLowerCase() as FindingSeverity;
        findings.push({
          target: json.host || target,
          phase: 'discovery',
          finding_type: json['template-id'] || 'candidate_vuln',
          severity: ['info', 'low', 'medium', 'high', 'critical'].includes(severity || '') ? severity : 'low',
          evidence: `${json.info?.name || json['template-id']} - ${json.matched || json.host || target}`,
          source_desk: sourceDesk,
          requires_approval: severity === 'high' || severity === 'critical'
        });
        continue;
      } catch {
        // Fall back to line regex
      }
    }

    // Standard format: [template-id] [protocol] [severity] url
    const bracketMatch = trimmed.match(/^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)$/);
    if (bracketMatch) {
      const [, templateId, , sevStr, matched] = bracketMatch;
      const severity = sevStr.toLowerCase() as FindingSeverity;
      findings.push({
        target,
        phase: 'discovery',
        finding_type: templateId,
        severity: ['info', 'low', 'medium', 'high', 'critical'].includes(severity || '') ? severity : 'low',
        evidence: `${templateId} matched at ${matched}`,
        source_desk: sourceDesk,
        requires_approval: severity === 'high' || severity === 'critical'
      });
    }
  }

  return findings;
}

/** Parse Gobuster / Ffuf directory bruteforce stdout into Recon findings */
export function parseDirectoryScanOutput(stdout: string, target: string, sourceDesk = '/jonathan'): WatchdogsFinding[] {
  const findings: WatchdogsFinding[] = [];
  const lines = stdout.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Gobuster: /path (Status: 200) [Size: 1234]
    const gobusterMatch = trimmed.match(/^(\/[^\s]+)\s+\(Status:\s*(\d+)\)/i);
    if (gobusterMatch) {
      const [, endpoint, status] = gobusterMatch;
      findings.push({
        target,
        phase: 'recon',
        finding_type: 'endpoint_discovered',
        severity: 'info',
        evidence: `Endpoint: ${endpoint} returned HTTP ${status}`,
        source_desk: sourceDesk,
        requires_approval: false
      });
      continue;
    }

    // Ffuf table: endpoint [Status: 200, Size: 1234]
    const ffufMatch = trimmed.match(/^([^\s]+)\s+\[Status:\s*(\d+)/i);
    if (ffufMatch) {
      const [, endpoint, status] = ffufMatch;
      findings.push({
        target,
        phase: 'recon',
        finding_type: 'endpoint_discovered',
        severity: 'info',
        evidence: `Endpoint: ${endpoint} returned HTTP ${status}`,
        source_desk: sourceDesk,
        requires_approval: false
      });
    }
  }

  return findings;
}

/** Parse Sqlmap stdout into Discovery/Exploitation findings */
export function parseSqlmapOutput(stdout: string, target: string, sourceDesk = '/chris'): WatchdogsFinding[] {
  const findings: WatchdogsFinding[] = [];
  const lines = stdout.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.includes('is vulnerable') || trimmed.includes('Parameter:') || trimmed.includes('sqlmap identified')) {
      findings.push({
        target,
        phase: 'discovery',
        finding_type: 'sqli_candidate',
        severity: 'high',
        evidence: trimmed,
        source_desk: sourceDesk,
        // Active injection validation requires explicit operator approval
        requires_approval: true
      });
    }
  }

  return findings;
}
