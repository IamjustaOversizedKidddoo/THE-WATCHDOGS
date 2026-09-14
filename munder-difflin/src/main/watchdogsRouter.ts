/**
 * The Watchdogs — Pentest Routing State Machine & Callsign Parser (Phases 2.4 & 2.4b)
 *
 * Enforces the pentest phase transitions:
 *   Recon → Vulnerability Discovery → Exploitation → Reporting
 *
 * Rules:
 *  1. Recon findings (open ports, endpoints, fingerprints) forward to Discovery desks.
 *  2. Discovery findings with severity >= 'medium' forward to Validation desks.
 *     Lower severity findings are logged but not auto-escalated.
 *  3. Exploitation actions MUST have requires_approval: true and are blocked pending operator approval.
 *  4. Validated PoCs forward to Michael for reporting.
 *  5. Anti-skip: Recon CANNOT jump directly to Exploitation.
 *  6. Callsigns (/michael, /chris, /daniel, /jonathan, /david, /gabriel) direct-address desks.
 */

import type { WatchdogsFinding, WatchdogsHiveMessage } from '../shared/watchdogsSchema';

export const WATCHDOGS_CALLSIGNS: Record<string, string> = {
  '/michael': 'michael',
  '/chris': 'chris',
  '/daniel': 'daniel',
  '/jonathan': 'jonathan',
  '/david': 'david',
  '/gabriel': 'hexstrike',
  '/wrench': 'hexstrike',
  '/maverick': 'maverick',
  '/rooster': 'rooster'
};

export interface CallsignParseResult {
  callsign: string;
  targetDesk: string;
  cleanedText: string;
}

/**
 * Phase 2.4b: Direct addressing command parser.
 * Checks if a human message starts with /<callsign>.
 */
export function parseDirectCallsign(input: string): CallsignParseResult | null {
  const trimmed = input.trim();
  for (const [callsign, targetDesk] of Object.entries(WATCHDOGS_CALLSIGNS)) {
    if (trimmed === callsign || trimmed.startsWith(`${callsign} `)) {
      const cleanedText = trimmed.slice(callsign.length).trim();
      return { callsign, targetDesk, cleanedText };
    }
  }
  return null;
}

export interface RoutingDecision {
  nextDesk: string | null;
  phase: string;
  requiresApproval: boolean;
  blocked: boolean;
  reason?: string;
}

/**
 * Phase 2.4: Pentest state machine routing logic.
 */
export function routePentestFinding(
  finding: WatchdogsFinding,
  previousPhase?: string
): RoutingDecision {
  // Anti-skip rule: There is no path from recon directly to exploitation.
  if (finding.phase === 'exploitation' && previousPhase === 'recon') {
    return {
      nextDesk: null,
      phase: finding.phase,
      requiresApproval: true,
      blocked: true,
      reason: 'Anti-skip violation: Recon findings cannot jump directly to Exploitation without Vulnerability Discovery.'
    };
  }

  switch (finding.phase) {
    case 'recon':
      // Forward recon data to Discovery desk (Daniel / Shannon or David / HackBot)
      return {
        nextDesk: 'daniel',
        phase: 'recon',
        requiresApproval: false,
        blocked: false
      };

    case 'discovery': {
      const sev = finding.severity?.toLowerCase();
      const isHighOrMed = sev === 'medium' || sev === 'high' || sev === 'critical';
      if (isHighOrMed) {
        // Candidate finding with severity >= medium forwarded to validation desk (Chris / Strix)
        return {
          nextDesk: 'chris', // Chris / Strix: exploitation validation desk (proves real PoC)
          phase: 'discovery',
          requiresApproval: false,
          blocked: false
        };
      }
      // Low or informational findings are logged but not auto-escalated
      return {
        nextDesk: null,
        phase: 'discovery',
        requiresApproval: false,
        blocked: false,
        reason: `Severity ${sev ?? 'low'} does not meet escalation threshold (medium+).`
      };
    }

    case 'exploitation':
      // Exploitation actions MUST have approval and are paused before dispatch to validation desk (Chris / Strix)
      return {
        nextDesk: 'chris',
        phase: 'exploitation',
        requiresApproval: true,
        blocked: true,
        reason: 'Exploitation-class action requires operator approval in Phase 2.5 queue.'
      };

    case 'reporting':
      // Validated findings forward to Michael (GOD orchestrator) for final reporting
      return {
        nextDesk: 'michael',
        phase: 'reporting',
        requiresApproval: false,
        blocked: false
      };

    default:
      return {
        nextDesk: null,
        phase: finding.phase,
        requiresApproval: false,
        blocked: false
      };
  }
}
