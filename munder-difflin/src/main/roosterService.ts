/**
 * The Watchdogs — /rooster AI/Chatbot Testing Desk (Addition 7)
 *
 * Safety properties (all non-negotiable):
 *
 *  1. NON-DESTRUCTIVE DEFAULT
 *     By default every test runs in observation-only mode. The probe is sent
 *     and the response is recorded — but no action the AI's response describes
 *     is ever executed. This is the default even if the AI says "run this code"
 *     or "call this endpoint".
 *
 *  2. PER-PROGRAM LIVE-TOOL AUTHORIZATION (human-set, not agent-set)
 *     Live tool-invocation tests (tests that would actually execute a tool the
 *     AI asks for) require `live_tool_invocation_authorized: true` in the
 *     program's registry entry. This flag can ONLY be set by a human operator
 *     editing the JSON directly — /rooster never sets it.
 *
 *  3. PRE-EXECUTION APPROVAL GATE (stricter than every other desk)
 *     Other desks use a post-hoc gate: the message is enqueued, the human
 *     approves, then it dispatches. /rooster's live-tool tests use a
 *     PRE-EXECUTION gate: the test is queued in the approval system BEFORE
 *     any probe with tool-triggering potential is sent. The test only runs
 *     after explicit operator approval. Observation-only probes do NOT need
 *     pre-execution approval.
 *
 *  4. FULL SCOPE CHECK
 *     Every session must carry a `program_id` that is (a) found in the registry,
 *     (b) not stale, and (c) includes the chatbot target in its `in_scope` list.
 *
 *  5. PII / SECRET REDACTION
 *     All transcript turns are passed through the redaction filter before being
 *     stored as evidence. Real API keys, passwords, email addresses, phone numbers,
 *     and IPv4 addresses are replaced with placeholders.
 */

import { randomBytes } from 'node:crypto';
import type { WatchdogsFinding, RoosterTestSession, RoosterTranscriptTurn } from '../shared/watchdogsSchema';
import type { ProgramRegistryService, ProgramRegistryEntry } from './programRegistry';
import type { ApprovalQueue } from './approvalQueue';

// ─── Redaction ───────────────────────────────────────────────────────────────

/** Patterns that must be stripped from any transcript turn content before storage. */
const REDACTION_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
  // API keys / tokens: long hex/base64 strings after common key prefixes
  { pattern: /\b(sk-|Bearer\s+|api[_-]?key[=:\s]+|token[=:\s]+)[A-Za-z0-9\-_./+]{16,}/gi, replacement: '[REDACTED_API_KEY]' },
  // Generic long secrets / hex strings (≥32 chars with mixed case/digits)
  { pattern: /\b[A-Za-z0-9]{32,}\b/g, replacement: '[REDACTED_SECRET]' },
  // Email addresses
  { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, replacement: '[REDACTED_EMAIL]' },
  // IPv4 addresses (non-localhost)
  { pattern: /\b(?!127\.0\.0\.1)(?!0\.0\.0\.0)(\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[REDACTED_IP]' },
  // Phone numbers (international and US formats)
  { pattern: /(?:\+\d{1,3}[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}/g, replacement: '[REDACTED_PHONE]' },
  // Passwords in common patterns
  { pattern: /\b(password|passwd|pwd|secret)[=:\s]+\S+/gi, replacement: '[REDACTED_PASSWORD]' },
];

/**
 * Redacts PII and secrets from a single string.
 * Must be applied to every transcript turn content before storage.
 */
export function redactTranscriptContent(raw: string): string {
  let result = raw;
  for (const { pattern, replacement } of REDACTION_PATTERNS) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

/**
 * Applies PII/secret redaction to all turns of a RoosterTestSession.
 * Returns a new session object; does not mutate the original.
 */
export function redactSession(session: RoosterTestSession): RoosterTestSession {
  return {
    ...session,
    summary: redactTranscriptContent(session.summary),
    turns: session.turns.map((turn) => ({
      ...turn,
      content: redactTranscriptContent(turn.content),
    })),
  };
}

// ─── Pre-execution Approval Queue ────────────────────────────────────────────

/**
 * A pending pre-execution approval request for a live tool-invocation test.
 * Stored in hive/approvals/rooster-pending/ and consumed by the pre-execution gate.
 */
export interface RoosterPendingApproval {
  /** Unique approval request ID */
  approval_id: string;
  /** The program this test belongs to */
  program_id: string;
  /** The AI/chatbot target endpoint or name */
  target: string;
  /** The technique being tested */
  technique: string;
  /** The specific probe that would be sent */
  proposed_probe: string;
  /** Why this requires pre-execution approval */
  reason: string;
  /** ISO timestamp when this request was queued */
  queued_at: string;
  /** Approval status */
  status: 'pending' | 'approved' | 'rejected';
  /** ISO timestamp when the decision was made */
  decided_at?: string;
}

// ─── Rooster Session Options ──────────────────────────────────────────────────

export interface RoosterSessionOptions {
  /** The program this session belongs to */
  program_id: string;
  /** The AI/chatbot target endpoint or name (must be in program's in_scope) */
  target: string;
  /** The technique class to test */
  technique: string;
  /** Whether this test may trigger a live tool invocation */
  involves_live_tool_invocation: boolean;
  /** The probe content to send to the target */
  probe: string;
  /** The simulated response from the AI (for tests that do not actually call a live endpoint) */
  simulated_response?: string;
}

// ─── Gate Result ─────────────────────────────────────────────────────────────

export interface RoosterGateResult {
  allowed: boolean;
  code:
    | 'OK'
    | 'NOT_AUTHORIZED_LIVE_TOOL'
    | 'NEEDS_PRE_EXECUTION_APPROVAL'
    | 'OUT_OF_SCOPE'
    | 'STALE_SCOPE'
    | 'MISSING_PROGRAM_ID'
    | 'PROGRAM_NOT_FOUND';
  reason: string;
}

// ─── Rooster Session Result ───────────────────────────────────────────────────

export interface RoosterSessionResult {
  gate: RoosterGateResult;
  session?: RoosterTestSession;
  finding?: WatchdogsFinding;
  pendingApprovalId?: string;
}

// ─── RoosterService ───────────────────────────────────────────────────────────

/**
 * /rooster AI/Chatbot Testing Desk (Addition 7).
 *
 * Manages non-destructive AI/chatbot security testing with:
 * - Per-program live-tool-invocation authorization gate (human-set flag only)
 * - PRE-execution approval for any test that would trigger a live tool
 * - Full scope verification via ProgramRegistryService
 * - PII/secret redaction on all transcript evidence
 */
export class RoosterService {
  private readonly programRegistry: ProgramRegistryService;
  private readonly approvalQueue: ApprovalQueue;

  /** In-memory store of pending pre-execution approvals (keyed by approval_id).
   * In production these would be persisted to disk; for the test harness, memory is sufficient. */
  private pendingApprovals: Map<string, RoosterPendingApproval> = new Map();

  constructor(programRegistry: ProgramRegistryService, approvalQueue: ApprovalQueue) {
    this.programRegistry = programRegistry;
    this.approvalQueue = approvalQueue;
  }

  // ── Private Helpers ────────────────────────────────────────────────────────

  private generateId(prefix: string): string {
    return `${prefix}-${randomBytes(6).toString('hex')}`;
  }

  /**
   * Validates program_id, scope, and staleness for a given target.
   * Returns the resolved program entry on success or a failing GateResult on failure.
   */
  private verifyScopeGate(
    program_id: string,
    target: string
  ): { ok: true; program: ProgramRegistryEntry } | { ok: false; gate: RoosterGateResult } {
    if (!program_id || program_id.trim().length === 0) {
      return {
        ok: false,
        gate: {
          allowed: false,
          code: 'MISSING_PROGRAM_ID',
          reason: 'Rooster session rejected: program_id is required and must not be empty. Every /rooster test must be tagged to a registered bounty program.',
        },
      };
    }

    const verification = this.programRegistry.verifyTargetForAction(target, new Date(), undefined, program_id);
    if (!verification.allowed) {
      const code: RoosterGateResult['code'] =
        verification.code === 'NOT_FOUND' ? 'PROGRAM_NOT_FOUND' :
        verification.code === 'STALE_VERIFICATION' ? 'STALE_SCOPE' :
        'OUT_OF_SCOPE';

      return {
        ok: false,
        gate: {
          allowed: false,
          code,
          reason: verification.reason,
        },
      };
    }

    const program = this.programRegistry.getProgram(program_id)!;
    return { ok: true, program };
  }

  // ── Pre-Execution Approval Methods ─────────────────────────────────────────

  /**
   * Queues a pre-execution approval request for a live tool-invocation test.
   * Returns the approval_id that the operator must approve before the test may run.
   */
  queuePreExecutionApproval(
    program_id: string,
    target: string,
    technique: string,
    proposedProbe: string
  ): string {
    const approvalId = this.generateId('rooster-preexec');
    const record: RoosterPendingApproval = {
      approval_id: approvalId,
      program_id,
      target,
      technique,
      proposed_probe: proposedProbe,
      reason: `/rooster live tool-invocation test requires pre-execution approval. Program: ${program_id}. Target: ${target}. Technique: ${technique}.`,
      queued_at: new Date().toISOString(),
      status: 'pending',
    };
    this.pendingApprovals.set(approvalId, record);
    return approvalId;
  }

  /**
   * Returns a pending pre-execution approval record by ID, or null if not found.
   */
  getPendingApproval(approvalId: string): RoosterPendingApproval | null {
    return this.pendingApprovals.get(approvalId) ?? null;
  }

  /**
   * Lists all currently pending pre-execution approval requests.
   */
  listPendingApprovals(): RoosterPendingApproval[] {
    return Array.from(this.pendingApprovals.values()).filter((r) => r.status === 'pending');
  }

  /**
   * Human operator approves a queued pre-execution test.
   * Returns true if the approval_id was found and in pending state.
   */
  approvePreExecution(approvalId: string): boolean {
    const record = this.pendingApprovals.get(approvalId);
    if (!record || record.status !== 'pending') return false;
    record.status = 'approved';
    record.decided_at = new Date().toISOString();
    return true;
  }

  /**
   * Human operator rejects a queued pre-execution test.
   * Returns true if the approval_id was found and in pending state.
   */
  rejectPreExecution(approvalId: string, reason?: string): boolean {
    const record = this.pendingApprovals.get(approvalId);
    if (!record || record.status !== 'pending') return false;
    record.status = 'rejected';
    record.decided_at = new Date().toISOString();
    if (reason) record.reason = reason;
    return true;
  }

  // ── Primary Session Runner ─────────────────────────────────────────────────

  /**
   * Runs a /rooster AI/chatbot test session.
   *
   * Implements the full gate hierarchy:
   *  1. Scope gate: program_id must resolve, target must be in-scope, scope must not be stale.
   *  2. Live tool authorization: live-tool-invocation tests require `live_tool_invocation_authorized: true`
   *     in the program's registry entry. If not set, the session runs in non-destructive mode only.
   *  3. Pre-execution gate: if this is a live tool-invocation test AND authorized, it must have a
   *     pre-existing APPROVED pre-execution approval record. If not, it is queued and blocked.
   *  4. Non-destructive mode: observation-only probes (no live tool invocation) do NOT need
   *     pre-execution approval and run immediately.
   *  5. Redaction: ALL transcript turns are PII/secret-redacted before being included in the finding.
   */
  runSession(options: RoosterSessionOptions): RoosterSessionResult {
    const { program_id, target, technique, involves_live_tool_invocation, probe, simulated_response } = options;

    // ── Gate 1: Scope verification ──────────────────────────────────────────
    const scopeResult = this.verifyScopeGate(program_id, target);
    if (!scopeResult.ok) {
      return { gate: scopeResult.gate };
    }
    const program = scopeResult.program;

    // ── Gate 2: Live tool invocation authorization check ────────────────────
    // If this test involves a live tool invocation AND the program does NOT
    // have explicit human authorization, downgrade to non-destructive mode.
    const isLiveAuthorized = program.live_tool_invocation_authorized === true;

    if (involves_live_tool_invocation && !isLiveAuthorized) {
      // Not authorized for live tool invocation — return a blocked result.
      // The test is NOT run, not even as observation-only. The operator must
      // explicitly enable `live_tool_invocation_authorized` for this program.
      return {
        gate: {
          allowed: false,
          code: 'NOT_AUTHORIZED_LIVE_TOOL',
          reason: `/rooster live tool-invocation test blocked: program "${program_id}" does not have live_tool_invocation_authorized=true. ` +
            `A human operator must set this flag in config/program-registry/${program_id}.json before live-tool tests can proceed.`,
        },
      };
    }

    // ── Gate 3: Pre-execution approval for live tool-invocation tests ───────
    // Even if the program has live_tool_invocation_authorized=true, the specific
    // test instance must have an APPROVED pre-execution record.
    if (involves_live_tool_invocation && isLiveAuthorized) {
      // Find an approved pre-execution record for this program+target+technique
      const approvedRecord = Array.from(this.pendingApprovals.values()).find(
        (r) =>
          r.status === 'approved' &&
          r.program_id === program_id &&
          r.target === target &&
          r.technique === technique
      );

      if (!approvedRecord) {
        // Queue a pre-execution approval request and block.
        const approvalId = this.queuePreExecutionApproval(program_id, target, technique, probe);
        return {
          gate: {
            allowed: false,
            code: 'NEEDS_PRE_EXECUTION_APPROVAL',
            reason: `/rooster live tool-invocation test blocked pending pre-execution approval (id: ${approvalId}). ` +
              `Program: ${program_id}. Target: ${target}. Technique: ${technique}. ` +
              `Operator must call roosterService.approvePreExecution("${approvalId}") before this test may run.`,
          },
          pendingApprovalId: approvalId,
        };
      }
    }

    // ── All gates passed — run the session ──────────────────────────────────

    const sessionId = this.generateId('session');
    const now = new Date().toISOString();

    // Build transcript turns with redaction applied immediately
    const turns: RoosterTranscriptTurn[] = [];

    turns.push({
      role: 'tester',
      content: redactTranscriptContent(probe),
      timestamp: now,
    });

    if (simulated_response) {
      turns.push({
        role: 'target',
        content: redactTranscriptContent(simulated_response),
        timestamp: new Date().toISOString(),
      });
    }

    // Determine outcome
    const nonDestructiveMode = !involves_live_tool_invocation;
    const outcome: RoosterTestSession['outcome'] = involves_live_tool_invocation
      ? (simulated_response ? 'success' : 'fail')
      : 'success';

    const rawSession: RoosterTestSession = {
      session_id: sessionId,
      target,
      program_id,
      technique,
      live_tool_invocation_attempted: involves_live_tool_invocation,
      live_tool_invocation_authorized: isLiveAuthorized,
      non_destructive_mode: nonDestructiveMode,
      turns,
      started_at: now,
      ended_at: new Date().toISOString(),
      outcome,
      summary: `Rooster test session for ${technique} against ${target} under program ${program_id}. Outcome: ${outcome}.`,
    };

    // Apply full redaction to the completed session before storing as evidence
    const redactedSession = redactSession(rawSession);

    const finding: WatchdogsFinding = {
      target,
      phase: 'discovery',
      finding_type: `rooster_${technique}`,
      severity: involves_live_tool_invocation ? 'high' : 'medium',
      evidence: JSON.stringify(redactedSession, null, 2),
      evidence_type: 'transcript',
      source_desk: '/rooster',
      requires_approval: involves_live_tool_invocation,
      program_id,
    };

    return {
      gate: { allowed: true, code: 'OK', reason: `Session authorized under program "${program_id}".` },
      session: redactedSession,
      finding,
    };
  }
}
