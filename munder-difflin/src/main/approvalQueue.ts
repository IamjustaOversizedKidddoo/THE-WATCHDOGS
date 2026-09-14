/**
 * The Watchdogs — Hardened Approval Queue (Phase 2.5)
 *
 * Sits OUTSIDE the hive as an external gate.
 * Any message marked `requires_approval: true` (exploitation-class actions,
 * active scanning, intrusive validation) pauses here and NEVER dispatches
 * to any desk until an explicit human operator approval is recorded.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { HiveMessage } from './hive';

export interface PendingApproval {
  id: string;
  queuedAt: string;
  message: HiveMessage;
  program_id?: string;
  formattedDisplay?: string;
}

export class ApprovalQueue {
  private readonly getHarnessHome: () => string | null;

  constructor(getHarnessHome: () => string | null) {
    this.getHarnessHome = getHarnessHome;
  }

  private dir(subdir: 'pending' | 'approved' | 'rejected'): string | null {
    const home = this.getHarnessHome();
    if (!home) return null;
    const p = join(home, 'hive', 'approvals', subdir);
    mkdirSync(p, { recursive: true });
    return p;
  }

  /**
   * Enqueue a message requiring human approval.
   * Atomic write to hive/approvals/pending/<id>.json
   * Formats program_id prominently at the top of the request.
   */
  enqueue(msg: HiveMessage): boolean {
    const pendingDir = this.dir('pending');
    if (!pendingDir) return false;

    const programId = msg.program_id || msg.finding?.program_id;
    const target = msg.finding?.target || (msg as any).target || 'Unknown Target';
    const action = msg.finding?.finding_type || 'exploitation_action';

    const formattedDisplay = [
      `==================================================`,
      `[PROGRAM: ${programId || 'UNKNOWN_PROGRAM'}]`,
      `==================================================`,
      `Target: ${target}`,
      `Action: ${action}`,
      `Desk: ${msg.from} -> ${msg.to}`,
      `Subject: ${msg.subject}`,
      `Details: ${msg.body}`
    ].join('\n');

    const file = join(pendingDir, `${msg.id}.json`);
    const record: PendingApproval = {
      id: msg.id,
      queuedAt: new Date().toISOString(),
      message: msg,
      program_id: programId,
      formattedDisplay
    };

    writeFileSync(file, JSON.stringify(record, null, 2), 'utf8');
    return true;
  }

  /**
   * List all currently pending approvals awaiting human decision.
   */
  listPending(): PendingApproval[] {
    const pendingDir = this.dir('pending');
    if (!pendingDir || !existsSync(pendingDir)) return [];

    const result: PendingApproval[] = [];
    for (const f of readdirSync(pendingDir)) {
      if (!f.endsWith('.json')) continue;
      try {
        const raw = readFileSync(join(pendingDir, f), 'utf8');
        result.push(JSON.parse(raw) as PendingApproval);
      } catch {
        // ignore malformed
      }
    }
    return result;
  }

  /**
   * Check if a specific message id is currently paused in the approval queue.
   */
  isPending(id: string): boolean {
    const pendingDir = this.dir('pending');
    if (!pendingDir) return false;
    return existsSync(join(pendingDir, `${id}.json`));
  }

  /**
   * Get a pending approval record without modifying or clearing it.
   */
  getPending(id: string): PendingApproval | null {
    const pendingDir = this.dir('pending');
    if (!pendingDir) return null;
    const pendingFile = join(pendingDir, `${id}.json`);
    if (!existsSync(pendingFile)) return null;
    try {
      const raw = readFileSync(pendingFile, 'utf8');
      return JSON.parse(raw) as PendingApproval;
    } catch {
      return null;
    }
  }

  /**
   * Human operator approves the action. Moves from pending to approved.
   * Returns the message for final dispatch to destination desk.
   */
  approve(id: string): HiveMessage | null {
    const pendingDir = this.dir('pending');
    const approvedDir = this.dir('approved');
    if (!pendingDir || !approvedDir) return null;

    const pendingFile = join(pendingDir, `${id}.json`);
    if (!existsSync(pendingFile)) return null;

    try {
      const raw = readFileSync(pendingFile, 'utf8');
      const record = JSON.parse(raw) as PendingApproval;
      renameSync(pendingFile, join(approvedDir, `${id}.json`));
      return record.message;
    } catch {
      return null;
    }
  }

  /**
   * Human operator rejects the action. Moves from pending to rejected.
   */
  reject(id: string, reason?: string): boolean {
    const pendingDir = this.dir('pending');
    const rejectedDir = this.dir('rejected');
    if (!pendingDir || !rejectedDir) return false;

    const pendingFile = join(pendingDir, `${id}.json`);
    if (!existsSync(pendingFile)) return false;

    try {
      const raw = readFileSync(pendingFile, 'utf8');
      const record = JSON.parse(raw) as PendingApproval;
      const rejectedRecord = { ...record, rejectedAt: new Date().toISOString(), reason };
      writeFileSync(join(rejectedDir, `${id}.json`), JSON.stringify(rejectedRecord, null, 2), 'utf8');
      renameSync(pendingFile, join(rejectedDir, `${id}.json`));
      return true;
    } catch {
      return false;
    }
  }
}
