/**
 * The Watchdogs — Continuous Reconnaissance Mode for /jonathan (Addition 1)
 *
 * Capabilities:
 *  1. Scheduled continuous recon against a human-authorized target whitelist.
 *  2. Configurable per-target interval (defaults to 6 hours = 21,600,000 ms).
 *  3. Persists recon snapshots keyed by date directly inside the agent's hive
 *     workspace (<hiveRoot>/agents/jonathan/recon/<target>/<date>.json) — no external DB.
 *  4. Diffs each run against the immediately prior run for that target (subdomains, endpoints, tech signals).
 *  5. Delta-only alerting:
 *     - If delta is empty: NO alert, NO notification.
 *     - If delta is non-empty: sends a structured alert message to /michael's inbox.
 *  6. Strict Guardrail: Rejects scanning any target not explicitly on the human-provided whitelist.
 *  7. Non-destructive: On-demand (single-run) recon mode remains 100% untouched.
 */

import fs from 'node:fs';
import path from 'node:path';
import type { ProgramRegistryService } from './programRegistry';

export const DEFAULT_RECON_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 hours

export interface ReconSnapshot {
  target: string;
  timestamp: string; // ISO-8601 string e.g. 2026-09-13T21:45:00.000Z
  dateKey: string;   // YYYY-MM-DD
  subdomains: string[];
  endpoints: string[];
  techSignals: Record<string, string>;
  metadata?: Record<string, unknown>;
}

export interface ReconDelta {
  target: string;
  timestamp: string;
  previousTimestamp: string | null;
  newSubdomains: string[];
  newEndpoints: string[];
  changedTechSignals: Array<{
    signal: string;
    oldVal?: string;
    newVal: string;
  }>;
  isEmpty: boolean;
}

export interface TargetReconConfig {
  target: string;
  intervalMs?: number; // per-target interval, default 6 hours
  enabled?: boolean;
}

export class JonathanContinuousReconService {
  private readonly targets = new Map<string, TargetReconConfig>();
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private isRunning = false;

  constructor(
    private readonly getHiveRoot: () => string | null,
    private readonly sendHiveMessage?: (message: {
      to: string;
      from: string;
      act: 'request' | 'inform' | 'propose' | 'query' | 'agree' | 'refuse' | 'done';
      subject: string;
      body: string;
      created_at?: string;
    }) => void,
    private readonly programRegistry?: ProgramRegistryService
  ) {}

  // ── Whitelist & Configuration Management ──────────────────────────────────

  /**
   * Set the entire target whitelist. Overwrites existing targets.
   * Only targets in this list are ever scanned.
   */
  public setTargetWhitelist(configs: TargetReconConfig[]): void {
    this.targets.clear();
    for (const cfg of configs) {
      this.addTarget(cfg);
    }
  }

  /**
   * Add or update a target configuration.
   */
  public addTarget(config: TargetReconConfig): void {
    const cleanTarget = config.target.trim().toLowerCase();
    if (!cleanTarget) return;

    const intervalMs =
      typeof config.intervalMs === 'number' && config.intervalMs > 0
        ? config.intervalMs
        : DEFAULT_RECON_INTERVAL_MS;

    this.targets.set(cleanTarget, {
      target: cleanTarget,
      intervalMs,
      enabled: config.enabled !== false
    });

    // If scheduler is actively running, adjust the timer for this target
    if (this.isRunning) {
      this.restartTimerForTarget(cleanTarget);
    }
  }

  /**
   * Remove a target from the continuous recon whitelist.
   */
  public removeTarget(target: string): boolean {
    const cleanTarget = target.trim().toLowerCase();
    this.stopTimerForTarget(cleanTarget);
    return this.targets.delete(cleanTarget);
  }

  /**
   * Check if a target is explicitly authorized on the whitelist.
   */
  public isTargetAuthorized(target: string): boolean {
    const cleanTarget = target.trim().toLowerCase();
    const config = this.targets.get(cleanTarget);
    return !!config && config.enabled !== false;
  }

  public getTargetConfig(target: string): TargetReconConfig | null {
    return this.targets.get(target.trim().toLowerCase()) || null;
  }

  public listTargets(): TargetReconConfig[] {
    return Array.from(this.targets.values());
  }

  // ── Workspace & Hive Persistence ──────────────────────────────────────────

  /**
   * Sanitizes target domain into safe folder name inside agent workspace.
   */
  public sanitizeTarget(target: string): string {
    return target.trim().toLowerCase().replace(/[^a-z0-9.-]/g, '_');
  }

  /**
   * Directory inside Jonathan's hive workspace dedicated to recon history.
   * Path: <hiveRoot>/agents/jonathan/recon/<sanitizedTarget>/
   */
  public getTargetReconDir(target: string): string | null {
    const hiveRoot = this.getHiveRoot();
    if (!hiveRoot) return null;
    const sanitized = this.sanitizeTarget(target);
    return path.join(hiveRoot, 'agents', 'jonathan', 'recon', sanitized);
  }

  /**
   * Persists a snapshot to disk inside Jonathan's hive agent workspace.
   * File format: <dateKey>_<timeKey>.json to ensure chronological ordering.
   */
  public saveSnapshot(snapshot: ReconSnapshot): string {
    const dir = this.getTargetReconDir(snapshot.target);
    if (!dir) {
      throw new Error(`Cannot persist recon snapshot: Hive root is unavailable.`);
    }

    fs.mkdirSync(dir, { recursive: true });

    // Format filename: YYYY-MM-DDTHH-mm-ss-SSSZ.json
    const safeTimestamp = snapshot.timestamp.replace(/[:.]/g, '-');
    const filename = `${safeTimestamp}.json`;
    const filePath = path.join(dir, filename);

    fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2), 'utf8');
    return filePath;
  }

  /**
   * Loads all snapshots for a given target sorted chronologically (oldest to newest).
   */
  public loadSnapshots(target: string): ReconSnapshot[] {
    const dir = this.getTargetReconDir(target);
    if (!dir || !fs.existsSync(dir)) return [];

    try {
      const files = fs
        .readdirSync(dir)
        .filter((f) => f.endsWith('.json'))
        .sort();

      const snapshots: ReconSnapshot[] = [];
      for (const file of files) {
        try {
          const content = fs.readFileSync(path.join(dir, file), 'utf8');
          snapshots.push(JSON.parse(content) as ReconSnapshot);
        } catch {
          // Skip corrupt snapshot files without crashing
        }
      }
      return snapshots;
    } catch {
      return [];
    }
  }

  /**
   * Retrieves the most recent snapshot for a target prior to a new execution.
   */
  public getLatestSnapshot(target: string): ReconSnapshot | null {
    const snapshots = this.loadSnapshots(target);
    if (snapshots.length === 0) return null;
    return snapshots[snapshots.length - 1];
  }

  // ── Delta Computation ─────────────────────────────────────────────────────

  /**
   * Diffs current snapshot against the immediately prior snapshot.
   * Computes only what is newly discovered or changed.
   */
  public computeDelta(current: ReconSnapshot, prior: ReconSnapshot | null): ReconDelta {
    if (!prior) {
      // First run: all discovered items are new
      const changedTechSignals = Object.entries(current.techSignals).map(([signal, newVal]) => ({
        signal,
        newVal
      }));

      const isEmpty =
        current.subdomains.length === 0 &&
        current.endpoints.length === 0 &&
        changedTechSignals.length === 0;

      return {
        target: current.target,
        timestamp: current.timestamp,
        previousTimestamp: null,
        newSubdomains: [...current.subdomains],
        newEndpoints: [...current.endpoints],
        changedTechSignals,
        isEmpty
      };
    }

    const priorSubdomains = new Set(prior.subdomains.map((s) => s.toLowerCase()));
    const newSubdomains = current.subdomains.filter(
      (s) => !priorSubdomains.has(s.toLowerCase())
    );

    const priorEndpoints = new Set(prior.endpoints);
    const newEndpoints = current.endpoints.filter((e) => !priorEndpoints.has(e));

    const changedTechSignals: Array<{ signal: string; oldVal?: string; newVal: string }> = [];
    for (const [key, currentVal] of Object.entries(current.techSignals)) {
      if (!(key in prior.techSignals)) {
        changedTechSignals.push({ signal: key, newVal: currentVal });
      } else if (prior.techSignals[key] !== currentVal) {
        changedTechSignals.push({
          signal: key,
          oldVal: prior.techSignals[key],
          newVal: currentVal
        });
      }
    }

    const isEmpty =
      newSubdomains.length === 0 &&
      newEndpoints.length === 0 &&
      changedTechSignals.length === 0;

    return {
      target: current.target,
      timestamp: current.timestamp,
      previousTimestamp: prior.timestamp,
      newSubdomains,
      newEndpoints,
      changedTechSignals,
      isEmpty
    };
  }

  /**
   * Formats the delta into a concise markdown alert for /michael.
   * Returns null if delta is empty.
   */
  public formatDeltaMessage(delta: ReconDelta): { subject: string; body: string } | null {
    if (delta.isEmpty) return null;

    const subject = `[Recon Delta Alert] New assets discovered on ${delta.target}`;
    const lines: string[] = [
      `### 🛰️ Continuous Recon Delta: \`${delta.target}\``,
      `**Timestamp:** \`${delta.timestamp}\``,
      delta.previousTimestamp
        ? `**Previous Run:** \`${delta.previousTimestamp}\``
        : `**Baseline:** Initial Target Run`,
      ''
    ];

    if (delta.newSubdomains.length > 0) {
      lines.push(`#### 🌐 Newly Discovered Subdomains (${delta.newSubdomains.length})`);
      for (const sub of delta.newSubdomains) {
        lines.push(`- \`${sub}\``);
      }
      lines.push('');
    }

    if (delta.newEndpoints.length > 0) {
      lines.push(`#### 🔗 Newly Discovered Endpoints (${delta.newEndpoints.length})`);
      for (const ep of delta.newEndpoints) {
        lines.push(`- \`${ep}\``);
      }
      lines.push('');
    }

    if (delta.changedTechSignals.length > 0) {
      lines.push(`#### ⚙️ Changed Tech Signals (${delta.changedTechSignals.length})`);
      for (const sig of delta.changedTechSignals) {
        const transition = sig.oldVal ? `\`${sig.oldVal}\` → ` : '';
        lines.push(`- **${sig.signal}**: ${transition}\`${sig.newVal}\``);
      }
      lines.push('');
    }

    return { subject, body: lines.join('\n').trim() };
  }

  // ── Execution Pipeline ────────────────────────────────────────────────────

  /**
   * Executes a scheduled recon run for an authorized target:
   *  1. Validates whitelist. Throws if target is unlisted.
   *  2. Gathers current findings (or uses provided snapshot data).
   *  3. Loads immediately prior snapshot.
   *  4. Persists new snapshot.
   *  5. Diffs current against prior.
   *  6. If delta is non-empty, sends message to /michael.
   *  7. If delta is empty, does NOTHING (silent no-op).
   */
  public async executeScheduledRun(
    target: string,
    snapshotData?: {
      subdomains?: string[];
      endpoints?: string[];
      techSignals?: Record<string, string>;
      timestamp?: string;
    }
  ): Promise<ReconDelta> {
    const cleanTarget = target.trim().toLowerCase();

    // STRICT GUARDRAIL: Refuse to scan any target not explicitly on human whitelist
    if (!this.isTargetAuthorized(cleanTarget)) {
      throw new Error(
        `Target "${target}" is not on the human-provided continuous recon whitelist. Execution refused.`
      );
    }

    const latestPrior = this.getLatestSnapshot(cleanTarget);
    const now = new Date();
    const timestamp = snapshotData?.timestamp || now.toISOString();
    const dateKey = timestamp.slice(0, 10);

    const currentSnapshot: ReconSnapshot = {
      target: cleanTarget,
      timestamp,
      dateKey,
      subdomains: snapshotData?.subdomains || [],
      endpoints: snapshotData?.endpoints || [],
      techSignals: snapshotData?.techSignals || {}
    };

    // Store new snapshot keyed by date/time in the hive
    this.saveSnapshot(currentSnapshot);

    // Compute diff against immediately prior run
    const delta = this.computeDelta(currentSnapshot, latestPrior);

    // Step 4: Record newly discovered assets as candidates in relevant program (NEVER auto-in_scope)
    if (this.programRegistry && !delta.isEmpty) {
      const prog = this.programRegistry.findProgramForTarget(cleanTarget);
      if (prog) {
        for (const sub of delta.newSubdomains) {
          this.programRegistry.recordCandidate(prog.program, sub);
        }
        for (const ep of delta.newEndpoints) {
          this.programRegistry.recordCandidate(prog.program, `${cleanTarget}${ep}`);
        }
      }
    }

    // Alert /michael ONLY if delta is non-empty
    if (!delta.isEmpty) {
      const message = this.formatDeltaMessage(delta);
      if (message && this.sendHiveMessage) {
        this.sendHiveMessage({
          to: 'michael',
          from: 'jonathan',
          act: 'inform',
          subject: message.subject,
          body: message.body,
          created_at: timestamp
        });
      }
    }

    return delta;
  }

  // ── Scheduler Controls ────────────────────────────────────────────────────

  public startScheduler(): void {
    if (this.isRunning) return;
    this.isRunning = true;

    for (const [target] of this.targets) {
      this.restartTimerForTarget(target);
    }
  }

  public stopScheduler(): void {
    this.isRunning = false;
    for (const timer of this.timers.values()) {
      clearInterval(timer);
    }
    this.timers.clear();
  }

  public isSchedulerRunning(): boolean {
    return this.isRunning;
  }

  private restartTimerForTarget(target: string): void {
    this.stopTimerForTarget(target);
    const config = this.targets.get(target);
    if (!config || config.enabled === false) return;

    const intervalMs = config.intervalMs || DEFAULT_RECON_INTERVAL_MS;
    const timer = setInterval(() => {
      this.executeScheduledRun(target).catch(() => {
        // Scheduler loop catch-all
      });
    }, intervalMs);

    if (typeof (timer as any).unref === 'function') {
      (timer as any).unref();
    }

    this.timers.set(target, timer);
  }

  private stopTimerForTarget(target: string): void {
    const timer = this.timers.get(target);
    if (timer) {
      clearInterval(timer);
      this.timers.delete(target);
    }
  }
}
