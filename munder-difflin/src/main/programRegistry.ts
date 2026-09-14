/**
 * The Watchdogs — Program Registry & Scope Source of Truth (Addition 2)
 *
 * Enforces:
 *  1. One entry per bounty program under config/program-registry/<program-name>.json.
 *  2. Human-write-only fields: in_scope, excluded, verified_by ("human"), last_verified.
 *  3. Exact-match & domain-suffix scope checking (blocks example.com.attacker.net).
 *  4. Exclusions always win on conflict over in_scope matches.
 *  5. Recon findings recorded strictly to `candidates: []`, never auto-merged into in_scope.
 *  6. 7-day staleness check gates Phase 2.5 approval of exploitation-class actions.
 *  7. Program registry lookup required for all scope decisions (no memory assumptions).
 */

import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_STALENESS_DAYS = 7;

export interface ProgramRegistryEntry {
  program: string;
  platform: string;
  in_scope: string[];
  excluded: string[];
  testing_restrictions?: string;
  last_verified: string; // YYYY-MM-DD
  verified_by: 'human';
  candidates?: string[];
  /**
   * Addition 7: /rooster pre-execution gate.
   * Must be set to `true` (by a human operator) before /rooster may attempt any
   * live tool-invocation test against an AI/chatbot target in this program.
   * When absent or false, /rooster runs in non-destructive / observation-only mode.
   */
  live_tool_invocation_authorized?: boolean;
}

export interface ScopeCheckResult {
  inScope: boolean;
  reason: string;
  matchedInScopePattern?: string;
  matchedExcludedPattern?: string;
}

export interface GateVerificationResult {
  allowed: boolean;
  code: 'OK' | 'NOT_FOUND' | 'OUT_OF_SCOPE' | 'EXCLUDED' | 'STALE_VERIFICATION';
  reason: string;
  program?: ProgramRegistryEntry;
}

/**
 * Normalizes and parses a target or pattern into { host, port, path }.
 */
export function parseTargetParts(raw: string): { host: string; port: string | null; path: string } {
  let cleaned = raw.trim().toLowerCase();
  // Remove protocol
  cleaned = cleaned.replace(/^[a-z]+:\/\//, '');

  let pathname = '';
  const slashIdx = cleaned.indexOf('/');
  if (slashIdx !== -1) {
    pathname = cleaned.slice(slashIdx);
    cleaned = cleaned.slice(0, slashIdx);
  }

  let port: string | null = null;
  const colonIdx = cleaned.lastIndexOf(':');
  if (colonIdx !== -1) {
    port = cleaned.slice(colonIdx + 1);
    cleaned = cleaned.slice(0, colonIdx);
  }

  return { host: cleaned, port, path: pathname };
}

/**
 * Strict exact or domain-suffix pattern matching.
 *
 * Rules:
 *  - Pattern "example.com" ONLY matches exact host "example.com"
 *  - Pattern "*.example.com" matches genuine subdomains (ends with ".example.com") or apex "example.com"
 *  - STRICTLY FAILS "example.com.attacker.net" or "fakeexample.com"
 */
export function matchDomainPattern(target: string, pattern: string): boolean {
  const t = parseTargetParts(target);
  const p = parseTargetParts(pattern);

  // 1. Host match
  let hostMatches = false;
  if (p.host.startsWith('*.')) {
    const suffix = p.host.slice(2); // e.g. "example.com"
    if (t.host === suffix || t.host.endsWith('.' + suffix)) {
      hostMatches = true;
    }
  } else if (p.host === '*') {
    hostMatches = true;
  } else {
    hostMatches = t.host === p.host;
  }

  if (!hostMatches) {
    return false;
  }

  // 2. Port match (if specified in pattern)
  if (p.port && p.port !== '*') {
    if (t.port !== p.port) {
      return false;
    }
  }

  // 3. Path match (if specified in pattern)
  if (p.path) {
    const patternPath = p.path;
    const targetPath = t.path || '/';

    if (patternPath === '/*' || patternPath === '*') {
      return true;
    }

    if (patternPath.endsWith('/*')) {
      const prefix = patternPath.slice(0, -2);
      return targetPath === prefix || targetPath.startsWith(prefix + '/');
    }

    if (patternPath.endsWith('*')) {
      const prefix = patternPath.slice(0, -1);
      return targetPath.startsWith(prefix);
    }

    return targetPath === patternPath;
  }

  return true;
}

export class ProgramRegistryService {
  private readonly registryDir: string;

  constructor(customRegistryDir?: string) {
    this.registryDir =
      customRegistryDir ||
      path.join(__dirname, '..', '..', 'config', 'program-registry');
  }

  public getRegistryDir(): string {
    return this.registryDir;
  }

  /**
   * Load a program entry by name (e.g. "example-corp").
   */
  public getProgram(programName: string): ProgramRegistryEntry | null {
    const clean = programName.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    const filePath = path.join(this.registryDir, `${clean}.json`);
    if (!fs.existsSync(filePath)) return null;

    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(raw) as ProgramRegistryEntry;
      if (!Array.isArray(data.candidates)) {
        data.candidates = [];
      }
      return data;
    } catch {
      return null;
    }
  }

  /**
   * List all registered programs.
   */
  public listPrograms(): ProgramRegistryEntry[] {
    if (!fs.existsSync(this.registryDir)) return [];
    try {
      const files = fs.readdirSync(this.registryDir).filter((f) => f.endsWith('.json'));
      const entries: ProgramRegistryEntry[] = [];
      for (const f of files) {
        try {
          const raw = fs.readFileSync(path.join(this.registryDir, f), 'utf8');
          const data = JSON.parse(raw) as ProgramRegistryEntry;
          if (!Array.isArray(data.candidates)) {
            data.candidates = [];
          }
          entries.push(data);
        } catch {
          // ignore malformed
        }
      }
      return entries;
    } catch {
      return [];
    }
  }

  /**
   * Human-write-only program entry save.
   * Modifying in_scope, excluded, verified_by, or last_verified is REJECTED if called by an agent.
   */
  public saveProgram(entry: ProgramRegistryEntry, modifiedBy: 'human' | 'agent' = 'human'): void {
    if (modifiedBy !== 'human') {
      throw new Error(
        `Security Guardrail Violation: Program registry entries can only be created or modified by "human". Automated agent modifications to scope fields are strictly prohibited.`
      );
    }

    if (entry.verified_by !== 'human') {
      throw new Error(`Security Guardrail: verified_by must strictly read "human".`);
    }

    fs.mkdirSync(this.registryDir, { recursive: true });
    const clean = entry.program.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    const filePath = path.join(this.registryDir, `${clean}.json`);

    fs.writeFileSync(filePath, JSON.stringify(entry, null, 2), 'utf8');
  }

  /**
   * Checks whether a target is in scope according to a program's rules.
   * EXCLUSIONS ALWAYS WIN ON CONFLICT.
   */
  public checkScope(target: string, program: ProgramRegistryEntry): ScopeCheckResult {
    // 1. Check exclusions first
    for (const pattern of program.excluded || []) {
      if (matchDomainPattern(target, pattern)) {
        return {
          inScope: false,
          reason: `Target matches excluded pattern "${pattern}" in program "${program.program}".`,
          matchedExcludedPattern: pattern
        };
      }
    }

    // 2. Check inclusions
    for (const pattern of program.in_scope || []) {
      if (matchDomainPattern(target, pattern)) {
        return {
          inScope: true,
          reason: `Target matches in_scope pattern "${pattern}" in program "${program.program}".`,
          matchedInScopePattern: pattern
        };
      }
    }

    return {
      inScope: false,
      reason: `Target "${target}" does not match any in_scope pattern in program "${program.program}".`
    };
  }

  /**
   * Finds the registered program that covers the given target (either in_scope or excluded).
   */
  public findProgramForTarget(target: string): ProgramRegistryEntry | null {
    const all = this.listPrograms();
    for (const prog of all) {
      const result = this.checkScope(target, prog);
      // If it matched an in_scope pattern or an excluded pattern, this program covers it
      if (result.matchedInScopePattern || result.matchedExcludedPattern) {
        return prog;
      }
    }
    return null;
  }

  /**
   * Staleness check: returns true if last_verified is older than maxDays (default 7).
   */
  public isStale(entry: ProgramRegistryEntry, maxDays = DEFAULT_STALENESS_DAYS, referenceDate = new Date()): boolean {
    if (!entry.last_verified) return true;
    const verifiedTime = new Date(entry.last_verified).getTime();
    if (isNaN(verifiedTime)) return true;

    const diffMs = referenceDate.getTime() - verifiedTime;
    const diffDays = diffMs / (1000 * 60 * 60 * 24);
    return diffDays > maxDays;
  }

  /**
   * Verification check for the Phase 2.5 Approval Gate.
   * Gates any exploitation-class action:
   *  - Must find program in registry
   *  - Target must be in-scope (and not excluded)
   *  - Scope must not be stale (> 7 days)
   */
  public verifyTargetForAction(
    target: string,
    currentDate = new Date(),
    maxStalenessDays = DEFAULT_STALENESS_DAYS,
    programId?: string
  ): GateVerificationResult {
    const cleanTarget = target.trim();

    let program: ProgramRegistryEntry | null = null;
    if (programId) {
      program = this.getProgram(programId);
      if (!program) {
        return {
          allowed: false,
          code: 'NOT_FOUND',
          reason: `Program "${programId}" not found in config/program-registry/. Scope cannot be assumed; operator must add the program to the registry first.`
        };
      }
    } else {
      program = this.findProgramForTarget(cleanTarget);
      if (!program) {
        return {
          allowed: false,
          code: 'NOT_FOUND',
          reason: `Target "${cleanTarget}" does not match any program in config/program-registry/. Scope cannot be assumed; operator must add the program to the registry first.`
        };
      }
    }

    // 2. Scope & Exclusion check
    const scopeCheck = this.checkScope(cleanTarget, program);
    if (!scopeCheck.inScope) {
      return {
        allowed: false,
        code: scopeCheck.matchedExcludedPattern ? 'EXCLUDED' : 'OUT_OF_SCOPE',
        reason: programId
          ? `Cross-Program Scope Violation: Target "${cleanTarget}" is not in scope for specified program "${program.program}". Action blocked to prevent cross-program scope confusion.`
          : scopeCheck.reason,
        program
      };
    }

    // 3. Staleness check
    if (this.isStale(program, maxStalenessDays, currentDate)) {
      return {
        allowed: false,
        code: 'STALE_VERIFICATION',
        reason: `Scope for program "${program.program}" is stale (last verified: ${program.last_verified}, >${maxStalenessDays} days ago). Operator re-confirmation against policy page required before approval.`,
        program
      };
    }

    return {
      allowed: true,
      code: 'OK',
      reason: `Target "${cleanTarget}" is authorized in program "${program.program}".`,
      program
    };
  }

  /**
   * Addition 6: Evaluates per-program testing restrictions at scheduling time.
   * Evaluates time windows and method restrictions per-task.
   */
  public evaluateTestingRestrictions(
    program: ProgramRegistryEntry,
    task: { action?: string; method?: string; finding_type?: string },
    currentDate = new Date()
  ): { allowed: boolean; reason?: string } {
    return evaluateTestingRestrictions(program, task, currentDate);
  }

  /**
   * Automated recon finding candidate recorder (Step 4).
   * Appends candidate asset strictly to `candidates: []`.
   * NEVER merges into in_scope.
   */
  public recordCandidate(programName: string, asset: string): boolean {
    const cleanAsset = asset.trim().toLowerCase();
    const program = this.getProgram(programName);
    if (!program) return false;

    if (!Array.isArray(program.candidates)) {
      program.candidates = [];
    }

    // Don't duplicate
    if (program.candidates.includes(cleanAsset) || program.in_scope.includes(cleanAsset)) {
      return false;
    }

    program.candidates.push(cleanAsset);

    // Atomic write to registry file preserving human-only fields
    const filePath = path.join(this.registryDir, `${program.program}.json`);
    fs.writeFileSync(filePath, JSON.stringify(program, null, 2), 'utf8');
    return true;
  }

  /**
   * Human promotion of a candidate to in_scope.
   */
  public promoteCandidate(
    programName: string,
    candidate: string,
    promotedBy: 'human' = 'human'
  ): boolean {
    if (promotedBy !== 'human') {
      throw new Error(`Only a human operator can promote candidates to in_scope.`);
    }

    const cleanCandidate = candidate.trim().toLowerCase();
    const program = this.getProgram(programName);
    if (!program) return false;

    if (!Array.isArray(program.candidates)) {
      program.candidates = [];
    }

    // Remove from candidates
    program.candidates = program.candidates.filter((c) => c !== cleanCandidate);

    // Add to in_scope if not present
    if (!program.in_scope.includes(cleanCandidate)) {
      program.in_scope.push(cleanCandidate);
    }

    // Save with human authority
    this.saveProgram(program, 'human');
    return true;
  }

  /**
   * Explicit human re-confirmation of scope (refreshes last_verified).
   */
  public reconfirmScope(programName: string, confirmedDate = new Date().toISOString().slice(0, 10)): boolean {
    const program = this.getProgram(programName);
    if (!program) return false;

    program.last_verified = confirmedDate;
    program.verified_by = 'human';
    this.saveProgram(program, 'human');
    return true;
  }
}

/**
 * Addition 6: Evaluates per-program testing restrictions at scheduling time.
 * Evaluates time windows and method restrictions per-task.
 */
export function evaluateTestingRestrictions(
  program: ProgramRegistryEntry,
  task: { action?: string; method?: string; finding_type?: string },
  currentDate = new Date()
): { allowed: boolean; reason?: string } {
  const restrictions = (program.testing_restrictions || '').toLowerCase();
  if (!restrictions || restrictions.trim().length === 0) {
    return { allowed: true };
  }

  // 1. Method restrictions
  const actionMethod = `${task.action || ''} ${task.method || ''} ${task.finding_type || ''}`.toLowerCase();
  const disallowedKeywords = ['dos', 'denial_of_service', 'bruteforce', 'brute_force', 'mass_scan', 'destructive'];

  for (const kw of disallowedKeywords) {
    if (restrictions.includes(`no_${kw}`) || restrictions.includes(`disallow_${kw}`) || restrictions.includes(`prohibit_${kw}`)) {
      if (actionMethod.includes(kw)) {
        return {
          allowed: false,
          reason: `Testing restriction violation: Program "${program.program}" forbids "${kw}". Action "${actionMethod.trim()}" is blocked.`
        };
      }
    }
  }

  // 2. Time window restrictions
  const allowedMatch = restrictions.match(/(?:time_window|allowed_hours|window|allowed_window)\s*[:=]\s*(\d{1,2}):?(\d{2})?-(\d{1,2}):?(\d{2})?/i);
  if (allowedMatch) {
    const startHour = parseInt(allowedMatch[1], 10);
    const startMin = allowedMatch[2] ? parseInt(allowedMatch[2], 10) : 0;
    const endHour = parseInt(allowedMatch[3], 10);
    const endMin = allowedMatch[4] ? parseInt(allowedMatch[4], 10) : 0;

    const currentHour = currentDate.getUTCHours();
    const currentMin = currentDate.getUTCMinutes();
    const currentMinutes = currentHour * 60 + currentMin;
    const startMinutes = startHour * 60 + startMin;
    const endMinutes = endHour * 60 + endMin;

    let inWindow = false;
    if (startMinutes <= endMinutes) {
      inWindow = currentMinutes >= startMinutes && currentMinutes <= endMinutes;
    } else {
      inWindow = currentMinutes >= startMinutes || currentMinutes <= endMinutes;
    }

    if (!inWindow) {
      return {
        allowed: false,
        reason: `Testing restriction violation: Current time (${String(currentHour).padStart(2, '0')}:${String(currentMin).padStart(2, '0')} UTC) is outside permitted testing window (${allowedMatch[0]}) for program "${program.program}".`
      };
    }
  }

  // Blackout window
  const restrictedMatch = restrictions.match(/(?:forbidden_hours|restricted_window|no_testing|blackout_window)\s*[:=]\s*(\d{1,2}):?(\d{2})?-(\d{1,2}):?(\d{2})?/i);
  if (restrictedMatch) {
    const startHour = parseInt(restrictedMatch[1], 10);
    const startMin = restrictedMatch[2] ? parseInt(restrictedMatch[2], 10) : 0;
    const endHour = parseInt(restrictedMatch[3], 10);
    const endMin = restrictedMatch[4] ? parseInt(restrictedMatch[4], 10) : 0;

    const currentHour = currentDate.getUTCHours();
    const currentMin = currentDate.getUTCMinutes();
    const currentMinutes = currentHour * 60 + currentMin;
    const startMinutes = startHour * 60 + startMin;
    const endMinutes = endHour * 60 + endMin;

    let inBlackout = false;
    if (startMinutes <= endMinutes) {
      inBlackout = currentMinutes >= startMinutes && currentMinutes <= endMinutes;
    } else {
      inBlackout = currentMinutes >= startMinutes || currentMinutes <= endMinutes;
    }

    if (inBlackout) {
      return {
        allowed: false,
        reason: `Testing restriction violation: Current time (${String(currentHour).padStart(2, '0')}:${String(currentMin).padStart(2, '0')} UTC) falls within restricted blackout window (${restrictedMatch[0]}) for program "${program.program}".`
      };
    }
  }

  return { allowed: true };
}
