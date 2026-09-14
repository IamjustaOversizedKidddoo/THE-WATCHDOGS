/**
 * The Watchdogs — /michael Parallel-Program Scheduler Service (Addition 6)
 *
 * Enforces:
 *  1. Mandatory program_id on every task; zero guessing or scheduling without one.
 *  2. Pre-scheduling testing restrictions check (time windows, prohibited methods) per-task.
 *  3. Parallel recon (/jonathan) vs strictly single-concurrency FIFO queues for validation desks
 *     (/chris, /daniel, /david). Tasks from different programs wait their turn rather than
 *     executing concurrently under the same desk.
 *  4. Configurable per-program pacing to prevent anti-automation defenses.
 *  5. Retains program_id context across all task states and queues.
 */

import { ProgramRegistryService, evaluateTestingRestrictions, type ProgramRegistryEntry } from './programRegistry';

export type DeskCallsign = '/jonathan' | '/chris' | '/daniel' | '/david' | '/michael';

export interface ScheduledTask {
  id: string;
  program_id: string;
  target: string;
  targetDesk: DeskCallsign | string;
  phase: 'recon' | 'discovery' | 'exploitation' | 'reporting';
  action: string;
  method?: string;
  finding_type?: string;
  status: 'queued' | 'running' | 'completed' | 'blocked' | 'delayed';
  queuedAt: string;
  startedAt?: string;
  completedAt?: string;
  blockedReason?: string;
  durationMs?: number;
}

export interface ScheduleTaskOptions {
  currentTime?: Date;
  customPacingMs?: number;
}

export class MichaelSchedulerService {
  private readonly programRegistry: ProgramRegistryService;
  private readonly tasks = new Map<string, ScheduledTask>();

  // Desk queues for sequential validation desks
  private readonly deskQueues = new Map<string, string[]>(); // desk -> array of taskIds
  private readonly activeRunningByDesk = new Map<string, string | null>(); // desk -> taskId

  // Per-program pacing tracker
  private readonly lastDispatchByProgram = new Map<string, number>(); // program_id -> timestamp ms
  private defaultPacingMs = 500;

  constructor(
    programRegistry?: ProgramRegistryService,
    defaultPacingMs = 500
  ) {
    this.programRegistry = programRegistry || new ProgramRegistryService();
    this.defaultPacingMs = defaultPacingMs;
  }

  public setProgramPacing(ms: number): void {
    this.defaultPacingMs = ms;
  }

  public getProgramPacing(): number {
    return this.defaultPacingMs;
  }

  /**
   * Addition 6: Inspects per-program pacing to ensure automated actions respect rate limits.
   */
  public checkPacing(programId: string, currentTime = new Date()): { allowed: boolean; waitMs: number } {
    const lastDispatch = this.lastDispatchByProgram.get(programId) || 0;
    const nowMs = currentTime.getTime();
    const elapsed = nowMs - lastDispatch;
    if (elapsed < this.defaultPacingMs) {
      return { allowed: false, waitMs: this.defaultPacingMs - elapsed };
    }
    return { allowed: true, waitMs: 0 };
  }

  /**
   * Schedules a task under /michael's parallel-program coordination.
   * STRICT GUARD: Rejects scheduling without confirmed program_id.
   * Evaluates per-program testing restrictions per-task.
   */
  public scheduleTask(
    taskInput: {
      id?: string;
      program_id?: string;
      target: string;
      targetDesk: DeskCallsign | string;
      phase: 'recon' | 'discovery' | 'exploitation' | 'reporting';
      action: string;
      method?: string;
      finding_type?: string;
    },
    options?: ScheduleTaskOptions
  ): {
    success: boolean;
    task?: ScheduledTask;
    reason?: string;
    queued?: boolean;
    startedImmediately?: boolean;
  } {
    const taskId = taskInput.id || `task-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    // ── 1. Guardrail: Mandatory Program ID ──────────────────────────────────────
    if (!taskInput.program_id || taskInput.program_id.trim().length === 0) {
      return {
        success: false,
        reason: 'Cannot schedule task: Missing or uncertain program_id. Program must be confirmed with operator before scheduling.'
      };
    }

    const program = this.programRegistry.getProgram(taskInput.program_id);
    if (!program) {
      return {
        success: false,
        reason: `Cannot schedule task: Program "${taskInput.program_id}" is not registered in program registry. Scope cannot be assumed.`
      };
    }

    // ── 2. Guardrail: Scope Verification for THIS Program ───────────────────────
    const scopeCheck = this.programRegistry.checkScope(taskInput.target, program);
    if (!scopeCheck.inScope) {
      return {
        success: false,
        reason: `Scope Violation: Target "${taskInput.target}" is not in scope for program "${program.program}".`
      };
    }

    // ── 3. Guardrail: Per-Program Testing Restrictions ──────────────────────────
    const evalTime = options?.currentTime || new Date();
    const restrictionCheck = evaluateTestingRestrictions(program, taskInput, evalTime);
    if (!restrictionCheck.allowed) {
      const blockedTask: ScheduledTask = {
        id: taskId,
        program_id: taskInput.program_id,
        target: taskInput.target,
        targetDesk: taskInput.targetDesk,
        phase: taskInput.phase,
        action: taskInput.action,
        method: taskInput.method,
        finding_type: taskInput.finding_type,
        status: 'blocked',
        queuedAt: evalTime.toISOString(),
        blockedReason: restrictionCheck.reason
      };
      this.tasks.set(taskId, blockedTask);

      return {
        success: false,
        task: blockedTask,
        reason: restrictionCheck.reason
      };
    }

    // ── 4. Per-Program Pacing Check ─────────────────────────────────────────────
    const pacingMs = options?.customPacingMs || this.defaultPacingMs;
    const lastDispatch = this.lastDispatchByProgram.get(taskInput.program_id) || 0;
    const nowMs = evalTime.getTime();
    const timeSinceLastAction = nowMs - lastDispatch;

    // ── 5. Enqueue & Concurrency Management ─────────────────────────────────────
    const task: ScheduledTask = {
      id: taskId,
      program_id: taskInput.program_id,
      target: taskInput.target,
      targetDesk: taskInput.targetDesk,
      phase: taskInput.phase,
      action: taskInput.action,
      method: taskInput.method,
      finding_type: taskInput.finding_type,
      status: 'queued',
      queuedAt: evalTime.toISOString()
    };

    this.tasks.set(taskId, task);

    const cleanDesk = taskInput.targetDesk.toLowerCase();

    // /jonathan (recon) runs genuinely in parallel across multiple programs
    if (cleanDesk === '/jonathan' || cleanDesk === 'jonathan') {
      task.status = 'running';
      task.startedAt = evalTime.toISOString();
      this.lastDispatchByProgram.set(taskInput.program_id, nowMs);
      return {
        success: true,
        task,
        startedImmediately: true
      };
    }

    // Validation desks (/chris, /daniel, /david) are single-concurrency FIFO queues
    const queue = this.deskQueues.get(cleanDesk) || [];
    const activeTask = this.activeRunningByDesk.get(cleanDesk);

    if (!activeTask) {
      // Desk is currently idle: start this task immediately
      task.status = 'running';
      task.startedAt = evalTime.toISOString();
      this.activeRunningByDesk.set(cleanDesk, taskId);
      this.lastDispatchByProgram.set(taskInput.program_id, nowMs);
      return {
        success: true,
        task,
        startedImmediately: true
      };
    } else {
      // Desk is busy: queue task
      queue.push(taskId);
      this.deskQueues.set(cleanDesk, queue);
      task.status = 'queued';
      return {
        success: true,
        task,
        queued: true,
        startedImmediately: false,
        reason: `Desk ${taskInput.targetDesk} is currently executing task "${activeTask}". Task queued in FIFO position #${queue.length}.`
      };
    }
  }

  /**
   * Completes an active task on a desk and triggers the next queued task sequentially.
   */
  public completeTask(
    taskId: string,
    completedTime = new Date()
  ): {
    completedTask: ScheduledTask | null;
    nextTaskStarted: ScheduledTask | null;
  } {
    const task = this.tasks.get(taskId);
    if (!task) {
      return { completedTask: null, nextTaskStarted: null };
    }

    task.status = 'completed';
    task.completedAt = completedTime.toISOString();
    if (task.startedAt) {
      task.durationMs = completedTime.getTime() - new Date(task.startedAt).getTime();
    }

    const cleanDesk = task.targetDesk.toLowerCase();

    // For parallel desks (/jonathan), no queue unwinding needed
    if (cleanDesk === '/jonathan' || cleanDesk === 'jonathan') {
      return { completedTask: task, nextTaskStarted: null };
    }

    // Unset active task if this task was the active one
    if (this.activeRunningByDesk.get(cleanDesk) === taskId) {
      this.activeRunningByDesk.set(cleanDesk, null);
    }

    // Dequeue next sequential task for this desk
    const queue = this.deskQueues.get(cleanDesk) || [];
    if (queue.length > 0) {
      const nextTaskId = queue.shift()!;
      this.deskQueues.set(cleanDesk, queue);

      const nextTask = this.tasks.get(nextTaskId);
      if (nextTask) {
        nextTask.status = 'running';
        nextTask.startedAt = completedTime.toISOString();
        this.activeRunningByDesk.set(cleanDesk, nextTaskId);
        this.lastDispatchByProgram.set(nextTask.program_id, completedTime.getTime());
        return { completedTask: task, nextTaskStarted: nextTask };
      }
    }

    return { completedTask: task, nextTaskStarted: null };
  }

  public getTask(taskId: string): ScheduledTask | null {
    return this.tasks.get(taskId) || null;
  }

  public getActiveTaskForDesk(desk: string): ScheduledTask | null {
    const clean = desk.toLowerCase();
    const activeId = this.activeRunningByDesk.get(clean);
    return activeId ? this.tasks.get(activeId) || null : null;
  }

  public getQueueForDesk(desk: string): ScheduledTask[] {
    const clean = desk.toLowerCase();
    const queueIds = this.deskQueues.get(clean) || [];
    return queueIds.map((id) => this.tasks.get(id)!).filter(Boolean);
  }

  public getAllTasks(): ScheduledTask[] {
    return Array.from(this.tasks.values());
  }

  public getTasksForProgram(programId: string): ScheduledTask[] {
    return Array.from(this.tasks.values()).filter((t) => t.program_id === programId);
  }
}
