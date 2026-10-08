/**
 * In-memory ScanPort stub (test double) for the ReconLab v2 scan-trigger contract.
 *
 * Models a realistic coarse-scan engine so contract tests can drive every branch
 * offline without a worker key or a live ReconLab server:
 *   - happy path: queued -> running -> done, partial-then-complete findings
 *   - scope-denied: OUT_OF_SCOPE / SCOPE_EXPIRED (as a thrown code OR a
 *     scope_check.allowed=false field, server-authority style)
 *   - BUDGET_EXHAUSTED on create
 *   - running-partial findings (complete:false), never final
 *   - idempotency: same key -> SAME scan; missing key -> IDEMPOTENCY_KEY_REQUIRED;
 *     same key + different request -> IDEMPOTENCY_CONFLICT
 *
 * It throws the SAME ReconLabError the real client throws, so callers branch on
 * error.code identically against the stub and the wire.
 */

import { ReconLabError } from "./reconlab-client.ts";
import {
  SCAN_ERROR_CODES,
  type Budget,
  type ScanFinding,
  type ScanFindingsResult,
  type ScanHandle,
  type ScanPort,
  type ScanRequest,
  type ScanState,
  type ScanStats,
  type ScanStatus,
  type ScopeCheck,
} from "./scan-port.ts";

export interface StubScanScript {
  /** If set, createScan throws this ReconLabError instead of creating a scan. */
  createError?: { status: number; code: string; message?: string; data?: Record<string, unknown> };
  /** scope_check attached to every getScan status (server-authority field path). */
  scopeCheck?: ScopeCheck;
  /** budget attached to every getScan status. */
  budget?: Budget;
  /** stats attached to every getScan status. */
  stats?: ScanStats;
  /** getScan state progression; index clamps to the LAST entry (which repeats). */
  states: ScanState[];
  /** findings returned while NOT done (complete:false). */
  partialFindings?: ScanFinding[];
  /** findings returned once done (complete:true). */
  finalFindings?: ScanFinding[];
  /**
   * Force getScanFindings to report a non-done / complete:false result even after
   * getScan reaches a terminal state -- used to prove callers never treat
   * partial / non-done findings as final.
   */
  neverComplete?: boolean;
}

export interface StubScanPortOptions {
  idFactory?: () => string;
}

interface ScanRecord {
  id: string;
  req: ScanRequest;
  poll: number;
  lastState: ScanState;
}

export class StubScanPort implements ScanPort {
  readonly script: StubScanScript;
  private readonly idFactory: () => string;
  private seq = 0;
  private readonly scans = new Map<string, ScanRecord>();
  private readonly idem = new Map<string, { id: string; fingerprint: string }>();

  // Observable counters for assertions.
  createCalls = 0;
  getScanCalls = 0;
  getFindingsCalls = 0;
  readonly createdIds: string[] = [];

  constructor(script: StubScanScript, options: StubScanPortOptions = {}) {
    this.script = script;
    this.idFactory = options.idFactory ?? (() => `scan-${(this.seq += 1)}`);
  }

  private err(status: number, code: string, message?: string, data?: Record<string, unknown>): ReconLabError {
    return new ReconLabError({ status, code, message: message ?? code, ...(data ? { data } : {}) });
  }

  private fingerprint(req: ScanRequest): string {
    return JSON.stringify({
      kind: req.kind,
      target: req.target,
      scope_id: req.scope_id,
      args: req.args ?? null,
    });
  }

  async createScan(req: ScanRequest, idempotencyKey: string): Promise<ScanHandle> {
    this.createCalls += 1;
    if (!idempotencyKey) {
      throw this.err(400, SCAN_ERROR_CODES.IDEMPOTENCY_KEY_REQUIRED, "Idempotency-Key header required");
    }
    const fp = this.fingerprint(req);
    const prior = this.idem.get(idempotencyKey);
    if (prior) {
      if (prior.fingerprint !== fp) {
        throw this.err(
          409,
          SCAN_ERROR_CODES.IDEMPOTENCY_CONFLICT,
          "Idempotency-Key reused with a different request",
        );
      }
      return { id: prior.id }; // replay: the SAME scan
    }
    if (this.script.createError) {
      const e = this.script.createError;
      throw this.err(e.status, e.code, e.message, e.data);
    }
    const id = this.idFactory();
    this.scans.set(id, { id, req, poll: 0, lastState: this.script.states[0] ?? "queued" });
    this.idem.set(idempotencyKey, { id, fingerprint: fp });
    this.createdIds.push(id);
    return { id };
  }

  async getScan(id: string): Promise<ScanStatus> {
    this.getScanCalls += 1;
    const rec = this.scans.get(id);
    if (!rec) throw this.err(404, SCAN_ERROR_CODES.NOT_FOUND, `scan ${id} not found`);
    const states = this.script.states.length > 0 ? this.script.states : (["done"] as ScanState[]);
    const idx = Math.min(rec.poll, states.length - 1);
    const state = states[idx]!;
    rec.poll += 1;
    rec.lastState = state;
    const terminal = state === "done" || state === "failed";
    const progress = terminal ? 100 : Math.min(95, Math.round(((idx + 1) / states.length) * 100));
    return {
      id,
      state,
      progress,
      ...(this.script.stats ? { stats: this.script.stats } : {}),
      ...(this.script.scopeCheck ? { scope_check: this.script.scopeCheck } : {}),
      ...(this.script.budget ? { budget: this.script.budget } : {}),
    };
  }

  async getScanFindings(id: string): Promise<ScanFindingsResult> {
    this.getFindingsCalls += 1;
    const rec = this.scans.get(id);
    if (!rec) throw this.err(404, SCAN_ERROR_CODES.NOT_FOUND, `scan ${id} not found`);
    if (this.script.neverComplete) {
      // Findings endpoint lags behind status: still running, never final.
      return {
        state: "running",
        complete: false,
        findings: this.script.partialFindings ?? [],
      };
    }
    const done = rec.lastState === "done";
    if (done) {
      return { state: "done", complete: true, findings: this.script.finalFindings ?? [] };
    }
    return { state: rec.lastState, complete: false, findings: this.script.partialFindings ?? [] };
  }
}