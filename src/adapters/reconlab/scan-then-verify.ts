/**
 * ReconLab v2 scan-then-verify orchestrator (PhantomVeil side, "Option A2").
 *
 * Ties the scan-trigger ScanPort to the existing verify-sync path:
 *   createScan -> poll getScan until terminal (done|failed, bounded interval +
 *   timeout) -> on done read getScanFindings -> select findings -> ingest the
 *   chosen ones into the review queue (ReconLabClient.report, the SAME queue
 *   ingest path the adapter already uses) -> reuse verifyFromReconLab to
 *   claim + deep-verify + write back.
 *
 * Hard guarantees:
 *   - NEVER treats partial / non-done findings as final: ingestion + verify only
 *     run when getScanFindings reports complete === true AND state === "done".
 *   - Surfaces scope-denied (OUT_OF_SCOPE / SCOPE_EXPIRED, whether thrown or
 *     returned as scope_check.allowed=false), BUDGET_EXHAUSTED, and a failed scan
 *     state as clear outcomes rather than proceeding.
 *   - Branches on ReconLabError.code, never on message.
 */

import { ReconLabError, type ReconLabClient } from "./reconlab-client.ts";
import {
  verifyFromReconLab,
  type SyncRunSummary,
  type VerifyFromReconLabArgs,
  type VerifyFromReconLabOptions,
} from "./reconlab-sync.ts";
import {
  SCAN_ERROR_CODES,
  SCOPE_DENIED_CODES,
  type Budget,
  type ScanFinding,
  type ScanPort,
  type ScanRequest,
  type ScanState,
  type ScopeCheck,
} from "./scan-port.ts";

export type ScanThenVerifyOutcome =
  | "verified"
  | "no_findings"
  | "scope_denied"
  | "budget_exhausted"
  | "scan_failed"
  | "findings_not_final"
  | "timeout"
  | "error";

export interface IngestedRef {
  finding_id: string;
  queue_id?: string;
  replay?: boolean;
}

export interface IngestOutcome {
  queue_id?: string;
  replay?: boolean;
}

export interface ScanThenVerifyArgs {
  request: ScanRequest;
  /** Stable client-generated UUID (NOT a content hash); duplicate -> same scan. */
  idempotencyKey: string;
  workerId: string;
}

export interface ScanThenVerifyOptions {
  pollIntervalMs?: number;
  pollTimeoutMs?: number;
  maxPolls?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  /** Choose which findings to ingest; default: all of them. */
  selectFindings?: (findings: ScanFinding[]) => ScanFinding[];
  /** Map a finding to the queue ingest body; default defaultScanFindingToQueue. */
  toReportBody?: (finding: ScanFinding, req: ScanRequest) => Record<string, unknown>;
  /** Stable idempotency key for ingesting one finding; default scan+finding id. */
  reportIdempotencyKey?: (finding: ScanFinding, scanId: string) => string;
  /** Override the ingest step (default: ReconLabClient.report). */
  ingest?: (body: Record<string, unknown>, idempotencyKey: string) => Promise<IngestOutcome>;
  /** Override the verify step (default: verifyFromReconLab). */
  verify?: () => Promise<SyncRunSummary>;
  /** Extra args forwarded to the default verifyFromReconLab (workerId is fixed). */
  verifyArgs?: Partial<Pick<VerifyFromReconLabArgs, "kind" | "limit" | "state">>;
  /** Options forwarded to the default verifyFromReconLab. */
  verifyOptions?: VerifyFromReconLabOptions;
}

export interface ScanThenVerifyResult {
  outcome: ScanThenVerifyOutcome;
  scanId?: string;
  state?: ScanState;
  code?: string;
  detail?: string;
  scope_check?: ScopeCheck;
  budget?: Budget;
  polls?: number;
  findingsCount?: number;
  ingested?: IngestedRef[];
  verify?: SyncRunSummary;
}

/** Default mapping from a structured scan finding to a verification-queue body. */
export function defaultScanFindingToQueue(
  finding: ScanFinding,
  req: ScanRequest,
): Record<string, unknown> {
  return {
    kind: finding.category ?? req.kind,
    title: finding.title,
    target: req.target,
    scope_id: req.scope_id,
    ...(finding.url ? { endpoint: finding.url } : {}),
    ...(finding.parameter ? { parameter: finding.parameter } : {}),
    ...(finding.severity ? { severity: finding.severity } : {}),
    ...(finding.confidence !== undefined ? { confidence: finding.confidence } : {}),
    ...(finding.service ? { service: finding.service } : {}),
    ...(finding.version ? { version: finding.version } : {}),
    ...(finding.fingerprint ? { fingerprint: finding.fingerprint } : {}),
    ...(finding.cve_candidates && finding.cve_candidates.length > 0
      ? { cve_candidates: finding.cve_candidates }
      : {}),
    source: "reconlab-scan",
    source_finding_id: finding.id,
  };
}

function asReconLabError(error: unknown): ReconLabError | undefined {
  return error instanceof ReconLabError ? error : undefined;
}

/** Map a ReconLabError from create/poll/findings to a terminal outcome, or undefined. */
function mapScanError(error: unknown, scanId?: string): ScanThenVerifyResult | undefined {
  const e = asReconLabError(error);
  if (!e) return undefined;
  if (SCOPE_DENIED_CODES.includes(e.code)) {
    return { outcome: "scope_denied", ...(scanId ? { scanId } : {}), code: e.code, detail: e.code };
  }
  if (e.code === SCAN_ERROR_CODES.BUDGET_EXHAUSTED) {
    return { outcome: "budget_exhausted", ...(scanId ? { scanId } : {}), code: e.code, detail: e.code };
  }
  return { outcome: "error", ...(scanId ? { scanId } : {}), code: e.code, detail: e.code };
}

export async function scanThenVerify(
  scanPort: ScanPort,
  client: ReconLabClient,
  projectRoot: string,
  args: ScanThenVerifyArgs,
  options: ScanThenVerifyOptions = {},
): Promise<ScanThenVerifyResult> {
  const sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const now = options.now ?? Date.now;
  const interval = options.pollIntervalMs ?? 2000;
  const timeout = options.pollTimeoutMs ?? 300_000;
  const selectFindings = options.selectFindings ?? ((f) => f);
  const toBody = options.toReportBody ?? defaultScanFindingToQueue;
  const reportKey =
    options.reportIdempotencyKey ?? ((f: ScanFinding, sid: string) => `scan:${sid}:finding:${f.id}`);
  const ingest: (body: Record<string, unknown>, key: string) => Promise<IngestOutcome> =
    options.ingest ??
    (async (body, key) => {
      const r = await client.report(body, { idempotencyKey: key });
      return { queue_id: r.item?.id, replay: r.replay };
    });

  // 1. Create the scan (Idempotency-Key required by contract).
  let scanId: string;
  try {
    const handle = await scanPort.createScan(args.request, args.idempotencyKey);
    scanId = handle.id;
  } catch (error) {
    const mapped = mapScanError(error);
    if (mapped) return mapped;
    throw error;
  }

  // 2. Poll until terminal, bounded by interval + timeout (+ optional maxPolls).
  const start = now();
  let polls = 0;
  let lastState: ScanState = "queued";
  let lastBudget: Budget | undefined;
  for (;;) {
    let status;
    try {
      status = await scanPort.getScan(scanId);
    } catch (error) {
      const mapped = mapScanError(error, scanId);
      if (mapped) return { ...mapped, polls };
      throw error;
    }
    polls += 1;
    lastState = status.state;
    lastBudget = status.budget;

    // Server-authority scope field: refuse to proceed if scope says no.
    if (status.scope_check && status.scope_check.allowed === false) {
      return {
        outcome: "scope_denied",
        scanId,
        state: status.state,
        ...(status.scope_check.code ? { code: status.scope_check.code } : {}),
        scope_check: status.scope_check,
        ...(status.budget ? { budget: status.budget } : {}),
        polls,
        detail: "scope_check.allowed=false",
      };
    }
    if (status.state === "failed") {
      return {
        outcome: "scan_failed",
        scanId,
        state: status.state,
        ...(status.scope_check ? { scope_check: status.scope_check } : {}),
        ...(status.budget ? { budget: status.budget } : {}),
        polls,
        detail: status.message ?? "scan failed",
      };
    }
    if (status.state === "done") break;

    if (now() - start >= timeout || (options.maxPolls !== undefined && polls >= options.maxPolls)) {
      return {
        outcome: "timeout",
        scanId,
        state: status.state,
        ...(status.budget ? { budget: status.budget } : {}),
        polls,
        detail: `no terminal state within ${timeout}ms`,
      };
    }
    await sleep(interval);
  }

  // 3. Read findings. GUARD: never treat partial / non-done findings as final.
  let findingsRes;
  try {
    findingsRes = await scanPort.getScanFindings(scanId);
  } catch (error) {
    const mapped = mapScanError(error, scanId);
    if (mapped) return { ...mapped, polls };
    throw error;
  }
  if (!(findingsRes.complete === true && findingsRes.state === "done")) {
    return {
      outcome: "findings_not_final",
      scanId,
      state: findingsRes.state,
      polls,
      findingsCount: findingsRes.findings.length,
      detail: `findings not final (complete=${findingsRes.complete}, state=${findingsRes.state})`,
    };
  }

  // 4. Select + ingest chosen findings into the review queue.
  const chosen = selectFindings(findingsRes.findings);
  if (chosen.length === 0) {
    return {
      outcome: "no_findings",
      scanId,
      state: lastState,
      ...(lastBudget ? { budget: lastBudget } : {}),
      polls,
      findingsCount: findingsRes.findings.length,
      ingested: [],
    };
  }
  const ingested: IngestedRef[] = [];
  for (const finding of chosen) {
    const body = toBody(finding, args.request);
    const key = reportKey(finding, scanId);
    let out: IngestOutcome;
    try {
      out = await ingest(body, key);
    } catch (error) {
      const e = asReconLabError(error);
      return {
        outcome: "error",
        scanId,
        state: lastState,
        ...(e ? { code: e.code } : {}),
        polls,
        findingsCount: findingsRes.findings.length,
        ingested,
        detail: `ingest_failed:${e ? e.code : String(error)}`,
      };
    }
    ingested.push({
      finding_id: finding.id,
      ...(out.queue_id ? { queue_id: out.queue_id } : {}),
      ...(out.replay !== undefined ? { replay: out.replay } : {}),
    });
  }

  // 5. Reuse verifyFromReconLab to claim + verify + write back.
  let summary: SyncRunSummary;
  try {
    summary = options.verify
      ? await options.verify()
      : await verifyFromReconLab(
          client,
          projectRoot,
          {
            workerId: args.workerId,
            state: options.verifyArgs?.state ?? "suspected",
            ...(options.verifyArgs?.kind ? { kind: options.verifyArgs.kind } : {}),
            ...(options.verifyArgs?.limit ? { limit: options.verifyArgs.limit } : {}),
          },
          options.verifyOptions ?? {},
        );
  } catch (error) {
    const e = asReconLabError(error);
    return {
      outcome: "error",
      scanId,
      state: lastState,
      ...(e ? { code: e.code } : {}),
      polls,
      findingsCount: findingsRes.findings.length,
      ingested,
      detail: `verify_failed:${e ? e.code : String(error)}`,
    };
  }

  return {
    outcome: "verified",
    scanId,
    state: "done",
    ...(lastBudget ? { budget: lastBudget } : {}),
    polls,
    findingsCount: findingsRes.findings.length,
    ingested,
    verify: summary,
  };
}