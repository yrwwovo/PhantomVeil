/**
 * ReconLab v2 scan-trigger contract (PhantomVeil side, "Option A2").
 *
 * Thin ScanPort over the three NEW scan endpoints agreed with the ReconLab team:
 *   POST /api/scans                 -> create a scan (needs Idempotency-Key header)
 *   GET  /api/scans/{id}            -> async state (queued|running|done|failed)
 *   GET  /api/scans/{id}/findings   -> structured findings (partial while running)
 *
 * Division of labor: ReconLab does the broad coarse scanning and produces
 * candidate findings; PhantomVeil orchestrates + deep-verifies + judges. This
 * port is the "tool interface" PhantomVeil drives; it does NOT rebuild scanners.
 *
 * Source of truth for error codes + scan states is GET /api/contract/meta. The
 * unions and constants below MIRROR that published set so code can branch on a
 * stable name; a live client should still treat meta as authority. Two hard
 * rules carried from the contract:
 *   1. Branch on error.code, never on message.
 *   2. NEVER treat partial / non-done findings as final (see ScanFindingsResult).
 */

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

/** Scan families ReconLab exposes. */
export type ScanKind = "subdomain" | "port" | "http" | "dir" | "vuln" | "poc";

/** Async lifecycle state of a scan (a STATE, not an error code). */
export type ScanState = "queued" | "running" | "done" | "failed";

/** Terminal states: polling stops here. */
export const TERMINAL_SCAN_STATES: ReadonlySet<ScanState> = new Set<ScanState>(["done", "failed"]);

/**
 * Contract-v2 error codes relevant to the scan endpoints. All but one REUSE the
 * shared v2 error_codes; the scan-new codes are BUDGET_EXHAUSTED and SCAN_FAILED
 * (generic terminal failure, surfaced via ScanStatus.failure_code). Published at
 * /api/contract/meta -- these constants only name the branches, they are not the
 * source of truth.
 */
export const SCAN_ERROR_CODES = {
  OUT_OF_SCOPE: "OUT_OF_SCOPE",
  SCOPE_EXPIRED: "SCOPE_EXPIRED",
  IDEMPOTENCY_KEY_REQUIRED: "IDEMPOTENCY_KEY_REQUIRED",
  IDEMPOTENCY_CONFLICT: "IDEMPOTENCY_CONFLICT",
  RATE_LIMITED: "RATE_LIMITED",
  NOT_FOUND: "NOT_FOUND",
  BUDGET_EXHAUSTED: "BUDGET_EXHAUSTED",
  /** Generic "scan ended in failed" code (no more specific code applies). */
  SCAN_FAILED: "SCAN_FAILED",
} as const;

export type ScanErrorCode = (typeof SCAN_ERROR_CODES)[keyof typeof SCAN_ERROR_CODES];

/** Codes that mean "scope refused the target"; a scan must not proceed. */
export const SCOPE_DENIED_CODES: readonly string[] = [
  SCAN_ERROR_CODES.OUT_OF_SCOPE,
  SCAN_ERROR_CODES.SCOPE_EXPIRED,
];

export interface ScanRequest {
  kind: ScanKind;
  target: string;
  scope_id: string;
  args?: Record<string, unknown>;
}

export interface ScanHandle {
  id: string;
}

/** scope_check response field; server is authority. */
export interface ScopeCheck {
  allowed: boolean;
  scope_id: string;
  /** Present when not allowed, e.g. OUT_OF_SCOPE / SCOPE_EXPIRED. */
  code?: string;
}

/** budget response field; remaining is server-authoritative. */
export interface Budget {
  remaining: number;
  limit: number;
}

/** Free-form progress counters (hosts, ports, requests, ...). */
export type ScanStats = Record<string, number>;

export interface ScanStatus {
  id: string;
  state: ScanState;
  /** 0..100. */
  progress: number;
  stats?: ScanStats;
  /** Human-readable only. NEVER branch on this; use failure_code. */
  message?: string;
  /**
   * Stable machine code (from meta's error_codes) explaining a `failed` state,
   * e.g. SCAN_FAILED / OUT_OF_SCOPE / SCOPE_EXPIRED / BUDGET_EXHAUSTED. Callers
   * branch on this, never on message. Absent while not failed.
   */
  failure_code?: string;
  scope_check?: ScopeCheck;
  budget?: Budget;
}

export interface ScanFinding {
  id: string;
  title: string;
  severity: string;
  url?: string;
  service?: string;
  version?: string;
  fingerprint?: string;
  cve_candidates?: string[];
  category?: string;
  parameter?: string;
  confidence?: number;
  /**
   * ReconLab evidence-channel ids (EV ids) backing this finding. Deep
   * verification anchors to these real evidence records, not only to the
   * coarse `confidence` number. Optional: older/partial findings may omit it.
   */
  evidence_refs?: string[];
}

/**
 * Findings read. While the scan is still running this returns HTTP 200 with
 * complete:false / state:"running" and PARTIAL findings. Callers MUST treat
 * findings as final ONLY when complete === true AND state === "done".
 */
export interface ScanFindingsResult {
  state: ScanState;
  complete: boolean;
  findings: ScanFinding[];
}

/**
 * Fixed UUIDv5 namespace for PhantomVeil scan idempotency keys. NEVER change it:
 * doing so would re-key every logical scan and break crash-and-retry dedupe.
 */
export const SCAN_IDEMPOTENCY_NAMESPACE = "1837aa1d-5584-4e1f-b075-6823fd3c657c";

/**
 * Deterministic, cross-process-stable Idempotency-Key for POST /api/scans.
 *
 * ReconLab only honors the Idempotency-Key header and never synthesizes one, so
 * determinism is OUR responsibility: a crash-and-retry of the same logical scan
 * must send the SAME key and therefore get back the SAME scan (never a fresh
 * random UUID per call).
 *
 * Key = RFC 4122 UUIDv5(SCAN_IDEMPOTENCY_NAMESPACE, name), where
 *   name = JSON.stringify([req.kind, req.target, req.scope_id])
 * (UTF-8, compact JSON array -> unambiguous field boundaries). Only kind,
 * target and scope_id are hashed; req.args is deliberately NOT part of the key.
 * Values are used verbatim (no trimming / case-folding). Reproducible elsewhere,
 * e.g. Python: uuid.uuid5(uuid.UUID(NS), json.dumps([kind, target, scope_id],
 * separators=(",", ":"), ensure_ascii=False)).
 */
export function deriveScanIdempotencyKey(req: ScanRequest): string {
  const name = JSON.stringify([req.kind, req.target, req.scope_id]);
  const ns = Buffer.from(SCAN_IDEMPOTENCY_NAMESPACE.replace(/-/g, ""), "hex");
  const digest = createHash("sha1").update(ns).update(name, "utf8").digest();
  const b = digest.subarray(0, 16);
  b[6] = (b[6]! & 0x0f) | 0x50; // version 5
  b[8] = (b[8]! & 0x3f) | 0x80; // RFC 4122 variant
  const hex = b.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/** The scan-trigger tool interface PhantomVeil drives. */
export interface ScanPort {
  createScan(req: ScanRequest, idempotencyKey: string): Promise<ScanHandle>;
  getScan(id: string): Promise<ScanStatus>;
  getScanFindings(id: string): Promise<ScanFindingsResult>;
}