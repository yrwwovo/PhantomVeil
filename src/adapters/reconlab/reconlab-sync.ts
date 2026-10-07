import { createHypothesis, type Hypothesis } from "../../hypotheses/hypothesis-manager.ts";
import { createDefaultVerifierRegistry } from "../../verifiers/index.ts";
import type { RubricProvider } from "../../verifiers/rubric-provider.ts";
import type { VerifierContext } from "../../verifiers/verifier-plugin.ts";
import type { VerifierRegistry } from "../../verifiers/verifier-registry.ts";
import {
  runVerificationStage,
  type VerificationStageResult,
} from "../../workflows/verification-stage.ts";
import {
  ReconLabError,
  type EvidenceRef,
  type QueueItem,
  type ReconLabClient,
  type VerdictInput,
} from "./reconlab-client.ts";

/**
 * ReconLab v2 verify-sync orchestrator (PhantomVeil side).
 *
 * Pulls suspected findings from ReconLab, claims each with a lease, runs the
 * PhantomVeil verification stage (steps 1-2) against a live HttpRubricProvider so
 * thresholds match the platform, uploads evidence, and writes the verdict back
 * under the contract concurrency rules (If-Match optimistic lock + lease).
 *
 * NOTE on "GET the fresh item" (brief step a): openapi.yaml exposes no read-only
 * GET /api/verification/queue/{id}. We obtain the freshest etag + confirm the
 * lease is still ours by RE-CLAIMING (same worker_id => server renews the lease
 * and returns the item). A lost lease therefore surfaces as 409
 * ALREADY_CLAIMED/LEASE_EXPIRED, which we treat as "lease lost -> abandon".
 */

export type SyncItemOutcome =
  | "confirmed"
  | "rejected"
  | "inconclusive"
  | "rubric_violation"
  | "skipped_claimed"
  | "scope_void"
  | "lease_lost"
  | "error";

export interface SyncItemResult {
  id: string;
  outcome: SyncItemOutcome;
  detail?: string;
  state_written?: string;
  evidence_ids?: string[];
  attempts?: number;
}

export interface SyncRunSummary {
  worker_id: string;
  processed: number;
  results: SyncItemResult[];
}

export interface EvidenceUpload {
  content: Uint8Array | ArrayBuffer | Buffer | string;
  kind?: string;
  note?: string;
  content_type?: string;
  filename?: string;
}

export interface VerifyFromReconLabArgs {
  workerId: string;
  kind?: string;
  limit?: number;
  state?: string;
}

export interface VerifyFromReconLabOptions {
  /** Threshold source; defaults to a live provider sharing the client transport. */
  rubricProvider?: RubricProvider;
  /** Verifier registry; defaults to the shipped plugins. Tests inject a stub. */
  registry?: VerifierRegistry;
  /** Override the whole verification step (tests stub a known judgment). */
  runVerification?: (ctx: {
    item: QueueItem;
    projectRoot: string;
    registry: VerifierRegistry;
    rubricProvider: RubricProvider;
  }) => Promise<VerificationStageResult>;
  /** Produce evidence bytes to upload for an item (confirmed needs >= 1). */
  gatherEvidence?: (item: QueueItem, stage: VerificationStageResult) => Promise<EvidenceUpload[]>;
  /** Redirect hops to scope-check before following; any out-of-scope => scope_void. */
  redirectHops?: (item: QueueItem) => string[];
  leaseSeconds?: number;
  maxPreconditionRetries?: number;
  heartbeatBeforeWrite?: boolean;
  artifactNamespace?: "opencode" | "hermes";
}

const TERMINAL_STATES = new Set(["confirmed", "rejected", "inconclusive"]);

function blank(value: unknown): value is undefined {
  return value === undefined || value === null || value === "";
}

function mergeEvidence(fresh: EvidenceRef[] = [], ours: EvidenceRef[] = []): EvidenceRef[] {
  const byId = new Map<string, EvidenceRef>();
  for (const ref of fresh) if (ref && ref.id) byId.set(ref.id, ref);
  for (const ref of ours) if (ref && ref.id) byId.set(ref.id, ref);
  return [...byId.values()];
}

function mergeChecks(
  fresh: Array<{ id?: string; state?: string }> = [],
  ours: Array<{ id?: string; state?: string }> = [],
): Array<{ id?: string; state?: string }> {
  const byId = new Map<string, { id?: string; state?: string }>();
  for (const c of fresh) if (c && c.id) byId.set(c.id, { id: c.id, state: c.state });
  for (const c of ours) if (c && c.id) byId.set(c.id, { id: c.id, state: c.state });
  return [...byId.values()];
}

/** Merge our verdict onto the freshest server record; do not clobber server fields we did not set. */
function buildVerdictBody(verdict: VerdictInput, fresh: QueueItem, leaseToken: string): VerdictInput {
  const location = !blank(verdict.location) ? verdict.location : (fresh.location as string | undefined);
  const parameter = !blank(verdict.parameter) ? verdict.parameter : (fresh.parameter as string | undefined);
  return {
    state: verdict.state,
    ...(verdict.verdict_note ? { verdict_note: verdict.verdict_note } : {}),
    ...(verdict.reason_code ? { reason_code: verdict.reason_code } : {}),
    ...(verdict.confidence !== undefined ? { confidence: verdict.confidence } : {}),
    ...(verdict.reproduction_steps && verdict.reproduction_steps.length > 0
      ? { reproduction_steps: verdict.reproduction_steps }
      : {}),
    evidence: mergeEvidence(fresh.evidence, verdict.evidence),
    checks: mergeChecks(fresh.checks, verdict.checks),
    ...(!blank(location) ? { location } : {}),
    ...(!blank(parameter) ? { parameter } : {}),
    lease_token: leaseToken,
  };
}

function defaultRunVerification(
  item: QueueItem,
  projectRoot: string,
  registry: VerifierRegistry,
  rubricProvider: RubricProvider,
  artifactNamespace: "opencode" | "hermes",
): Promise<VerificationStageResult> {
  if (blank(item.endpoint)) {
    throw new Error(`queue item ${item.id} has no endpoint to verify`);
  }
  const created = createHypothesis({
    title: item.title || `${item.kind} finding`,
    description: item.verdict_note || `imported from ReconLab queue item ${item.id}`,
    target_url: item.endpoint as string,
    reason: `imported from ReconLab item ${item.id} for verification`,
  });
  if (!created.ok) {
    throw new Error(`cannot materialize hypothesis for ${item.id}: ${created.reason}`);
  }
  const hypothesis: Hypothesis = created.hypothesis;
  const context: VerifierContext = {
    projectRoot,
    authorization_reference: (item.scope_id as string) ?? "",
    artifactNamespace,
  };
  return runVerificationStage({
    hypothesis,
    registry,
    context,
    rubricProvider,
    candidate: {
      kind: item.kind,
      endpoint: item.endpoint as string,
      ...(!blank(item.parameter) ? { parameter_name: item.parameter as string } : {}),
      ...(!blank(item.location) ? { location: item.location as never } : {}),
      ...(item.evidence && item.evidence.length > 0
        ? { evidence_ids: item.evidence.map((e) => e.id) }
        : {}),
    },
  });
}

/**
 * Pull suspected findings and verify each, writing verdicts back with the full
 * claim / verify / evidence / If-Match write-back concurrency dance.
 */
export async function verifyFromReconLab(
  client: ReconLabClient,
  projectRoot: string,
  args: VerifyFromReconLabArgs,
  options: VerifyFromReconLabOptions = {},
): Promise<SyncRunSummary> {
  const workerId = args.workerId;
  const leaseSeconds = options.leaseSeconds ?? 900;
  const maxPre = options.maxPreconditionRetries ?? 3;
  const rubricProvider = options.rubricProvider ?? client.createRubricProvider();
  const registry = options.registry ?? createDefaultVerifierRegistry();
  const artifactNamespace = options.artifactNamespace ?? "opencode";
  const results: SyncItemResult[] = [];

  const safeRelease = async (id: string, leaseToken: string, reason: string): Promise<void> => {
    try {
      await client.release(id, { lease_token: leaseToken, reason });
    } catch {
      // Best effort: the lease may already be gone; never fail the run on release.
    }
  };

  // Re-claim to read the freshest item + etag and confirm the lease is still ours.
  const refreshItem = async (
    id: string,
    leaseToken: string,
  ): Promise<{ item: QueueItem; token: string } | { abandon: SyncItemResult }> => {
    try {
      const claim = await client.claim(id, { worker_id: workerId, lease_seconds: leaseSeconds });
      return { item: (claim.item ?? { id, kind: "", state: "" }) as QueueItem, token: claim.lease_token ?? leaseToken };
    } catch (error) {
      if (!(error instanceof ReconLabError)) {
        return { abandon: { id, outcome: "error", detail: `refresh:${String(error)}` } };
      }
      if (["ALREADY_CLAIMED", "LEASE_EXPIRED", "NO_LEASE", "ALREADY_FINAL", "TERMINAL_IMMUTABLE"].includes(error.code)) {
        return { abandon: { id, outcome: "lease_lost", detail: error.code } };
      }
      if (["OUT_OF_SCOPE", "SCOPE_EXPIRED"].includes(error.code)) {
        return { abandon: { id, outcome: "scope_void", detail: error.code } };
      }
      return { abandon: { id, outcome: "error", detail: `refresh:${error.code}` } };
    }
  };

  const writeBack = async (
    item: QueueItem,
    leaseToken: string,
    verdict: VerdictInput,
    evidenceRefs: EvidenceRef[],
  ): Promise<SyncItemResult> => {
    const id = item.id;
    let token = leaseToken;
    let attempts = 0;

    // (a) Freshest etag right before writing (and confirm the lease).
    const first = await refreshItem(id, token);
    if ("abandon" in first) return first.abandon;
    let fresh = first.item;
    let etag = (fresh.etag as string) ?? (item.etag as string) ?? "";
    token = first.token;

    for (;;) {
      attempts += 1;
      const body = buildVerdictBody(verdict, fresh, token);
      try {
        const res = await client.patchVerdict(id, etag, body);
        return {
          id,
          outcome: verdict.state as SyncItemOutcome,
          detail: "written",
          state_written: (res.item?.state as string) ?? verdict.state,
          evidence_ids: evidenceRefs.map((e) => e.id),
          attempts,
        };
      } catch (error) {
        if (!(error instanceof ReconLabError)) {
          await safeRelease(id, token, "write error");
          return { id, outcome: "error", detail: String(error), attempts };
        }
        // 412: content moved under us.
        if (error.code === "PRECONDITION_FAILED") {
          if (attempts >= maxPre) {
            await safeRelease(id, token, "precondition retries exhausted");
            return { id, outcome: "error", detail: "precondition_exhausted", attempts };
          }
          // Confirm the lease is still ours via heartbeat (also re-checks scope).
          try {
            await client.heartbeat(id, { lease_token: token, lease_seconds: leaseSeconds });
          } catch (hb) {
            if (hb instanceof ReconLabError) {
              if (["LEASE_EXPIRED", "NO_LEASE"].includes(hb.code)) {
                return { id, outcome: "lease_lost", detail: hb.code, attempts };
              }
              if (["SCOPE_EXPIRED", "OUT_OF_SCOPE"].includes(hb.code)) {
                return { id, outcome: "scope_void", detail: hb.code, attempts };
              }
              return { id, outcome: "error", detail: `heartbeat:${hb.code}`, attempts };
            }
            return { id, outcome: "error", detail: `heartbeat:${String(hb)}`, attempts };
          }
          // Re-GET fresh etag + merge, then retry.
          const again = await refreshItem(id, token);
          if ("abandon" in again) return { ...again.abandon, attempts };
          fresh = again.item;
          etag = (fresh.etag as string) ?? etag;
          token = again.token;
          continue;
        }
        // 428: missing If-Match (we always send it) - defensive single retry.
        if (error.code === "PRECONDITION_REQUIRED") {
          if (attempts >= maxPre) {
            await safeRelease(id, token, "precondition required loop");
            return { id, outcome: "error", detail: "precondition_required", attempts };
          }
          continue;
        }
        // Lease gone on any non-412 call => stop writing this item.
        if (["LEASE_EXPIRED", "NO_LEASE", "ALREADY_FINAL", "TERMINAL_IMMUTABLE"].includes(error.code)) {
          return { id, outcome: "lease_lost", detail: error.code, attempts };
        }
        if (["SCOPE_EXPIRED", "OUT_OF_SCOPE"].includes(error.code)) {
          return { id, outcome: "scope_void", detail: error.code, attempts };
        }
        if (error.code === "RUBRIC_VIOLATION") {
          await safeRelease(id, token, "platform rubric violation");
          return { id, outcome: "rubric_violation", detail: error.code, attempts };
        }
        await safeRelease(id, token, `write error ${error.code}`);
        return { id, outcome: "error", detail: error.code, attempts };
      }
    }
  };

  const processItem = async (item: QueueItem): Promise<SyncItemResult> => {
    const id = item.id;

    // 1. Claim.
    let leaseToken: string;
    let current: QueueItem = item;
    try {
      const claim = await client.claim(id, { worker_id: workerId, lease_seconds: leaseSeconds });
      leaseToken = claim.lease_token;
      current = (claim.item ?? item) as QueueItem;
    } catch (error) {
      if (!(error instanceof ReconLabError)) return { id, outcome: "error", detail: String(error) };
      if (["ALREADY_CLAIMED", "ALREADY_FINAL"].includes(error.code)) {
        return { id, outcome: "skipped_claimed", detail: error.code };
      }
      if (["OUT_OF_SCOPE", "SCOPE_EXPIRED"].includes(error.code)) {
        return { id, outcome: "scope_void", detail: error.code };
      }
      return { id, outcome: "error", detail: error.code };
    }

    // 2. Redirect-hop scope check (every hop before following).
    const hops = options.redirectHops ? options.redirectHops(current) : [];
    if (hops.length > 0) {
      try {
        const check = await client.checkScope({ urls: hops, target: current.target as string | undefined });
        if (!check.in_scope) {
          await safeRelease(id, leaseToken, "redirect hop out of scope");
          return { id, outcome: "scope_void", detail: "redirect_out_of_scope" };
        }
      } catch (error) {
        if (error instanceof ReconLabError && ["OUT_OF_SCOPE", "SCOPE_EXPIRED"].includes(error.code)) {
          await safeRelease(id, leaseToken, "redirect hop out of scope");
          return { id, outcome: "scope_void", detail: error.code };
        }
        await safeRelease(id, leaseToken, "scope check failed");
        return { id, outcome: "error", detail: error instanceof ReconLabError ? error.code : String(error) };
      }
    }

    // 3. Run verification (stage from steps 1-2) against the live rubric.
    let stage: VerificationStageResult;
    try {
      stage = options.runVerification
        ? await options.runVerification({ item: current, projectRoot, registry, rubricProvider })
        : await defaultRunVerification(current, projectRoot, registry, rubricProvider, artifactNamespace);
    } catch (error) {
      await safeRelease(id, leaseToken, "verification error");
      return { id, outcome: "error", detail: `verify_failed:${String(error)}` };
    }

    // 4. Interpret the stage result.
    if (!stage.ok && stage.code === "RUBRIC_VIOLATION") {
      await safeRelease(id, leaseToken, "local rubric violation");
      return {
        id,
        outcome: "rubric_violation",
        detail: stage.errors.map((e) => e.code).join(",") || "RUBRIC_VIOLATION",
      };
    }
    if (!stage.ok) {
      await safeRelease(id, leaseToken, stage.code);
      return { id, outcome: "error", detail: stage.code };
    }
    const judgment = stage.judgment;
    const outcome = stage.outcome;
    if (!TERMINAL_STATES.has(outcome)) {
      await safeRelease(id, leaseToken, "non-terminal verdict");
      return { id, outcome: "error", detail: `non_terminal_outcome:${outcome}` };
    }

    // 5. Heartbeat before write (keep-alive + re-check scope).
    if (options.heartbeatBeforeWrite !== false) {
      try {
        await client.heartbeat(id, { lease_token: leaseToken, lease_seconds: leaseSeconds });
      } catch (error) {
        if (error instanceof ReconLabError) {
          if (["LEASE_EXPIRED", "NO_LEASE"].includes(error.code)) {
            return { id, outcome: "lease_lost", detail: error.code };
          }
          if (["SCOPE_EXPIRED", "OUT_OF_SCOPE"].includes(error.code)) {
            return { id, outcome: "scope_void", detail: error.code };
          }
        }
        // Other heartbeat errors are non-fatal; the write-back refresh re-checks.
      }
    }

    // 6. Upload evidence, collect refs.
    const evidenceRefs: EvidenceRef[] = [];
    if (options.gatherEvidence) {
      let blobs: EvidenceUpload[];
      try {
        blobs = await options.gatherEvidence(current, stage);
      } catch (error) {
        await safeRelease(id, leaseToken, "evidence gather failed");
        return { id, outcome: "error", detail: `evidence_gather:${String(error)}` };
      }
      for (const blob of blobs) {
        try {
          const up = await client.uploadEvidence(blob.content, {
            kind: blob.kind,
            note: blob.note,
            content_type: blob.content_type,
            filename: blob.filename,
          });
          evidenceRefs.push({ id: up.id, sha256: up.sha256 });
        } catch (error) {
          await safeRelease(id, leaseToken, "evidence upload failed");
          return {
            id,
            outcome: "error",
            detail: `evidence_upload:${error instanceof ReconLabError ? error.code : String(error)}`,
          };
        }
      }
    }

    // 7. Build verdict and run the write-back dance.
    const verdict: VerdictInput = {
      state: outcome,
      verdict_note: judgment.rationale,
      ...(judgment.reason_code ? { reason_code: judgment.reason_code } : {}),
      ...(judgment.confidence !== undefined ? { confidence: judgment.confidence } : {}),
      ...(judgment.reproduction_steps && judgment.reproduction_steps.length > 0
        ? { reproduction_steps: judgment.reproduction_steps }
        : {}),
      evidence: evidenceRefs,
      ...(judgment.checks && judgment.checks.length > 0
        ? { checks: judgment.checks.map((c) => ({ id: c, state: "pass" })) }
        : {}),
      ...(!blank(current.location) ? { location: current.location as string } : {}),
      ...(!blank(current.parameter) ? { parameter: current.parameter as string } : {}),
    };

    return writeBack(current, leaseToken, verdict, evidenceRefs);
  };

  const listed = await client.listQueue({
    state: args.state ?? "suspected",
    ...(args.kind ? { kind: args.kind } : {}),
    ...(args.limit ? { limit: args.limit } : {}),
  });
  for (const item of listed.items) {
    results.push(await processItem(item));
  }

  return { worker_id: workerId, processed: results.length, results };
}
