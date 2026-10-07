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
 * Freshness is a CLEAN READ: GET /api/verification/queue/{id} (contract v2) is a
 * read-only preflight that never touches the lease or advances the etag. We use
 * it once right before PATCH (the repro can take minutes) to get the If-Match etag
 * and confirm the lease is still ours, and to chase a superseded_by successor. A
 * 412 on the PATCH carries only the new etag (ETag header / data.current_etag),
 * so we simply swap it in and retry once; lease / terminal / superseded outcomes
 * all come from a 409 on the PATCH, never a 412. `claim` is never used as a read:
 * it is a write that renews the lease and may rotate the lease_token, so it is
 * reserved for (re)acquiring a lease and its response token + etag always
 * overwrite our locals.
 */

export type SyncItemOutcome =
  | "confirmed"
  | "rejected"
  | "inconclusive"
  | "rubric_violation"
  | "skipped_claimed"
  | "scope_void"
  | "lease_lost"
  | "superseded"
  | "abandoned"
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
 * claim / verify / evidence / clean-read + If-Match write-back concurrency dance.
 */
export async function verifyFromReconLab(
  client: ReconLabClient,
  projectRoot: string,
  args: VerifyFromReconLabArgs,
  options: VerifyFromReconLabOptions = {},
): Promise<SyncRunSummary> {
  const workerId = args.workerId;
  const leaseSeconds = options.leaseSeconds ?? 900;
  const maxPre = options.maxPreconditionRetries ?? 1;
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

  type FreshRead =
    | { item: QueueItem; etag: string; leaseOk: boolean }
    | { abandon: SyncItemResult };

  // Clean read-only preflight: GET the item for the freshest etag + authoritative
  // lease state. Never renews the lease and never rotates the token (unlike claim).
  const freshRead = async (id: string, preferEtag: string): Promise<FreshRead> => {
    try {
      const res = await client.getQueueItem(id);
      const item = (res.item ?? { id, kind: "", state: "" }) as QueueItem;
      const etag = res.etag ?? (item.etag as string | undefined) ?? preferEtag ?? "";
      const lease = (item.lease ?? {}) as { active?: boolean; holder?: string };
      const leaseOk = lease.active === true && lease.holder === workerId;
      return { item, etag, leaseOk };
    } catch (error) {
      if (!(error instanceof ReconLabError)) {
        return { abandon: { id, outcome: "error", detail: `read:${String(error)}` } };
      }
      return { abandon: { id, outcome: "error", detail: `read:${error.code}` } };
    }
  };

  const writeBack = async (
    item: QueueItem,
    leaseToken: string,
    verdict: VerdictInput,
    evidenceRefs: EvidenceRef[],
  ): Promise<SyncItemResult> => {
    const id = item.id;
    const token = leaseToken; // a clean read never rotates the token; only claim does.
    let attempts = 0;

    // (a) Pre-write freshness: a clean read right before PATCH (repro may have
    // taken minutes). Resolve which record we will actually write to and confirm
    // the lease is still ours.
    const first = await freshRead(id, (item.etag as string) ?? "");
    if ("abandon" in first) return first.abandon;

    // A GET returns a superseded / retired record normally (not 409); never PATCH
    // onto it. Instead chase the successor id and only write if THAT record is
    // alive and its lease is ours. We never fabricate a state-machine transition
    // or a supersedes POST in the adapter.
    let writeId = id;
    let fresh = first.item;
    let etag = first.etag || (item.etag as string) || "";
    let leaseOk = first.leaseOk;

    const supersededBy = first.item.superseded_by;
    if (typeof supersededBy === "string" && supersededBy !== "") {
      const succ = await freshRead(supersededBy, "");
      if ("abandon" in succ) {
        return { id, outcome: "superseded", detail: `superseded_by:${supersededBy}:successor_unavailable` };
      }
      const succState = typeof succ.item.state === "string" ? succ.item.state : "";
      const succSuperseded =
        typeof succ.item.superseded_by === "string" && succ.item.superseded_by !== "";
      const succAlive = succState !== "" && !TERMINAL_STATES.has(succState) && !succSuperseded;
      if (!(succAlive && succ.leaseOk)) {
        // Successor is dead / terminal / superseded, or not leased to us: abandon.
        return { id, outcome: "superseded", detail: `superseded_by:${supersededBy}` };
      }
      // Successor is alive and the lease is ours: retarget the write onto it.
      writeId = supersededBy;
      fresh = succ.item;
      etag = succ.etag;
      leaseOk = succ.leaseOk;
    }

    if (!leaseOk) {
      return { id, outcome: "lease_lost", detail: "lease_not_held" };
    }

    let precond = 0;
    for (;;) {
      attempts += 1;
      const body = buildVerdictBody(verdict, fresh, token);
      try {
        const res = await client.patchVerdict(writeId, etag, body);
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
          await safeRelease(writeId, token, "write error");
          return { id, outcome: "error", detail: String(error), attempts };
        }
        // 412: the response carries ONLY the new etag (ETag header /
        // data.current_etag) -- no lease or state info -- so this branch does
        // exactly one thing: swap in that etag and retry the PATCH once. A repeat
        // 412 means live contention: abandon the item back to the queue (release
        // the lease) and move on. Every lease / terminal / superseded decision
        // comes from a 409 on the PATCH below, never from a 412.
        if (error.code === "PRECONDITION_FAILED") {
          const nextEtag =
            error.etag ??
            (typeof error.data?.current_etag === "string" ? (error.data.current_etag as string) : undefined);
          if (!nextEtag) {
            await safeRelease(writeId, token, "precondition without etag");
            return { id, outcome: "error", detail: "precondition_no_etag", attempts };
          }
          if (precond >= maxPre) {
            await safeRelease(writeId, token, "precondition conflict, back to queue");
            return { id, outcome: "abandoned", detail: "precondition_conflict", attempts };
          }
          precond += 1;
          etag = nextEtag;
          continue;
        }
        // 428: missing If-Match (we always send one) - single defensive retry.
        if (error.code === "PRECONDITION_REQUIRED") {
          if (precond >= maxPre) {
            await safeRelease(writeId, token, "precondition required loop");
            return { id, outcome: "error", detail: "precondition_required", attempts };
          }
          precond += 1;
          continue;
        }
        // Lease gone (409) => stop writing. Do NOT re-claim this item in this run.
        if (["LEASE_EXPIRED", "NO_LEASE"].includes(error.code)) {
          return { id, outcome: "lease_lost", detail: error.code, attempts };
        }
        // 409 terminal / superseded under us => minimal abandon. PROVISIONAL: the
        // ReconLab dev is still confirming whether etag is recomputed on supersede,
        // which decides if this path is even reachable. Keep this logic minimal.
        if (["TERMINAL_IMMUTABLE", "ALREADY_SUPERSEDED", "ALREADY_FINAL"].includes(error.code)) {
          return { id, outcome: "superseded", detail: error.code, attempts };
        }
        if (["SCOPE_EXPIRED", "OUT_OF_SCOPE"].includes(error.code)) {
          return { id, outcome: "scope_void", detail: error.code, attempts };
        }
        if (error.code === "RUBRIC_VIOLATION") {
          await safeRelease(writeId, token, "platform rubric violation");
          return { id, outcome: "rubric_violation", detail: error.code, attempts };
        }
        await safeRelease(writeId, token, `write error ${error.code}`);
        return { id, outcome: "error", detail: error.code, attempts };
      }
    }
  };

  const processItem = async (item: QueueItem): Promise<SyncItemResult> => {
    const id = item.id;

    // 1. Claim (acquire the lease). The response is authoritative: always overwrite
    //    our lease_token + etag from it, because a (re)claim may rotate the token.
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
        // Other heartbeat errors are non-fatal; the pre-write clean read re-checks.
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
