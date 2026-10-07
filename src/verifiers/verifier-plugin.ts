import type { HypothesisStatus, ParameterLocation } from "../hypotheses/hypothesis-manager.ts";

/**
 * Generic vulnerability-verifier plugin framework.
 *
 * Every vulnerability type (reflected XSS, SQLi, SSRF, IDOR, broken access
 * control, ...) is implemented as a plugin that declares four things:
 *   1. applicability  -> appliesTo(candidate)
 *   2. verification actions -> verify(candidate, context)
 *   3. judgment rule -> judge(runResult)
 *   4. output -> the judgment is mapped onto the shared hypothesis state
 *      machine (suspected -> testing -> confirmed/rejected/inconclusive).
 *
 * The discovery -> verify -> report chain and the evidence / authorization /
 * budget layers stay shared; adding a new vulnerability only means adding a
 * new plugin file and registering it. Nothing in the core pipeline changes.
 */

export type VerificationOutcome = "confirmed" | "rejected" | "inconclusive";

/** A verifiable finding produced by the discovery stage. */
export interface VerifierCandidate {
  /** Vulnerability class key, e.g. "reflected_xss". Used for applicability. */
  kind: string;
  /** Normalized endpoint (no query/credentials) the candidate lives on. */
  endpoint: string;
  /** Affected parameter, when the class is parameter-scoped. */
  parameter_name?: string;
  /** ReconLab v2: where the affected parameter sits (query/body/header/cookie/path). */
  location?: ParameterLocation;
  /** Linked hypothesis to transition once a verdict is reached. */
  hypothesis_id?: string;
  /** Supporting evidence ids already attached to the hypothesis. */
  evidence_ids?: string[];
  /** Class-specific inputs the plugin needs to run (kept opaque here). */
  metadata?: Record<string, unknown>;
}

/** Shared services and scope a plugin runs inside. */
export interface VerifierContext {
  projectRoot: string;
  authorization_reference: string;
  artifactNamespace: "opencode" | "hermes";
}

/** The plugin's verdict about a candidate. */
export interface VerificationJudgment {
  outcome: VerificationOutcome;
  /** Human-readable Chinese explanation of why this verdict was reached. */
  rationale: string;
  /** Steps that reproduce a confirmed finding (empty unless confirmed). */
  reproduction_steps: string[];
  /** Caveats that bound the verdict. */
  limitations: string[];
  /**
   * ReconLab v2: optional structured reason code for a rejected/inconclusive
   * verdict. Allowed values come from the ReconLab rubric API (validated in a
   * later step), so this stays a free-form optional string here.
   */
  reason_code?: string;
  /** Evidence ids backing the verdict. */
  evidence_ids: string[];
}

/** Raw result of running the verification actions, consumed by judge(). */
export interface VerifierRunResult<TSignals = unknown> {
  ok: boolean;
  code: string;
  reason: string;
  /** Class-specific collected data the judge() turns into a verdict. */
  signals?: TSignals;
  evidence_ids: string[];
  verification_id?: string;
}

export interface VerifierPlugin<TSignals = unknown> {
  readonly id: string;
  readonly vulnerability: string;
  /** OWASP Top 10 category this plugin maps to, used as list skeleton. */
  readonly owaspCategory?: string;
  appliesTo(candidate: VerifierCandidate): boolean;
  verify(
    candidate: VerifierCandidate,
    context: VerifierContext,
  ): Promise<VerifierRunResult<TSignals>>;
  judge(runResult: VerifierRunResult<TSignals>): VerificationJudgment;
}

const OUTCOME_TO_STATUS: Record<VerificationOutcome, HypothesisStatus> = {
  confirmed: "confirmed",
  rejected: "rejected",
  inconclusive: "inconclusive",
};

export function outcomeToHypothesisStatus(outcome: VerificationOutcome): HypothesisStatus {
  return OUTCOME_TO_STATUS[outcome];
}

/**
 * Pure planner: given the current hypothesis status and a verdict outcome,
 * return the ordered sequence of status transitions that honor the hypothesis
 * state machine. Returns [] when no (legal) change applies, e.g. the
 * hypothesis is already terminal or already in the requested resting state.
 *
 * Because the state machine forbids jumping straight from suspected to
 * confirmed/rejected, a real verification always passes through "testing".
 */
export function planHypothesisTransitions(
  current: HypothesisStatus,
  outcome: VerificationOutcome,
): HypothesisStatus[] {
  const target = outcomeToHypothesisStatus(outcome);
  if (current === "confirmed" || current === "rejected") {
    return []; // terminal: never re-open
  }
  if (current === "testing") {
    return [target];
  }
  if (current === "inconclusive") {
    // inconclusive -> inconclusive is not a legal self-transition.
    if (target === "inconclusive") return [];
    return ["testing", target];
  }
  // current === "suspected"
  return ["testing", target];
}
