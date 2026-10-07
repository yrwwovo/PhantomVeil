import type { Hypothesis, HypothesisStatus } from "../hypotheses/hypothesis-manager.ts";
import { transitionHypothesis } from "../hypotheses/hypothesis-manager.ts";
import type {
  VerificationJudgment,
  VerifierCandidate,
  VerifierContext,
} from "../verifiers/verifier-plugin.ts";
import { planHypothesisTransitions } from "../verifiers/verifier-plugin.ts";
import type { VerifierRegistry } from "../verifiers/verifier-registry.ts";

/**
 * Verification stage of the main chain.
 *
 * Discovery hands us a hypothesis (resting at "suspected"). This stage turns it
 * into a VerifierCandidate, lets the registry auto-select the one applicable
 * plugin by candidate.kind, runs verify -> judge, then writes the verdict back
 * onto the hypothesis through the real state machine (passing through "testing",
 * honoring the confirm requirements). The stage never knows about any specific
 * vulnerability class; adding a plugin needs no change here.
 */

export interface VerificationCandidateInput {
  /** Vulnerability class key used to route to a plugin, e.g. "open_redirect". */
  kind: string;
  /** Overrides the endpoint derived from the hypothesis when provided. */
  endpoint?: string;
  parameter_name?: string;
  /** Plugin-specific verify inputs (e.g. XSS proofs, redirect samples). */
  metadata?: Record<string, unknown>;
  /** Extra evidence ids beyond those already on the hypothesis. */
  evidence_ids?: string[];
}

export interface VerificationStageInput {
  hypothesis: Hypothesis;
  registry: VerifierRegistry;
  context: VerifierContext;
  candidate: VerificationCandidateInput;
  now?: () => Date;
}

export type VerificationStageResult =
  | {
      ok: true;
      code: "VERIFIED";
      plugin_id: string;
      vulnerability: string;
      outcome: VerificationJudgment["outcome"];
      judgment: VerificationJudgment;
      transitions_applied: HypothesisStatus[];
      hypothesis: Hypothesis;
    }
  | {
      ok: false;
      code: "NO_VERIFIER" | "AMBIGUOUS_VERIFIER";
      reason: string;
      candidate_kind: string;
      plugin_ids?: string[];
      hypothesis: Hypothesis;
    }
  | {
      ok: false;
      code: "TRANSITION_FAILED";
      reason: string;
      plugin_id: string;
      vulnerability: string;
      outcome: VerificationJudgment["outcome"];
      judgment: VerificationJudgment;
      transitions_applied: HypothesisStatus[];
      hypothesis: Hypothesis;
    };

function buildCandidate(input: VerificationStageInput): VerifierCandidate {
  const { hypothesis, candidate } = input;
  const endpoint =
    candidate.endpoint ??
    hypothesis.candidate_identity?.endpoint ??
    hypothesis.target_url;
  const parameter_name =
    candidate.parameter_name ?? hypothesis.candidate_identity?.parameter_name;
  const existingEvidence = hypothesis.evidence.map((ref) => ref.evidence_id);
  const evidence_ids = [
    ...new Set([...existingEvidence, ...(candidate.evidence_ids ?? [])]),
  ];
  return {
    kind: candidate.kind,
    endpoint,
    ...(parameter_name ? { parameter_name } : {}),
    hypothesis_id: hypothesis.hypothesis_id,
    evidence_ids,
    ...(candidate.metadata ? { metadata: candidate.metadata } : {}),
  };
}

export async function runVerificationStage(
  input: VerificationStageInput,
): Promise<VerificationStageResult> {
  const { hypothesis, registry, context, now } = input;
  const candidate = buildCandidate(input);
  const run = await registry.run(candidate, context);

  if (!run.ok) {
    return {
      ok: false,
      code: run.code,
      reason: run.reason,
      candidate_kind: run.candidate_kind,
      ...(run.plugin_ids ? { plugin_ids: run.plugin_ids } : {}),
      hypothesis,
    };
  }

  const { judgment, plugin_id, vulnerability } = run;
  const plan = planHypothesisTransitions(hypothesis.status, judgment.outcome);
  const target = judgment.outcome; // resting state the plan drives toward

  let current = hypothesis;
  const applied: HypothesisStatus[] = [];

  for (const step of plan) {
    const isFinal = step === target;
    const transition = await transitionHypothesis(
      current,
      {
        to: step,
        reason: isFinal
          ? judgment.rationale
          : `进入验证（${plugin_id}）`,
        // Reproduction steps matter on the confirming step; dedup is handled
        // by the manager. Evidence already attached to the hypothesis is reused.
        ...(isFinal && judgment.reproduction_steps.length > 0
          ? { reproduction_steps: judgment.reproduction_steps }
          : {}),
      },
      now ? { now } : {},
    );
    if (!transition.ok) {
      return {
        ok: false,
        code: "TRANSITION_FAILED",
        reason: transition.reason,
        plugin_id,
        vulnerability,
        outcome: judgment.outcome,
        judgment,
        transitions_applied: applied,
        hypothesis: current,
      };
    }
    current = transition.hypothesis;
    applied.push(step);
  }

  return {
    ok: true,
    code: "VERIFIED",
    plugin_id,
    vulnerability,
    outcome: judgment.outcome,
    judgment,
    transitions_applied: applied,
    hypothesis: current,
  };
}
