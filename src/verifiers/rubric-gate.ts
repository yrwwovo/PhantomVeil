import type { Rubric } from "./rubric-provider.ts";
import type { VerificationJudgment } from "./verifier-plugin.ts";

/**
 * Shared ReconLab rubric enforcement gate.
 *
 * This mirrors ReconLab performing enforcement server-side, uniformly, instead
 * of each verifier plugin re-implementing verdict thresholds. It is applied once
 * in the verification stage, not inside the plugins.
 *
 * It ONLY checks the tunable GATES carried by the rubric row: min_confidence,
 * required confirm_checks, required confirm_evidence_kinds, and the allowed
 * reason_code vocabulary. A plugin DETECTION logic is never moved here.
 */

export type RubricIssueCode =
  | "confidence_below_min"
  | "missing_check"
  | "missing_evidence_kind"
  | "reason_code_out_of_vocab"
  | "unenforced_legacy_judgment";

export interface RubricIssue {
  code: RubricIssueCode;
  /** The rubric rule (kind) this issue is about. */
  rule: string;
  message: string;
  detail?: Record<string, unknown>;
}

export interface RubricEvaluation {
  rule: string;
  enforced: boolean;
  /** True only when a confirmed verdict must NOT be written (hard violation). */
  blocked: boolean;
  /** Hard violations (rubric.enforce === true). Mirrors the platform 422 errors[]. */
  errors: RubricIssue[];
  /** Advisory issues that do not block. */
  warnings: RubricIssue[];
}

/**
 * A judgment is "gate-aware" once it declares any of the gate inputs. Legacy
 * judgments that declare none cannot be meaningfully enforced; they are allowed
 * through with an advisory warning on enforced kinds (keeps older callers and
 * fixtures working while surfacing the gap).
 */
function isGateAware(judgment: VerificationJudgment): boolean {
  return (
    judgment.confidence !== undefined ||
    judgment.checks !== undefined ||
    judgment.evidence_kinds !== undefined
  );
}

function evaluateConfirmed(rubric: Rubric, judgment: VerificationJudgment): RubricIssue[] {
  const issues: RubricIssue[] = [];

  const confidence = typeof judgment.confidence === "number" ? judgment.confidence : 0;
  if (confidence < rubric.min_confidence) {
    issues.push({
      code: "confidence_below_min",
      rule: rubric.kind,
      message: "confidence " + confidence + " is below the rubric minimum " + rubric.min_confidence,
      detail: { required: rubric.min_confidence, got: confidence },
    });
  }

  const checks = Array.isArray(judgment.checks) ? judgment.checks : [];
  for (const required of rubric.confirm_checks) {
    if (!checks.includes(required)) {
      issues.push({
        code: "missing_check",
        rule: rubric.kind,
        message: "required confirm check not satisfied: " + required,
        detail: { required, satisfied: checks },
      });
    }
  }

  if (rubric.confirm_evidence_kinds.length > 0) {
    const kinds = Array.isArray(judgment.evidence_kinds) ? judgment.evidence_kinds : [];
    if (!kinds.some((k) => rubric.confirm_evidence_kinds.includes(k))) {
      issues.push({
        code: "missing_evidence_kind",
        rule: rubric.kind,
        message: "no evidence of a rubric-required kind is present",
        detail: { required: rubric.confirm_evidence_kinds, got: kinds },
      });
    }
  }

  return issues;
}

/**
 * Evaluate a judgment against its rubric row. Does not mutate anything; the
 * verification stage uses `blocked` to decide whether to write a confirmed
 * transition, and surfaces errors[]/warnings[] either way.
 */
export function evaluateRubric(
  rubric: Rubric,
  judgment: VerificationJudgment,
): RubricEvaluation {
  const errors: RubricIssue[] = [];
  const warnings: RubricIssue[] = [];

  if (judgment.outcome === "confirmed") {
    if (!isGateAware(judgment)) {
      if (rubric.enforce) {
        warnings.push({
          code: "unenforced_legacy_judgment",
          rule: rubric.kind,
          message:
            "confirmed judgment declares no confidence/checks/evidence_kinds; rubric gates not enforced",
        });
      }
    } else {
      const issues = evaluateConfirmed(rubric, judgment);
      if (issues.length > 0) {
        if (rubric.enforce) {
          errors.push(...issues);
        } else {
          warnings.push(...issues);
        }
      }
    }
  } else if (judgment.reason_code !== undefined) {
    // Advisory only: reason_code vocabulary can drift, so never block on it.
    const vocab =
      judgment.outcome === "rejected" ? rubric.reject_reasons : rubric.inconclusive_triggers;
    if (vocab.length > 0 && !vocab.includes(judgment.reason_code)) {
      warnings.push({
        code: "reason_code_out_of_vocab",
        rule: rubric.kind,
        message:
          "reason_code '" + judgment.reason_code + "' is not in the rubric vocabulary for " + judgment.outcome,
        detail: { reason_code: judgment.reason_code, allowed: vocab },
      });
    }
  }

  const blocked = judgment.outcome === "confirmed" && errors.length > 0;
  return { rule: rubric.kind, enforced: rubric.enforce, blocked, errors, warnings };
}
