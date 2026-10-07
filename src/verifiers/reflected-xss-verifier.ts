import type { BrowserProof } from "../../capabilities/web/xss-execution-verifier.ts";
import { DockerXssVerifier } from "../../capabilities/web/xss-execution-verifier.ts";
import type { EvidenceRecord } from "../evidence/evidence-store.ts";
import { saveXssVerification } from "../evidence/xss-verification-record.ts";
import type {
  VerificationJudgment,
  VerifierCandidate,
  VerifierContext,
  VerifierPlugin,
  VerifierRunResult,
} from "./verifier-plugin.ts";

/**
 * One execution attempt: an http_exchange evidence whose captured response body
 * reflects the payload, the marker the in-page script calls back with, and the
 * exact <script> textContent expected to appear (and run) in the isolated
 * browser. The control uses a benign marker that must NOT execute; the trials
 * carry the real payloads that should execute iff the endpoint is vulnerable.
 */
export interface ReflectedXssTrialInput {
  record: EvidenceRecord;
  marker: string;
  script: string;
}

export interface ReflectedXssVerifyInput {
  control: ReflectedXssTrialInput;
  trials: ReflectedXssTrialInput[];
}

export interface ReflectedXssSignals {
  verifier_ready: boolean;
  control: BrowserProof | null;
  trials: BrowserProof[];
}

const inconclusive = (
  rationale: string,
  limitations: string[] = [],
): VerificationJudgment => ({
  outcome: "inconclusive",
  rationale,
  reproduction_steps: [],
  limitations,
  evidence_ids: [],
});

/**
 * COMPLETED judgment rule. Pure function: it maps the isolated-browser
 * execution proofs to a confirmed / rejected / inconclusive verdict, with no
 * IO so it is fully unit-testable.
 *
 * Decision order (conservative on purpose):
 *   - no control or no trials                 -> inconclusive
 *   - any proof not network-isolated          -> inconclusive (untrustworthy)
 *   - control itself executed                 -> inconclusive (harness noise)
 *   - no trial was delivered                  -> inconclusive (cannot observe)
 *   - a delivered trial executed              -> confirmed (reproduced)
 *   - trials delivered but none executed      -> rejected (encoded / escaped)
 */
export function judgeReflectedXssProofs(
  control: BrowserProof | null,
  trials: BrowserProof[],
): VerificationJudgment {
  const limitations: string[] = [];
  if (!control || trials.length === 0) {
    return inconclusive("执行验证器未产出对照组或试验组证明，无法判定");
  }
  const allProofs = [control, ...trials];
  if (allProofs.some((proof) => proof.network_isolated !== true)) {
    return inconclusive("验证环境的网络隔离未成立，拒绝据此下结论", [
      "存在未处于网络隔离状态的验证，结果不可信",
    ]);
  }
  if (control.executed === true) {
    return inconclusive("对照组（无害标记）也触发了执行，判定器无法区分真实漏洞与环境噪声", [
      "对照组自发执行，疑似环境误报",
    ]);
  }
  const deliveredTrials = trials.filter((trial) => trial.delivered === true);
  if (deliveredTrials.length === 0) {
    return inconclusive("试验载荷均未成功投递到隔离浏览器，无法观察是否执行", [
      "试验载荷投递失败",
    ]);
  }
  const executed = deliveredTrials.some((trial) => trial.executed === true);
  if (executed) {
    return {
      outcome: "confirmed",
      confidence: 95,
      checks: ["reproduce", "control"],
      evidence_kinds: ["http_exchange"],
      rationale: "对照组未执行，而试验载荷在网络隔离的浏览器中成功执行，确认存在反射型 XSS",
      reproduction_steps: [
        "在网络隔离的浏览器中加载目标响应，对照组的无害标记未被执行",
        "以同一端点、同一参数注入反射型 XSS 载荷后，脚本在隔离浏览器中被执行并回调唯一标记",
        "对照组未执行、试验组执行，形成可复现的对比证据",
      ],
      limitations,
      evidence_ids: [],
    };
  }
  return {
    outcome: "rejected",
    rationale: "试验载荷已成功投递但均未在隔离浏览器中执行（通常因输出被编码或转义），据此否定该候选",
    reproduction_steps: [],
    limitations,
    evidence_ids: [],
  };
}

function isVerifyInput(value: unknown): value is ReflectedXssVerifyInput {
  if (!value || typeof value !== "object") return false;
  const input = value as ReflectedXssVerifyInput;
  const validTrial = (trial: unknown): trial is ReflectedXssTrialInput =>
    !!trial && typeof trial === "object" &&
    typeof (trial as ReflectedXssTrialInput).marker === "string" &&
    typeof (trial as ReflectedXssTrialInput).script === "string" &&
    !!(trial as ReflectedXssTrialInput).record;
  return validTrial(input.control) && Array.isArray(input.trials) &&
    input.trials.length > 0 && input.trials.every(validTrial);
}

/**
 * First concrete verifier plugin. It implements the generic VerifierPlugin
 * interface; the execution itself is delegated to the existing Docker-isolated
 * browser verifier, and the verdict logic lives in judgeReflectedXssProofs.
 */
export class ReflectedXssVerifier implements VerifierPlugin<ReflectedXssSignals> {
  readonly id = "reflected-xss";
  readonly vulnerability = "Reflected XSS";
  readonly owaspCategory = "A03:2021 Injection";

  private readonly docker: DockerXssVerifier;

  constructor(docker: DockerXssVerifier = new DockerXssVerifier()) {
    this.docker = docker;
  }

  appliesTo(candidate: VerifierCandidate): boolean {
    return (
      !!candidate &&
      candidate.kind === "reflected_xss" &&
      typeof candidate.endpoint === "string" &&
      candidate.endpoint.length > 0
    );
  }

  async verify(
    candidate: VerifierCandidate,
    context: VerifierContext,
  ): Promise<VerifierRunResult<ReflectedXssSignals>> {
    const evidenceIds = candidate.evidence_ids ?? [];
    const input = candidate.metadata?.["reflected_xss_verify"];
    if (!isVerifyInput(input)) {
      return {
        ok: false,
        code: "MISSING_VERIFY_INPUT",
        reason: "缺少执行验证所需的对照组/试验组证据（control + trials）",
        evidence_ids: evidenceIds,
      };
    }
    if (!(await this.docker.ready())) {
      return {
        ok: false,
        code: "VERIFIER_UNAVAILABLE",
        reason: "隔离浏览器验证镜像不可用，未执行验证",
        evidence_ids: evidenceIds,
        signals: { verifier_ready: false, control: null, trials: [] },
      };
    }

    const control = await this.docker.verify(input.control.record, input.control.marker, input.control.script);
    const trials: BrowserProof[] = [];
    for (const trial of input.trials) {
      const proof = await this.docker.verify(trial.record, trial.marker, trial.script);
      if (proof) trials.push(proof);
    }

    const signals: ReflectedXssSignals = { verifier_ready: true, control, trials };
    let verificationId: string | undefined;
    if (control && candidate.hypothesis_id && candidate.parameter_name) {
      try {
        const outcome = judgeReflectedXssProofs(control, trials).outcome;
        const saved = await saveXssVerification(context.projectRoot, {
          task_id: candidate.hypothesis_id,
          hypothesis_id: candidate.hypothesis_id,
          endpoint: candidate.endpoint,
          parameter_name: candidate.parameter_name,
          outcome: outcome === "confirmed" ? "reproduced" : "inconclusive",
          control_evidence_id: input.control.record.evidence_id,
          control_proof: control,
          trials: input.trials.map((trial, index) => ({
            evidence_id: trial.record.evidence_id,
            payload_sha256: trial.record.integrity.payload_sha256,
            marker: trial.marker,
            script: trial.script,
            proof: trials[index] ?? control,
          })),
          limitations: [],
        });
        verificationId = saved.record.verification_id;
      } catch {
        // Best effort: a persistence failure must not change the verdict.
      }
    }

    return {
      ok: true,
      code: "VERIFICATION_RUN",
      reason: "隔离浏览器执行验证完成",
      signals,
      evidence_ids: evidenceIds,
      verification_id: verificationId,
    };
  }

  judge(runResult: VerifierRunResult<ReflectedXssSignals>): VerificationJudgment {
    if (!runResult.ok || !runResult.signals) {
      return inconclusive(runResult.reason || "验证未成功执行，无法判定");
    }
    const verdict = judgeReflectedXssProofs(runResult.signals.control, runResult.signals.trials);
    return { ...verdict, evidence_ids: runResult.evidence_ids };
  }
}
