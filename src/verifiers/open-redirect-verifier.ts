import type { RedirectProbeSample } from "../../capabilities/web/redirect-observation.ts";
import type {
  VerificationJudgment,
  VerifierCandidate,
  VerifierContext,
  VerifierPlugin,
  VerifierRunResult,
} from "./verifier-plugin.ts";

/**
 * Second concrete verifier plugin, built to the same interface as the reflected
 * XSS one. It needs no sandboxed browser: the "verification action" is a set of
 * authorized GETs (one in-site control + several distinct off-site trials)
 * captured upstream through the restricted HTTP layer and handed in as samples.
 * The brain is the pure judgeOpenRedirectProbes() below.
 */

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export interface OpenRedirectVerifyInput {
  source_url: string;
  control: RedirectProbeSample;
  trials: RedirectProbeSample[];
}

export interface OpenRedirectSignals {
  source_url: string;
  control: RedirectProbeSample | null;
  trials: RedirectProbeSample[];
}

function locationOf(sample: RedirectProbeSample): string | undefined {
  const value = Object.entries(sample.headers).find(
    ([name]) => name.toLowerCase() === "location",
  )?.[1];
  return Array.isArray(value) ? value[0] : value;
}

/** True when the sample's 3xx Location resolves to an off-site URL. */
function redirectsOffsite(sample: RedirectProbeSample, sourceOrigin: string): boolean {
  if (!REDIRECT_STATUSES.has(sample.status)) return false;
  const location = locationOf(sample);
  if (typeof location !== "string") return false;
  try {
    const destination = new URL(location, sample.request_url);
    return ["http:", "https:"].includes(destination.protocol) &&
      destination.origin !== sourceOrigin;
  } catch {
    return false;
  }
}

/** True when the off-site Location matches exactly the destination we asked for. */
function honorsOffsiteTarget(sample: RedirectProbeSample, sourceOrigin: string): boolean {
  if (!redirectsOffsite(sample, sourceOrigin)) return false;
  try {
    const destination = new URL(locationOf(sample) as string, sample.request_url);
    const expected = new URL(sample.expected_destination);
    return expected.origin !== sourceOrigin && destination.href === expected.href;
  } catch {
    return false;
  }
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
 * COMPLETED judgment rule (pure, no IO):
 *   - no control, or fewer than two trials      -> inconclusive
 *   - invalid source origin                      -> inconclusive
 *   - control itself redirects off-site          -> inconclusive (endpoint
 *     redirects regardless of input; cannot attribute to the parameter)
 *   - >= 2 distinct off-site trial targets honored exactly -> confirmed
 *   - trials answered but none honored off-site  -> rejected (sanitized/ignored)
 *   - otherwise (only one honored, no responses) -> inconclusive
 */
export function judgeOpenRedirectProbes(
  sourceUrl: string,
  control: RedirectProbeSample | null,
  trials: RedirectProbeSample[],
): VerificationJudgment {
  if (!control || trials.length < 2) {
    return inconclusive("开放重定向验证需要一个站内对照组和至少两个不同的站外试验目标");
  }
  let sourceOrigin: string;
  try {
    sourceOrigin = new URL(sourceUrl).origin;
  } catch {
    return inconclusive("源地址无效，无法判定");
  }
  if (redirectsOffsite(control, sourceOrigin)) {
    return inconclusive("对照组（站内目标）也跳到了站外，端点疑似无条件外跳，无法归因到该参数", [
      "对照组发生站外跳转",
    ]);
  }
  const honored = trials.filter((trial) => honorsOffsiteTarget(trial, sourceOrigin));
  const distinctHonored = new Set(honored.map((trial) => new URL(trial.expected_destination).href));
  if (distinctHonored.size >= 2) {
    return {
      outcome: "confirmed",
      confidence: 90,
      checks: ["reproduce", "control"],
      evidence_kinds: ["http_exchange"],
      rationale: "对照组未外跳，而两个不同的站外目标都被原样跟随为 3xx 跳转，确认存在开放重定向",
      reproduction_steps: [
        "以站内目标请求该参数时，响应未跳转到站外（对照组）",
        "分别以两个不同的站外地址作为该参数值请求，响应均返回 3xx 且 Location 精确指向对应站外地址",
        "对照组不外跳、两个不同站外目标都被跟随，排除固定跳转，确认任意外跳",
      ],
      limitations: [],
      evidence_ids: [],
    };
  }
  const answered = trials.filter((trial) => trial.status > 0);
  if (answered.length === trials.length && honored.length === 0) {
    return {
      outcome: "rejected",
      rationale: "试验请求均有响应，但没有一个站外目标被跟随（通常因重定向目标被校验或忽略），据此否定该候选",
      reproduction_steps: [],
      limitations: [],
      evidence_ids: [],
    };
  }
  return inconclusive("观察不稳定（仅单个目标被跟随或部分请求无响应），无法形成确定结论");
}

function isVerifyInput(value: unknown): value is OpenRedirectVerifyInput {
  if (!value || typeof value !== "object") return false;
  const input = value as OpenRedirectVerifyInput;
  const validSample = (sample: unknown): sample is RedirectProbeSample =>
    !!sample && typeof sample === "object" &&
    typeof (sample as RedirectProbeSample).request_url === "string" &&
    typeof (sample as RedirectProbeSample).expected_destination === "string" &&
    typeof (sample as RedirectProbeSample).status === "number" &&
    !!(sample as RedirectProbeSample).headers;
  return typeof input.source_url === "string" && validSample(input.control) &&
    Array.isArray(input.trials) && input.trials.length >= 2 && input.trials.every(validSample);
}

export class OpenRedirectVerifier implements VerifierPlugin<OpenRedirectSignals> {
  readonly id = "open-redirect";
  readonly vulnerability = "Open Redirect";
  readonly owaspCategory = "A01:2021 Broken Access Control（URL 重定向）";

  appliesTo(candidate: VerifierCandidate): boolean {
    return (
      !!candidate &&
      candidate.kind === "open_redirect" &&
      typeof candidate.endpoint === "string" &&
      candidate.endpoint.length > 0
    );
  }

  async verify(
    candidate: VerifierCandidate,
    _context: VerifierContext,
  ): Promise<VerifierRunResult<OpenRedirectSignals>> {
    const evidenceIds = candidate.evidence_ids ?? [];
    const input = candidate.metadata?.["open_redirect_verify"];
    if (!isVerifyInput(input)) {
      return {
        ok: false,
        code: "MISSING_VERIFY_INPUT",
        reason: "缺少开放重定向验证所需的对照组/试验组样本（control + 至少两个站外 trials）",
        evidence_ids: evidenceIds,
      };
    }
    return {
      ok: true,
      code: "VERIFICATION_RUN",
      reason: "开放重定向观察样本已收集",
      signals: { source_url: input.source_url, control: input.control, trials: input.trials },
      evidence_ids: evidenceIds,
    };
  }

  judge(runResult: VerifierRunResult<OpenRedirectSignals>): VerificationJudgment {
    if (!runResult.ok || !runResult.signals) {
      return inconclusive(runResult.reason || "验证未成功执行，无法判定");
    }
    const { source_url, control, trials } = runResult.signals;
    const verdict = judgeOpenRedirectProbes(source_url, control, trials);
    return { ...verdict, evidence_ids: runResult.evidence_ids };
  }
}
