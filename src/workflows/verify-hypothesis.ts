import { realpath } from "node:fs/promises";
import path from "node:path";

import { HypothesisStore } from "../hypotheses/hypothesis-store.ts";
import { createDefaultVerifierRegistry } from "../verifiers/index.ts";
import type { VerificationJudgment } from "../verifiers/verifier-plugin.ts";
import { runVerificationStage } from "./verification-stage.ts";

const HYP_ID = /^HYP-\d{14}-[a-f0-9]{8}$/u;

export interface VerifyHypothesisInput {
  hypothesis_id: string;
  /** Vulnerability class key routing to a plugin, e.g. "reflected_xss". */
  kind: string;
  endpoint?: string;
  parameter_name?: string;
  /** Plugin-specific verify inputs (opaque; shape depends on the plugin). */
  metadata?: Record<string, unknown>;
  evidence_ids?: string[];
}

export type VerifyHypothesisResult =
  | {
      ok: true;
      code: "HYPOTHESIS_VERIFIED";
      reason: string;
      hypothesis_id: string;
      plugin_id: string;
      vulnerability: string;
      outcome: VerificationJudgment["outcome"];
      status: string;
      transitions_applied: string[];
      rationale: string;
      file_path: string;
    }
  | {
      ok: false;
      code:
        | "INVALID_ID"
        | "PATH_REJECTED"
        | "NOT_FOUND"
        | "IO_ERROR"
        | "LOAD_ERROR"
        | "NO_VERIFIER"
        | "AMBIGUOUS_VERIFIER"
        | "TRANSITION_FAILED"
        | "PERSIST_FAILED";
      reason: string;
      hypothesis_id: string;
      plugin_ids?: string[];
    };

/**
 * Main-chain verification tool entry point: load an existing suspected
 * hypothesis, auto-select the applicable verifier plugin by `kind`, run
 * verify -> judge, and write the verdict back through the state machine,
 * persisting each transition. The caller stays agnostic to vulnerability class.
 */
export async function runVerifyHypothesis(
  projectRoot: string,
  input: VerifyHypothesisInput,
  artifactNamespace: "opencode" | "hermes" = "opencode",
): Promise<VerifyHypothesisResult> {
  if (!input || typeof input.hypothesis_id !== "string" || !HYP_ID.test(input.hypothesis_id)) {
    return { ok: false, code: "INVALID_ID", reason: "请提供合法的 HYP 假设编号", hypothesis_id: input?.hypothesis_id ?? "" };
  }
  if (typeof input.kind !== "string" || input.kind.trim().length === 0) {
    return { ok: false, code: "INVALID_ID", reason: "必须提供漏洞类型 kind 以路由到验证器", hypothesis_id: input.hypothesis_id };
  }

  // Pin the lookup directory; refuse symlink escapes out of the namespace.
  let outputDir: string;
  try {
    const root = await realpath(projectRoot);
    const relativeFile = path.join("hypotheses", artifactNamespace, `${input.hypothesis_id}.json`);
    const resolvedFile = await realpath(path.join(root, relativeFile));
    if (path.relative(root, resolvedFile) !== relativeFile) {
      return { ok: false, code: "PATH_REJECTED", reason: "假设文件被重定向到其他位置，拒绝读取", hypothesis_id: input.hypothesis_id };
    }
    outputDir = path.join(root, "hypotheses", artifactNamespace);
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    return {
      ok: false,
      code: missing ? "NOT_FOUND" : "IO_ERROR",
      reason: missing ? "该项目找不到该假设记录" : "无法定位项目假设文件",
      hypothesis_id: input.hypothesis_id,
    };
  }

  const store = new HypothesisStore(outputDir);
  const loaded = await store.load(input.hypothesis_id);
  if (!loaded.ok) {
    return { ok: false, code: loaded.code === "NOT_FOUND" ? "NOT_FOUND" : "LOAD_ERROR", reason: loaded.reason, hypothesis_id: input.hypothesis_id };
  }

  let runningSha = loaded.payload_sha256;
  const registry = createDefaultVerifierRegistry();
  const result = await runVerificationStage({
    hypothesis: loaded.hypothesis,
    registry,
    context: {
      projectRoot: path.resolve(projectRoot),
      authorization_reference: loaded.hypothesis.authorization_reference ?? "",
      artifactNamespace,
    },
    candidate: {
      kind: input.kind,
      ...(input.endpoint ? { endpoint: input.endpoint } : {}),
      ...(input.parameter_name ? { parameter_name: input.parameter_name } : {}),
      ...(input.metadata ? { metadata: input.metadata } : {}),
      ...(input.evidence_ids ? { evidence_ids: input.evidence_ids } : {}),
    },
    commit: async (hypothesis) => {
      const saved = await store.update(hypothesis, runningSha);
      if (!saved.ok) return { ok: false, reason: saved.reason };
      runningSha = saved.payload_sha256;
      return { ok: true };
    },
  });

  if (!result.ok) {
    if (result.code === "NO_VERIFIER" || result.code === "AMBIGUOUS_VERIFIER") {
      return {
        ok: false,
        code: result.code,
        reason: result.reason,
        hypothesis_id: input.hypothesis_id,
        ...(result.plugin_ids ? { plugin_ids: result.plugin_ids } : {}),
      };
    }
    return { ok: false, code: result.code, reason: result.reason, hypothesis_id: input.hypothesis_id };
  }

  return {
    ok: true,
    code: "HYPOTHESIS_VERIFIED",
    reason: `验证器 ${result.plugin_id} 已判定并按状态机回写假设`,
    hypothesis_id: input.hypothesis_id,
    plugin_id: result.plugin_id,
    vulnerability: result.vulnerability,
    outcome: result.outcome,
    status: result.hypothesis.status,
    transitions_applied: result.transitions_applied,
    rationale: result.judgment.rationale,
    file_path: loaded.file_path,
  };
}
