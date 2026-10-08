import { runSoStaticAudit, type SoStaticAuditOptions, type SoStaticAuditResult } from "../../../capabilities/apk/so-static-audit.ts";
import { resolveSessionSoPath, type SoSessionBinding } from "../../../capabilities/apk/so-path.ts";
import type { EvidenceEntry } from "../../../capabilities/apk/evidence.ts";
import type { ApkScope } from "./scope.ts";

/** ④ so_static_audit 工作流：readelf/strings/LIEF 列 so 符号/字符串/依赖事实。脚手架。 */
export interface ApkSoStaticAuditResult {
  ok: boolean;
  stage: "so_static_audit";
  code: string;
  reason: string;
  scope?: ApkScope;
  observation?: SoStaticAuditResult;
  evidence: EvidenceEntry[];
}

export async function runApkSoStaticAudit(
  soPath: string,
  input: { scope?: ApkScope; workRoot?: string; options?: SoStaticAuditOptions } = {},
): Promise<ApkSoStaticAuditResult> {
  const session: SoSessionBinding | undefined =
    input.workRoot && input.scope?.apk_sha256
      ? { workRoot: input.workRoot, apk_sha256: input.scope.apk_sha256 }
      : undefined;
  const gate = resolveSessionSoPath(soPath, session);
  if (!gate.ok) {
    return {
      ok: false,
      stage: "so_static_audit",
      code: gate.code,
      reason: gate.reason,
      ...(input.scope ? { scope: input.scope } : {}),
      evidence: [],
    };
  }
  const observation = await runSoStaticAudit(gate.resolved, {
    ...(input.options ?? {}),
    session,
  });
  return {
    ok: true, stage: "so_static_audit", code: "SO_FACTS_COLLECTED",
    reason: "已列出 so 架构/符号/依赖/相关字符串事实",
    ...(input.scope ? { scope: input.scope } : {}),
    observation, evidence: observation.evidence,
  };
}
