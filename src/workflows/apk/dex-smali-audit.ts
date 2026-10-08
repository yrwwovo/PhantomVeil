import { runDexSmaliAudit, type DexSmaliAuditOptions, type DexSmaliAuditResult } from "../../../capabilities/apk/dex-smali-audit.ts";
import type { EvidenceEntry } from "../../../capabilities/apk/evidence.ts";
import { assertScopeMatch, type ApkScope } from "./scope.ts";

/** ③ dex_smali_audit 工作流：jadx 反编译后清点调用点并与 exported 组件关联。只产事实定位。 */
export interface ApkDexSmaliAuditResult {
  ok: boolean;
  stage: "dex_smali_audit";
  code: string;
  reason: string;
  scope?: ApkScope;
  observation?: DexSmaliAuditResult;
  evidence: EvidenceEntry[];
}

export async function runApkDexSmaliAudit(
  apkPath: string,
  input: { scope?: ApkScope; components?: Array<{ name: string; type?: string | null }>; options?: DexSmaliAuditOptions } = {},
): Promise<ApkDexSmaliAuditResult> {
  const options: DexSmaliAuditOptions = { ...(input.options ?? {}), ...(input.components ? { components: input.components } : {}) };
  const observation = await runDexSmaliAudit(apkPath, options);
  const scopeCheck = assertScopeMatch(input.scope, observation.apk_sha256);
  if (!scopeCheck.ok) {
    return { ok: false, stage: "dex_smali_audit", code: "SCOPE_MISMATCH", reason: scopeCheck.reason ?? "scope 不一致", evidence: [] };
  }
  return {
    ok: true, stage: "dex_smali_audit", code: "DEX_SMALI_FACTS_COLLECTED",
    reason: "已清点调用点位置并与 exported 组件关联",
    ...(input.scope ? { scope: input.scope } : {}),
    observation, evidence: observation.evidence,
  };
}
