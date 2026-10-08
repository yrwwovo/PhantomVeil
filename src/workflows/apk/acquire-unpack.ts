import { runAcquireUnpack, type AcquireUnpackOptions, type AcquireUnpackResult } from "../../../capabilities/apk/acquire-unpack.ts";
import type { EvidenceEntry } from "../../../capabilities/apk/evidence.ts";
import { assertScopeMatch, type ApkScope } from "./scope.ts";

/** ① acquire_unpack 工作流：算主键、列条目、取签名/证书事实、加固指示项。只产事实，不判定。 */
export interface ApkAcquireUnpackResult {
  ok: boolean;
  stage: "acquire_unpack";
  code: string;
  reason: string;
  scope?: ApkScope;
  observation?: AcquireUnpackResult;
  evidence: EvidenceEntry[];
}

export async function runApkAcquireUnpack(
  apkPath: string,
  input: { scope?: ApkScope; options?: AcquireUnpackOptions } = {},
): Promise<ApkAcquireUnpackResult> {
  const observation = await runAcquireUnpack(apkPath, input.options ?? {});
  const scopeCheck = assertScopeMatch(input.scope, observation.apk_sha256);
  if (!scopeCheck.ok) {
    return { ok: false, stage: "acquire_unpack", code: "SCOPE_MISMATCH", reason: scopeCheck.reason ?? "scope 不一致", evidence: [] };
  }
  return {
    ok: true, stage: "acquire_unpack", code: "ACQUIRE_FACTS_COLLECTED",
    reason: "已采集 APK 哈希/条目/签名/加固指示项事实",
    ...(input.scope ? { scope: input.scope } : {}),
    observation, evidence: observation.evidence,
  };
}
