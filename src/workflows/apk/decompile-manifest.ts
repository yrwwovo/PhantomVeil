import { runDecompileManifest, type DecompileManifestOptions, type DecompileManifestResult, type ManifestComponent } from "../../../capabilities/apk/decompile-manifest.ts";
import type { EvidenceEntry } from "../../../capabilities/apk/evidence.ts";
import { assertScopeMatch, type ApkScope } from "./scope.ts";

/** ② decompile_manifest 工作流：解包取 manifest，枚举组件/权限/开关事实 + 候选定位。 */
export interface CandidateLocator {
  stage: "decompile_manifest";
  component: string;
  component_type: string;
  /** 中性事实标注：供 Agent 推理，不含 CWE。 */
  facts: Record<string, unknown>;
  manifest_anchor: string;
}

export interface ApkDecompileManifestResult {
  ok: boolean;
  stage: "decompile_manifest";
  code: string;
  reason: string;
  scope?: ApkScope;
  observation?: DecompileManifestResult;
  /** 事实型候选定位（exported 组件 + 其权限现状），交 Agent 推 cwe/locator。 */
  candidate_locators: CandidateLocator[];
  evidence: EvidenceEntry[];
}

function toCandidates(components: ManifestComponent[]): CandidateLocator[] {
  return components.map((c) => ({
    stage: "decompile_manifest" as const,
    component: c.name,
    component_type: c.type,
    facts: {
      exported_attr: c.exported_attr,
      has_intent_filter: c.has_intent_filter,
      permission: c.permission,
      read_permission: c.read_permission,
      write_permission: c.write_permission,
      grant_uri_permissions: c.grant_uri_permissions,
      has_any_permission_guard: c.permission !== null || c.read_permission !== null || c.write_permission !== null,
    },
    manifest_anchor: `manifest#${c.type}:${c.name}`,
  }));
}

export async function runApkDecompileManifest(
  apkPath: string,
  input: { scope?: ApkScope; options?: DecompileManifestOptions } = {},
): Promise<ApkDecompileManifestResult> {
  const observation = await runDecompileManifest(apkPath, input.options ?? {});
  const scopeCheck = assertScopeMatch(input.scope, observation.apk_sha256);
  if (!scopeCheck.ok) {
    return { ok: false, stage: "decompile_manifest", code: "SCOPE_MISMATCH", reason: scopeCheck.reason ?? "scope 不一致", candidate_locators: [], evidence: [] };
  }
  return {
    ok: true, stage: "decompile_manifest", code: "MANIFEST_FACTS_COLLECTED",
    reason: "已枚举组件/权限/全局开关事实",
    ...(input.scope ? { scope: input.scope } : {}),
    observation,
    candidate_locators: toCandidates(observation.facts.components),
    evidence: observation.evidence,
  };
}
