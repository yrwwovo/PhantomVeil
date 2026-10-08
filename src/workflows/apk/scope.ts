/**
 * APK 静态线路的 Scope 三元组（设计 §1）。
 * apk_sha256 为主键；换 APK（SHA-256 变）→ 另起会话。签名指纹作辅助核验。
 */
export interface ApkScope {
  apk_sha256: string;
  package_name?: string | null;
  version_name?: string | null;
  signing_cert_sha256?: string | null;
}

export interface ScopeCheckResult { ok: boolean; reason?: string }

/** 执行前核对 capability 实测 apk_sha256 与当前 Scope 主键一致，防串台（§1 教训直引）。 */
export function assertScopeMatch(scope: ApkScope | undefined, observedApkSha256: string | null): ScopeCheckResult {
  if (!scope) return { ok: true };
  if (!observedApkSha256) return { ok: false, reason: "无法算出 apk_sha256，无法核对 Scope 主键" };
  if (scope.apk_sha256 && scope.apk_sha256 !== observedApkSha256) {
    return { ok: false, reason: `apk_sha256 与 Scope 主键不一致（Scope=${scope.apk_sha256.slice(0, 12)}… 实测=${observedApkSha256.slice(0, 12)}…），换 APK 应另起会话` };
  }
  return { ok: true };
}

export type { SoSessionBinding, SoPathGate } from "../../../capabilities/apk/so-path.ts";
export { resolveSessionSoPath } from "../../../capabilities/apk/so-path.ts";
