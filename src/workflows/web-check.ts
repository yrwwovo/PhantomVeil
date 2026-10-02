import { readFile } from "node:fs/promises";
import path from "node:path";

import { restrictedHttpGet, type HttpGetPolicy, type HttpRequestControl } from "../../capabilities/web/restricted-http-get.ts";
import { EvidenceStore } from "../evidence/evidence-store.ts";
import { generateHeaderCheckReport } from "../reporting/header-check-report.ts";
import type { ScopeConfig } from "../scope/scope-guard.ts";

/** 单次受限观察 → 保存证据 → 离线检查 → 中文报告。命令行与 OpenCode 共用。 */
export async function runWebCheck(projectRoot: string, targetUrl: string, control: HttpRequestControl = {}) {
  if (typeof targetUrl !== "string" || !targetUrl.trim()) {
    return { ok: false as const, code: "INVALID_INPUT", reason: "请输入一个完整的 HTTP(S) URL" };
  }
  const root = path.resolve(projectRoot);
  let scope: ScopeConfig;
  let policy: HttpGetPolicy;
  try {
    const [scopeJson, policyJson] = await Promise.all([
      readFile(path.join(root, "configs", "scope.local.json"), "utf8"),
      readFile(path.join(root, "configs", "http.local.json"), "utf8"),
    ]);
    scope = JSON.parse(scopeJson);
    policy = JSON.parse(policyJson);
  } catch {
    return { ok: false as const, code: "CONFIG_ERROR", reason: "无法读取项目的范围配置或 HTTP 配置，检查未启动" };
  }

  const http = await restrictedHttpGet(targetUrl, scope, policy, control);
  if (!http.ok || !http.response) {
    return { ok: false as const, code: "HTTP_REJECTED", cause: http.code,
      reason: `未取得可用于检查的响应（${http.code}），请核对目标、授权范围和连接情况` };
  }
  const evidence = await new EvidenceStore({ output_dir: path.join(root, "evidence", "opencode") }).saveHttpGet(http);
  if (!evidence.ok) return { ok: false as const, code: "EVIDENCE_ERROR", reason: "响应已取得，但证据保存失败，检查未完成" };
  const trace = { evidence_id: evidence.evidence_id, evidence_file: evidence.file_path };
  const report = await generateHeaderCheckReport(evidence.file_path, path.join(root, "reports", "opencode"));
  if (!report.ok) {
    return { ok: false as const, code: "REPORT_ERROR", cause: report.code, reason: report.reason, trace };
  }
  return {
    ok: true as const, code: "WEB_CHECK_COMPLETED", user_summary: report.user_summary,
    result: report.result,
    trace: { ...trace, report_id: report.report_id, report_file: report.file_path },
  };
}
