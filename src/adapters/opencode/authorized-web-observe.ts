import { readFile } from "node:fs/promises";
import path from "node:path";

import {
  restrictedHttpGet,
  type HttpGetPolicy,
} from "../../../capabilities/web/restricted-http-get.ts";
import { EvidenceStore } from "../../evidence/evidence-store.ts";
import { generateMarkdownReport } from "../../reporting/markdown-report.ts";
import type { ScopeConfig } from "../../scope/scope-guard.ts";

export type AuthorizedWebObserveResult =
  | {
      ok: true;
      code: "OBSERVATION_RECORDED";
      reason: string;
      target_url: string;
      http_status: number;
      evidence_id: string;
      evidence_file: string;
      report_id: string;
      report_file: string;
    }
  | {
      ok: false;
      code:
        | "CONFIG_ERROR"
        | "HTTP_REJECTED"
        | "EVIDENCE_ERROR"
        | "REPORT_ERROR";
      reason: string;
    };

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await readFile(filePath, "utf8")) as T;
}

/**
 * OpenCode 适配层的可测试入口。Agent 只提供 URL，授权配置始终由项目文件决定。
 * 返回内容不包含网页正文，避免把不可信页面内容直接送回模型上下文。
 */
export async function runAuthorizedWebObservation(
  projectRoot: string,
  targetUrl: string,
): Promise<AuthorizedWebObserveResult> {
  const root = path.resolve(projectRoot);
  let scopeConfig: ScopeConfig;
  let httpPolicy: HttpGetPolicy;

  try {
    [scopeConfig, httpPolicy] = await Promise.all([
      readJson<ScopeConfig>(path.join(root, "configs", "scope.local.json")),
      readJson<HttpGetPolicy>(path.join(root, "configs", "http.local.json")),
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      code: "CONFIG_ERROR",
      reason: `无法读取项目授权配置：${message}`,
    };
  }

  const httpResult = await restrictedHttpGet(targetUrl, scopeConfig, httpPolicy);
  if (!httpResult.ok || !httpResult.response) {
    return {
      ok: false,
      code: "HTTP_REJECTED",
      reason: httpResult.reason,
    };
  }

  const evidenceStore = new EvidenceStore({
    output_dir: path.join(root, "evidence", "opencode"),
  });
  const evidence = await evidenceStore.saveHttpGet(httpResult);
  if (!evidence.ok) {
    return {
      ok: false,
      code: "EVIDENCE_ERROR",
      reason: evidence.reason,
    };
  }

  const report = await generateMarkdownReport([evidence.file_path], {
    output_dir: path.join(root, "reports", "opencode"),
  });
  if (!report.ok) {
    return {
      ok: false,
      code: "REPORT_ERROR",
      reason: report.reason,
    };
  }

  return {
    ok: true,
    code: "OBSERVATION_RECORDED",
    reason: "已完成授权 GET，并保存证据与中文观察报告",
    target_url: httpResult.response.url,
    http_status: httpResult.response.status,
    evidence_id: evidence.evidence_id,
    evidence_file: evidence.file_path,
    report_id: report.report_id,
    report_file: report.file_path,
  };
}
