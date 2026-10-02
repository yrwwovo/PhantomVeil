import { randomUUID } from "node:crypto";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { checkHttpSecurityHeaders, type SecurityHeaderCheckResult } from "../../capabilities/web/security-header-check.ts";
import { loadVerifiedEvidenceFile, type EvidenceRecord } from "../evidence/evidence-store.ts";

// 用户摘要不包含查询串或片段，避免把 URL 中的业务秘密展示到模型和报告。
function displayTarget(value: string): string {
  const url = new URL(value);
  url.search = "";
  url.hash = "";
  url.username = "";
  url.password = "";
  return url.href;
}

function escapeMarkdown(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replace(/[\\`*_[\]|]/gu, "\\$&").replace(/[\r\n]/gu, " ");
}

const LABELS = { pass: "通过", review: "需要复核", not_applicable: "不适用" };

export function summarizeHeaderCheck(result: SecurityHeaderCheckResult): string {
  const lines = [
    `目标：${displayTarget(result.target_url)}`,
    `检查完成：单个 URL 的响应头检查（HTTP ${result.http_status}）`,
    `通过 ${result.summary.pass} 项；需要复核 ${result.summary.review} 项；不适用 ${result.summary.not_applicable} 项。`,
    ...result.findings.map((item) => `${LABELS[item.status]}｜${item.title}：${item.reason}`),
    result.conclusion,
    "检查仅覆盖本次响应，不包含站内爬取或注入、越权等主动漏洞验证。",
  ];
  if (result.http_status >= 400) lines.splice(2, 0, "本次取得的是错误状态响应，不能代表正常业务页面的配置。");
  return lines.join("\n");
}

function renderHeaderCheckReport(
  reportId: string,
  generatedAt: string,
  record: EvidenceRecord,
  result: SecurityHeaderCheckResult,
  summary: string,
): string {
  return [
    "# 单 URL 安全检查报告", "",
    ...summary.split("\n").map((line) => `${escapeMarkdown(line)}\n`),
    "## 追溯信息", "",
    `- 报告编号：${reportId}`,
    `- 生成时间：${generatedAt}`,
    `- 证据编号：${escapeMarkdown(record.evidence_id)}`,
    `- 观察时间：${escapeMarkdown(record.created_at)}`,
    `- 规则版本：${result.check_id}`,
    `- 证据 SHA-256：${escapeMarkdown(record.integrity.payload_sha256)}`,
    `- 重定向次数：${record.observation.redirects.length}`, "",
    "CSP 当前只检查是否存在，页面嵌入限制只作基础检查；通过不代表策略足够严格。", "",
  ].join("\n");
}

/** 从证据重新校验、执行规则并生成报告，不能由模型直接提供检查结论。 */
export async function generateHeaderCheckReport(evidenceFile: string, outputDir: string) {
  const loaded = await loadVerifiedEvidenceFile(evidenceFile);
  if (!loaded.ok) return { ok: false as const, code: "EVIDENCE_INVALID", reason: "证据校验失败，无法生成检查报告" };
  let result: SecurityHeaderCheckResult;
  let summary: string;
  try {
    result = checkHttpSecurityHeaders(loaded.record);
    summary = summarizeHeaderCheck(result);
  } catch {
    return { ok: false as const, code: "EVIDENCE_INVALID", reason: "证据内容无法用于响应头检查" };
  }
  const generatedAt = new Date().toISOString();
  const reportId = `RPT-${generatedAt.replace(/[-:.TZ]/gu, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
  const directory = path.resolve(outputDir);
  const filePath = path.join(directory, `${reportId}.md`);
  const temporaryPath = path.join(directory, `.${reportId}.${randomUUID()}.tmp`);
  const markdown = renderHeaderCheckReport(reportId, generatedAt, loaded.record, result, summary);
  try {
    await mkdir(directory, { recursive: true });
    await writeFile(temporaryPath, markdown, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporaryPath, filePath);
  } catch {
    return { ok: false as const, code: "WRITE_ERROR", reason: "检查已执行，但报告保存失败；已保存的证据仍可用于离线分析" };
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => {});
  }
  return { ok: true as const, code: "REPORT_SAVED", report_id: reportId, file_path: filePath,
    user_summary: summary, result: { ...result, target_url: displayTarget(result.target_url) } };
}
