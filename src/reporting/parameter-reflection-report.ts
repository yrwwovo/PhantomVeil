import { randomUUID } from "node:crypto";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

export interface ParameterReflectionResult {
  classification: "input_reflection_observation";
  outcome: "reflected" | "not_reflected" | "inconclusive";
  endpoint: string;
  parameter_name: string;
  http_status: number;
  reflected_in_body: boolean;
  occurrence_count: number;
  source_evidence_id: string;
  request_evidence_id: string;
  conclusion: string;
}

function escapeMarkdown(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replace(/[\\`*_[\]|]/gu, "\\$&").replace(/[\r\n]/gu, " ");
}

export function summarizeParameterReflection(result: ParameterReflectionResult): string {
  const label = result.outcome === "reflected" ? "观察到输入标记反射" :
    result.outcome === "not_reflected" ? "未观察到输入标记反射" : "本次结果无法判断";
  return [
    `目标：${result.endpoint}`,
    `参数：${result.parameter_name}`,
    `结果：${label}（HTTP ${result.http_status}）`,
    result.conclusion,
    "本检查只发送一个无害随机标记；未使用 XSS、SQL 注入或其他攻击载荷。",
  ].join("\n");
}

export async function generateParameterReflectionReport(
  result: ParameterReflectionResult,
  outputDir: string,
) {
  const generatedAt = new Date().toISOString();
  const reportId = `RFL-${generatedAt.replace(/[-:.TZ]/gu, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
  const directory = path.resolve(outputDir);
  const filePath = path.join(directory, `${reportId}.md`);
  const temporaryPath = path.join(directory, `.${reportId}.${randomUUID()}.tmp`);
  const summary = summarizeParameterReflection(result);
  const markdown = [
    "# GET 参数反射观察报告", "",
    ...summary.split("\n").map(line => escapeMarkdown(line)), "",
    "## 追溯信息", "",
    `- 报告编号：${reportId}`,
    `- 生成时间：${generatedAt}`,
    `- 来源页面证据：${escapeMarkdown(result.source_evidence_id)}`,
    `- 本次请求证据：${escapeMarkdown(result.request_evidence_id)}`,
    `- 响应正文出现次数：${result.occurrence_count}`, "",
    "输入被反射不等于可以执行脚本；未反射也不代表参数不存在其他安全问题。", "",
  ].join("\n");
  try {
    await mkdir(directory, { recursive: true });
    await writeFile(temporaryPath, `${markdown}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporaryPath, filePath);
  } catch {
    return { ok: false as const, code: "WRITE_ERROR", reason: "反射检查已完成，但报告保存失败" };
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => {});
  }
  return { ok: true as const, code: "REPORT_SAVED", report_id: reportId,
    file_path: filePath, user_summary: summary };
}
