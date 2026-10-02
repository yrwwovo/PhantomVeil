import { randomUUID } from "node:crypto";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import type { XssEncodingObservationResult } from "../../capabilities/web/xss-encoding-observation.ts";

export interface XssEncodingReportInput {
  endpoint: string;
  parameter_name: string;
  http_status: number;
  source_evidence_id: string;
  request_evidence_id: string;
  observation: XssEncodingObservationResult;
}

function escapeMarkdown(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replace(/[\\`*_[\]|]/gu, "\\$&").replace(/[\r\n]/gu, " ");
}

function formLabel(value: string): string {
  return ({
    raw: "原样出现",
    html_entity: "HTML 实体编码",
    percent_encoded: "URL 百分号编码",
    removed: "被删除",
    transformed: "其他转换",
  } as Record<string, string>)[value] ?? value;
}

export function summarizeXssEncodingObservation(input: XssEncodingReportInput): string {
  const outcome = input.observation.outcome === "raw_special_characters_observed"
    ? "观察到原样特殊字符，需要复核"
    : input.observation.outcome === "all_observed_characters_encoded"
      ? "本次观察到全部特殊字符被编码"
      : input.observation.outcome === "partially_encoded"
        ? "只观察到部分特殊字符被编码"
        : "本次无法稳定评价编码";
  return [
    `目标：${input.endpoint}`,
    `参数：${input.parameter_name}`,
    `结果：${outcome}（HTTP ${input.http_status}）`,
    input.observation.conclusion,
    "本轮没有发送可执行 XSS 载荷，也没有确认漏洞。",
  ].join("\n");
}

export async function generateXssEncodingReport(input: XssEncodingReportInput, outputDir: string) {
  const generatedAt = new Date().toISOString();
  const reportId = `ENC-${generatedAt.replace(/[-:.TZ]/gu, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
  const directory = path.resolve(outputDir);
  const filePath = path.join(directory, `${reportId}.md`);
  const temporaryPath = path.join(directory, `.${reportId}.${randomUUID()}.tmp`);
  const summary = summarizeXssEncodingObservation(input);
  const rows = input.observation.characters.map(item => {
    const forms = item.observed_forms.length ? item.observed_forms.map(formLabel).join("、") : "未观察到";
    return `| ${escapeMarkdown(item.label)} | ${escapeMarkdown(forms)} | ${item.occurrence_count} |`;
  });
  const markdown = [
    "# XSS 输出编码观察报告", "",
    ...summary.split("\n").map(escapeMarkdown), "",
    "## 字符观察", "",
    "| 字符 | 响应中的形式 | 出现次数 |", "|---|---|---|", ...rows, "",
    "## 追溯信息", "",
    `- 报告编号：${reportId}`,
    `- 生成时间：${generatedAt}`,
    `- 来源反射证据：${escapeMarkdown(input.source_evidence_id)}`,
    `- 本次请求证据：${escapeMarkdown(input.request_evidence_id)}`, "",
    "原样字符不是 XSS 结论；编码结果也不是全站安全证明。需要结合具体 HTML 上下文和独立复核规则判断。", "",
  ].join("\n");
  try {
    await mkdir(directory, { recursive: true });
    await writeFile(temporaryPath, `${markdown}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporaryPath, filePath);
  } catch {
    return { ok: false as const, code: "WRITE_ERROR", reason: "编码观察已完成，但报告保存失败" };
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => {});
  }
  return { ok: true as const, code: "REPORT_SAVED", report_id: reportId,
    file_path: filePath, user_summary: summary };
}
