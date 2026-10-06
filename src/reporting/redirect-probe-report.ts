import { randomUUID } from "node:crypto";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import type { RedirectProbeAssessment } from "../../capabilities/web/redirect-observation.ts";

export interface RedirectProbeReportInput {
  endpoint: string;
  parameter_name: string;
  source_evidence_id: string;
  probe_evidence_ids: string[];
  assessment: RedirectProbeAssessment;
}

function escape(value: string) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll("`", "\\`").replaceAll("*", "\\*").replaceAll("_", "\\_")
    .replaceAll("[", "\\[").replaceAll("]", "\\]").replaceAll("|", "\\|")
    .replace(/[\r\n]/gu, " ");
}

export async function generateRedirectProbeReport(input: RedirectProbeReportInput, outputDir: string) {
  const now = new Date().toISOString();
  const reportId = `RDP-${now.replace(/[-:.TZ]/gu, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
  const directory = path.resolve(outputDir);
  const file = path.join(directory, `${reportId}.md`);
  const temporary = path.join(directory, `.${reportId}.${randomUUID()}.tmp`);
  const label = input.assessment.outcome === "candidate" ? "待人工复核的站外重定向候选"
    : input.assessment.outcome === "not_observed" ? "本次未观察到站外重定向" : "本次结果无法判断";
  const summary = `目标 ${input.endpoint} 的参数 ${input.parameter_name}：${label}。${input.assessment.reason}`;
  const body = ["# GET 重定向参数观察报告", "", `- 目标：${escape(input.endpoint)}`,
    `- 参数：${escape(input.parameter_name)}`, `- 结果：${escape(label)}`,
    `- 说明：${escape(input.assessment.reason)}`,
    `- 两次状态码：${input.assessment.statuses.join("、")}`,
    `- 精确匹配次数：${input.assessment.matched_count}/2`, "",
    "## 证据", "", `- 来源 EV：${escape(input.source_evidence_id)}`,
    ...input.probe_evidence_ids.map(id => `- 探针 EV：${escape(id)}`), "",
    "客户端未访问重定向目的地；本报告不自动确认漏洞或业务影响。", ""].join("\n");
  try {
    await mkdir(directory, { recursive: true });
    await writeFile(temporary, body, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporary, file);
  } catch {
    return { ok: false as const, code: "WRITE_ERROR", reason: "观察已完成，但报告保存失败" };
  } finally {
    await rm(temporary, { force: true }).catch(() => {});
  }
  return { ok: true as const, code: "REPORT_SAVED", report_id: reportId,
    file_path: file, user_summary: summary };
}
