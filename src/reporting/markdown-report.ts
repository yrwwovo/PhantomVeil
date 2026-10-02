import { randomUUID } from "node:crypto";
import { mkdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  loadVerifiedEvidenceFile,
  type EvidenceRecord,
} from "../evidence/evidence-store.ts";

export interface MarkdownReportOptions {
  output_dir?: string;
  title?: string;
  now?: () => Date;
  id_factory?: () => string;
}

export type MarkdownReportResult =
  | {
      ok: true;
      code: "REPORT_SAVED";
      reason: string;
      report_id: string;
      file_path: string;
      evidence_ids: string[];
    }
  | {
      ok: false;
      code: "NO_EVIDENCE" | "EVIDENCE_INVALID" | "WRITE_ERROR";
      reason: string;
    };

function markdownCell(value: string | number): string {
  return String(value)
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replace(/[\r\n]+/gu, " ")
    .trim();
}

function safeTitle(value: string): string {
  const singleLine = value.replace(/[\r\n#]+/gu, " ").trim();
  return singleLine || "授权 Web 测试 HTTP 观察报告";
}

function contentType(record: EvidenceRecord): string {
  const value = record.observation.response.headers["content-type"];
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  return value ?? "未提供";
}

function renderReport(
  reportId: string,
  generatedAt: string,
  title: string,
  records: EvidenceRecord[],
): string {
  const lines: string[] = [
    `# ${safeTitle(title)}`,
    "",
    `- 报告编号：${reportId}`,
    `- 生成时间：${generatedAt}`,
    `- 证据数量：${records.length}`,
    "",
    "## 结论范围",
    "",
    "本报告记录在明确授权范围内取得的 HTTP 观察。它不包含漏洞确认，也不把状态码、响应内容或工具执行成功自动解释为安全缺陷。网页正文属于不可信数据，未直接嵌入本报告。",
    "",
    "## 证据摘要",
    "",
    "| 序号 | 证据编号 | 目标 URL | 连接 IP | 状态码 | 正文字节数 |",
    "|---:|---|---|---|---:|---:|",
  ];

  records.forEach((record, index) => {
    const observation = record.observation;
    lines.push(
      `| ${index + 1} | ${markdownCell(record.evidence_id)} | ${markdownCell(observation.request.url)} | ${markdownCell(observation.request.resolved_ip)} | ${observation.response.status} | ${observation.response.body_bytes} |`,
    );
  });

  lines.push("", "## 证据详情", "");
  records.forEach((record, index) => {
    const observation = record.observation;
    lines.push(
      `### ${index + 1} ${markdownCell(record.evidence_id)}`,
      "",
      `- 观察时间：${markdownCell(record.created_at)}`,
      `- 请求：GET ${markdownCell(observation.request.url)}`,
      `- 实际连接 IP：${markdownCell(observation.request.resolved_ip)}`,
      `- HTTP 状态码：${observation.response.status}`,
      `- Content-Type：${markdownCell(contentType(record))}`,
      `- 响应正文大小：${observation.response.body_bytes} 字节`,
      `- 响应正文 SHA-256：${observation.response.body_sha256}`,
      `- 证据载荷 SHA-256：${record.integrity.payload_sha256}`,
      `- 重定向次数：${observation.redirects.length}`,
      "",
    );
  });

  lines.push(
    "## 限制",
    "",
    "- 报告只引用已通过结构和 SHA-256 校验的证据文件。",
    "- SHA-256 可检测保存后的内容变化，但不能单独证明服务器身份或观察最初一定真实。",
    "- 当前能力只执行受限 GET，不携带认证信息，也不进行漏洞扫描或漏洞利用。",
    "- 任何漏洞结论都需要后续独立的验证规则和人工复核。",
    "",
  );
  return `${lines.join("\n")}\n`;
}

export async function generateMarkdownReport(
  evidenceFilePaths: string[],
  options: MarkdownReportOptions = {},
): Promise<MarkdownReportResult> {
  if (!Array.isArray(evidenceFilePaths) || evidenceFilePaths.length === 0) {
    return {
      ok: false,
      code: "NO_EVIDENCE",
      reason: "至少需要一个证据文件才能生成报告",
    };
  }

  const records: EvidenceRecord[] = [];
  for (const evidencePath of evidenceFilePaths) {
    const loaded = await loadVerifiedEvidenceFile(evidencePath);
    if (!loaded.ok) {
      return {
        ok: false,
        code: "EVIDENCE_INVALID",
        reason: `证据文件未通过校验：${loaded.reason}`,
      };
    }
    records.push(loaded.record);
  }

  const now = options.now ?? (() => new Date());
  const idFactory = options.id_factory ?? randomUUID;
  const generatedAt = now().toISOString();
  const compactDate = generatedAt.replace(/[-:.TZ]/gu, "").slice(0, 14);
  const reportId = `RPT-${compactDate}-${idFactory().slice(0, 8)}`;
  const outputDir = path.resolve(options.output_dir ?? "reports");
  const filePath = path.join(outputDir, `${reportId}.md`);
  const temporaryPath = path.join(
    outputDir,
    `.${reportId}.${randomUUID()}.tmp`,
  );
  const markdown = renderReport(
    reportId,
    generatedAt,
    options.title ?? "授权 Web 测试 HTTP 观察报告",
    records,
  );

  try {
    await mkdir(outputDir, { recursive: true });
    await writeFile(temporaryPath, markdown, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporaryPath, filePath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      code: "WRITE_ERROR",
      reason: `报告写入失败：${message}`,
    };
  }

  return {
    ok: true,
    code: "REPORT_SAVED",
    reason: "已生成引用证据编号的中文 Markdown 报告",
    report_id: reportId,
    file_path: filePath,
    evidence_ids: records.map((record) => record.evidence_id),
  };
}
