import { claimsConfirmedVulnerability } from "./claim-language.ts";
import type { EvidenceRecord } from "../evidence/evidence-store.ts";

function exactLineCount(lines: string[], expected: string): number {
  return lines.filter(line => line === expected).length;
}

/** Check report claims against verified EV facts without calling the report renderer. */
export function auditObservationReport(
  text: string,
  reportId: string,
  evidence: EvidenceRecord,
  toolName: string,
): boolean {
  const lines = text.split(/\r?\n/u);
  const { request, response, redirects } = evidence.observation;
  const observedUrls = [...text.matchAll(/https?:\/\/[^\s|<>]+/gu)].map(match => match[0]);
  const evidenceIds = [...text.matchAll(/EV-\d{14}-[a-f0-9]{8}/gu)].map(match => match[0]);
  const reportIds = [...text.matchAll(/RPT-\d{14}-[a-f0-9]{8}/gu)].map(match => match[0]);
  const requestClaims = [...text.matchAll(/\b(?:GET|POST|PUT|PATCH|DELETE)\s+(?:https?:\/\/[^\s|]+|\/[^\s|]+)/gu)];
  if (observedUrls.length === 0 || observedUrls.some(url => url !== request.url) ||
      evidenceIds.length === 0 || evidenceIds.some(id => id !== evidence.evidence_id) ||
      reportIds.length === 0 || reportIds.some(id => id !== reportId) ||
      exactLineCount(lines, `- 报告编号：${reportId}`) !== 1 ||
      claimsConfirmedVulnerability(text)) {
    return false;
  }

  if (toolName === "authorized_web_observe") {
    const summaryRows = lines.filter(line => /^\| \d+ \| /u.test(line));
    return lines[0] === "# 授权 Web 测试 HTTP 观察报告" &&
      exactLineCount(lines, "- 证据数量：1") === 1 &&
      exactLineCount(lines, `- 请求：GET ${request.url}`) === 1 &&
      exactLineCount(lines, `- 实际连接 IP：${request.resolved_ip}`) === 1 &&
      exactLineCount(lines, `- HTTP 状态码：${response.status}`) === 1 &&
      exactLineCount(lines, `- 响应正文大小：${response.body_bytes} 字节`) === 1 &&
      exactLineCount(lines, `- 响应正文 SHA-256：${response.body_sha256}`) === 1 &&
      exactLineCount(lines, `- 证据载荷 SHA-256：${evidence.integrity.payload_sha256}`) === 1 &&
      exactLineCount(lines, `- 重定向次数：${redirects.length}`) === 1 &&
      summaryRows.length === 1 && summaryRows[0].includes(evidence.evidence_id) &&
      summaryRows[0].includes(request.url) && requestClaims.length === 1;
  }

  if (toolName === "authorized_web_check") {
    return lines[0] === "# 单 URL 安全检查报告" &&
      exactLineCount(lines, `- 证据编号：${evidence.evidence_id}`) === 1 &&
      exactLineCount(lines, `- 证据 SHA-256：${evidence.integrity.payload_sha256}`) === 1 &&
      exactLineCount(lines, `- 重定向次数：${redirects.length}`) === 1 &&
      text.includes(`HTTP ${response.status}`) && requestClaims.length === 0;
  }
  return false;
}
