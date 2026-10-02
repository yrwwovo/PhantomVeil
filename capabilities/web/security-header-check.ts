import type { EvidenceRecord } from "../../src/evidence/evidence-store.ts";

export type HeaderCheckStatus = "pass" | "review" | "not_applicable";

export interface HeaderCheckFinding {
  rule_id: string;
  title: string;
  status: HeaderCheckStatus;
  reason: string;
  evidence_id: string;
}

export interface SecurityHeaderCheckResult {
  schema_version: 1;
  check_id: "http_response_headers_v1";
  evidence_id: string;
  target_url: string;
  http_status: number;
  classification: "configuration_review";
  summary: {
    pass: number;
    review: number;
    not_applicable: number;
  };
  findings: HeaderCheckFinding[];
  conclusion: string;
}

function headerValue(
  headers: Record<string, string | string[]>,
  wanted: string,
): string | undefined {
  const entry = Object.entries(headers)
    .find(([name]) => name.toLowerCase() === wanted.toLowerCase());
  if (!entry) return undefined;
  if (Array.isArray(entry[1]) && entry[1].some((item) => typeof item !== "string")) {
    return undefined;
  }
  if (!Array.isArray(entry[1]) && typeof entry[1] !== "string") return undefined;
  const value = Array.isArray(entry[1]) ? entry[1].join(", ") : entry[1];
  return value.trim() || undefined;
}

function finding(
  evidenceId: string,
  ruleId: string,
  title: string,
  status: HeaderCheckStatus,
  reason: string,
): HeaderCheckFinding {
  return { rule_id: ruleId, title, status, reason, evidence_id: evidenceId };
}

function hasFrameAncestors(csp: string | undefined): boolean {
  if (!csp) return false;
  return csp.split(";").some((directive) => {
    const [name, ...values] = directive.trim().split(/\s+/u);
    return name?.toLowerCase() === "frame-ancestors" && values.length > 0;
  });
}

function validXFrameOptions(value: string | undefined): boolean {
  if (!value) return false;
  return /^(?:DENY|SAMEORIGIN)$/iu.test(value.trim());
}

function validHsts(value: string | undefined): boolean {
  if (!value) return false;
  const match = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?(?:\s*;|\s*$)/iu.exec(value);
  return Boolean(match && Number(match[1]) > 0);
}

/**
 * 对已经保存并通过完整性校验的 HTTP 证据做离线、确定性的响应头检查。
 * `review` 表示需要结合应用用途复核或加固，不等于漏洞已确认。
 */
export function checkHttpSecurityHeaders(record: EvidenceRecord): SecurityHeaderCheckResult {
  const { evidence_id: evidenceId, observation } = record;
  const { response } = observation;
  const headers = response.headers;
  const contentType = headerValue(headers, "content-type");
  const hasRepresentation = response.body_bytes > 0 &&
    response.status !== 204 && response.status !== 304;
  const isHtml = Boolean(contentType &&
    /^(?:text\/html|application\/xhtml\+xml)(?:\s*;|$)/iu.test(contentType));
  const csp = headerValue(headers, "content-security-policy");
  const findings: HeaderCheckFinding[] = [];

  findings.push(hasRepresentation
    ? finding(evidenceId, "HDR-CONTENT-TYPE", "响应内容类型", contentType ? "pass" : "review",
      contentType ? "响应声明了 Content-Type" : "响应包含正文但未声明 Content-Type，需要复核浏览器解释方式")
    : finding(evidenceId, "HDR-CONTENT-TYPE", "响应内容类型", "not_applicable",
      "该响应没有需要解释的正文"));

  const nosniff = headerValue(headers, "x-content-type-options");
  findings.push(hasRepresentation
    ? finding(evidenceId, "HDR-NOSNIFF", "MIME 嗅探限制",
      nosniff?.toLowerCase() === "nosniff" ? "pass" : "review",
      nosniff?.toLowerCase() === "nosniff"
        ? "X-Content-Type-Options 设置为 nosniff"
        : "未观察到有效的 X-Content-Type-Options: nosniff，建议结合资源类型复核")
    : finding(evidenceId, "HDR-NOSNIFF", "MIME 嗅探限制", "not_applicable",
      "该响应没有需要解释的正文"));

  findings.push(isHtml
    ? finding(evidenceId, "HDR-CSP", "内容安全策略", csp ? "pass" : "review",
      csp ? "HTML 响应包含 Content-Security-Policy" : "HTML 响应未观察到 Content-Security-Policy，需要结合页面脚本和资源来源设计策略")
    : finding(evidenceId, "HDR-CSP", "内容安全策略", "not_applicable",
      contentType ? "当前响应不是已识别的 HTML 文档" : "缺少 Content-Type，无法确认这是 HTML 文档"));

  const xFrameOptions = headerValue(headers, "x-frame-options");
  const frameProtected = hasFrameAncestors(csp) || validXFrameOptions(xFrameOptions);
  findings.push(isHtml
    ? finding(evidenceId, "HDR-FRAME-ANCESTORS", "页面嵌入限制",
      frameProtected ? "pass" : "review",
      frameProtected
        ? "观察到 CSP frame-ancestors 或有效的 X-Frame-Options"
        : "HTML 响应未观察到有效的页面嵌入限制；是否需要允许被嵌入仍需结合业务复核")
    : finding(evidenceId, "HDR-FRAME-ANCESTORS", "页面嵌入限制", "not_applicable",
      contentType ? "当前响应不是已识别的 HTML 文档" : "缺少 Content-Type，无法确认这是 HTML 文档"));

  let protocol: string | undefined;
  try {
    protocol = new URL(observation.request.url).protocol;
  } catch {
    protocol = undefined;
  }
  const hsts = headerValue(headers, "strict-transport-security");
  findings.push(protocol === "https:"
    ? finding(evidenceId, "HDR-HSTS", "HTTPS 强制策略", validHsts(hsts) ? "pass" : "review",
      validHsts(hsts)
        ? "HTTPS 响应包含有效且大于零的 Strict-Transport-Security max-age"
        : "HTTPS 响应未观察到有效且大于零的 Strict-Transport-Security max-age")
    : protocol === "http:"
      ? finding(evidenceId, "HDR-HSTS", "HTTPS 强制策略", "not_applicable",
        "证据中的最终请求使用 HTTP；本规则不据此判断 HSTS 配置")
      : finding(evidenceId, "HDR-HSTS", "HTTPS 强制策略", "review",
        "证据中的请求 URL 无法解析为 HTTP(S)，无法判断 HSTS 配置"));

  const summary = {
    pass: findings.filter((item) => item.status === "pass").length,
    review: findings.filter((item) => item.status === "review").length,
    not_applicable: findings.filter((item) => item.status === "not_applicable").length,
  };
  return {
    schema_version: 1,
    check_id: "http_response_headers_v1",
    evidence_id: evidenceId,
    target_url: observation.request.url,
    http_status: response.status,
    classification: "configuration_review",
    summary,
    findings,
    conclusion: summary.review > 0
      ? "发现需要结合应用用途复核的响应头配置；这些结果是加固线索，不是已确认漏洞"
      : "本组规则未发现需要复核的响应头配置；这不代表目标不存在其他安全问题",
  };
}
