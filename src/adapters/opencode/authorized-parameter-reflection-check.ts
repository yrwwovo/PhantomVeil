import { randomUUID } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";

import { inventoryPageInputs } from "../../../capabilities/web/input-inventory.ts";
import { restrictedHttpGet, validatePolicy, type HttpGetPolicy } from "../../../capabilities/web/restricted-http-get.ts";
import { EvidenceStore, loadVerifiedEvidenceFile } from "../../evidence/evidence-store.ts";
import { generateParameterReflectionReport, type ParameterReflectionResult } from "../../reporting/parameter-reflection-report.ts";
import { checkActionAuthorization, type AuthorizationRegistry } from "../../scope/authorization-registry.ts";
import { checkUrlScope, type ScopeConfig } from "../../scope/scope-guard.ts";

const EVIDENCE_ID = /^EV-\d{14}-[a-f0-9]{8}$/u;

export interface AuthorizedParameterReflectionInput {
  evidence_id: string;
  form_index: number;
  parameter_name: string;
  authorization_reference: string;
}

function headerValue(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
  return Array.isArray(value) ? value.join(";") : value;
}

function countOccurrences(body: string, marker: string): number {
  let count = 0;
  let offset = 0;
  while ((offset = body.indexOf(marker, offset)) !== -1) {
    count++;
    offset += marker.length;
  }
  return count;
}

/**
 * 对已在可信 HTML 证据中发现的一个 GET 参数发送一次无害标记。
 * 不执行脚本、不使用漏洞载荷、不自动创建或确认 HYP。
 */
export async function runAuthorizedParameterReflectionCheck(
  projectRoot: string,
  input: AuthorizedParameterReflectionInput,
) {
  if (!input || typeof input.evidence_id !== "string" || !EVIDENCE_ID.test(input.evidence_id) ||
      !Number.isInteger(input.form_index) || input.form_index < 1 || input.form_index > 50 ||
      typeof input.parameter_name !== "string" || input.parameter_name.trim() === "" ||
      input.parameter_name.length > 128 || /[\u0000-\u001f\u007f]/u.test(input.parameter_name) ||
      typeof input.authorization_reference !== "string") {
    return { ok: false as const, code: "INVALID_INPUT", reason: "请提供有效 EV 编号、表单序号、参数名称和授权引用" };
  }
  const root = path.resolve(projectRoot);
  let evidenceFile: string;
  try {
    const canonicalRoot = await realpath(root);
    const relativeFile = path.join("evidence", "opencode", `${input.evidence_id}.json`);
    evidenceFile = await realpath(path.join(canonicalRoot, relativeFile));
    if (path.relative(canonicalRoot, evidenceFile) !== relativeFile) {
      return { ok: false as const, code: "PATH_REJECTED", reason: "证据文件被重定向到其他位置，拒绝读取" };
    }
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    return { ok: false as const, code: missing ? "NOT_FOUND" : "IO_ERROR",
      reason: missing ? "项目中找不到该来源证据" : "无法定位项目证据文件" };
  }

  const loaded = await loadVerifiedEvidenceFile(evidenceFile);
  if (!loaded.ok) return loaded;
  if (loaded.record.evidence_id !== input.evidence_id) {
    return { ok: false as const, code: "INVALID_EVIDENCE_FILE", reason: "证据编号与文件名不一致" };
  }
  const source = loaded.record.observation;
  const contentType = headerValue(source.response.headers, "content-type");
  if (!contentType?.toLowerCase().includes("text/html")) {
    return { ok: false as const, code: "NOT_HTML", reason: "来源证据不是 HTML 页面" };
  }
  const inventory = inventoryPageInputs(source.response.body, source.request.url);
  const form = inventory.forms.find(item => item.index === input.form_index);
  if (!form) return { ok: false as const, code: "FORM_NOT_FOUND", reason: "来源证据中找不到该表单序号" };
  if (form.method !== "get") {
    return { ok: false as const, code: "METHOD_NOT_ALLOWED", reason: "本阶段只允许检查静态 HTML 中发现的 GET 表单" };
  }
  if (!form.action_valid || !form.action || form.same_origin !== true || form.action_query_parameters.length) {
    return { ok: false as const, code: "ACTION_NOT_ALLOWED", reason: "表单 action 无效、非同源或包含无法安全复用的查询参数" };
  }
  if (!form.parameter_names.includes(input.parameter_name)) {
    return { ok: false as const, code: "PARAMETER_NOT_FOUND", reason: "该参数不是来源证据中可提交的命名控件" };
  }

  let scope: ScopeConfig;
  let httpPolicy: HttpGetPolicy;
  let registry: AuthorizationRegistry;
  try {
    const [scopeJson, policyJson, registryJson] = await Promise.all([
      readFile(path.join(root, "configs", "scope.local.json"), "utf8"),
      readFile(path.join(root, "configs", "http.local.json"), "utf8"),
      readFile(path.join(root, "configs", "authorization.local.json"), "utf8"),
    ]);
    scope = JSON.parse(scopeJson);
    httpPolicy = JSON.parse(policyJson);
    registry = JSON.parse(registryJson);
    if (validatePolicy(httpPolicy)) throw new Error();
  } catch {
    return { ok: false as const, code: "CONFIG_ERROR", reason: "无法读取有效的范围、HTTP 或主动检查授权配置" };
  }

  const target = new URL(form.action);
  const marker = `PV-REFLECT-${randomUUID().replaceAll("-", "").slice(0, 16)}`;
  target.searchParams.set(input.parameter_name, marker);
  const scoped = checkUrlScope(target.href, scope);
  if (!scoped.allowed || !scoped.target) {
    return { ok: false as const, code: "SCOPE_DENIED", reason: scoped.reason };
  }
  const authorization = checkActionAuthorization(
    scoped.target.url, input.authorization_reference, "parameter_reflection_check", registry,
  );
  if (!authorization.authorized) {
    return { ok: false as const, code: "AUTHORIZATION_DENIED", reason: authorization.reason };
  }

  const boundedPolicy: HttpGetPolicy = {
    ...httpPolicy,
    timeout_ms: Math.min(httpPolicy.timeout_ms, 3000),
    max_response_bytes: Math.min(httpPolicy.max_response_bytes, 131072),
    max_redirects: 0,
  };
  const http = await restrictedHttpGet(scoped.target.url, scope, boundedPolicy);
  if (!http.ok || !http.response) {
    return { ok: false as const, code: "HTTP_REJECTED", cause: http.code,
      reason: `主动检查未取得响应（${http.code}）；没有生成成功证据` };
  }
  const saved = await new EvidenceStore({ output_dir: path.join(root, "evidence", "opencode") }).saveHttpGet(http);
  if (!saved.ok) return { ok: false as const, code: "EVIDENCE_ERROR", reason: "响应已取得，但证据保存失败" };

  const occurrences = countOccurrences(http.response.body, marker);
  const responseType = headerValue(http.response.headers, "content-type")?.toLowerCase() ?? "";
  const textual = responseType.startsWith("text/") || responseType.includes("json") || responseType.includes("xml");
  const outcome: ParameterReflectionResult["outcome"] =
    http.response.status >= 400 || !textual ? "inconclusive" : occurrences > 0 ? "reflected" : "not_reflected";
  const conclusion = outcome === "reflected"
    ? "无害标记出现在响应正文中，说明该输入可能被页面反射；这不是 XSS 结论，仍需分析输出位置和编码。"
    : outcome === "not_reflected"
      ? "本次响应正文中未出现无害标记；这不能排除存储、异步处理或其他类型的参数问题。"
      : "响应状态或类型不适合据此判断输入是否正常反射，需要人工复核。";
  const endpoint = new URL(form.action); endpoint.search = ""; endpoint.hash = "";
  const result: ParameterReflectionResult = {
    classification: "input_reflection_observation", outcome, endpoint: endpoint.href,
    parameter_name: input.parameter_name, http_status: http.response.status,
    reflected_in_body: occurrences > 0, occurrence_count: occurrences,
    source_evidence_id: input.evidence_id, request_evidence_id: saved.evidence_id, conclusion,
  };
  const report = await generateParameterReflectionReport(result, path.join(root, "reports", "opencode"));
  const trace = { source_evidence_id: input.evidence_id, evidence_id: saved.evidence_id,
    evidence_file: saved.file_path };
  if (!report.ok) return { ok: false as const, code: "REPORT_ERROR", reason: report.reason, result, trace };
  return { ok: true as const, code: "REFLECTION_CHECK_COMPLETED", reason: "一次无害 GET 参数反射检查已完成",
    user_summary: report.user_summary, result, trace: { ...trace, report_id: report.report_id, report_file: report.file_path } };
}
