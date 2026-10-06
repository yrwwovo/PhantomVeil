import { randomUUID } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";

import { inventoryPageInputs } from "../../capabilities/web/input-inventory.ts";
import { assessRedirectProbe, type RedirectProbeSample } from "../../capabilities/web/redirect-observation.ts";
import { restrictedHttpGet, validatePolicy, type HttpGetPolicy, type HttpRequestControl } from "../../capabilities/web/restricted-http-get.ts";
import { EvidenceStore, loadVerifiedEvidenceFile } from "../evidence/evidence-store.ts";
import { generateRedirectProbeReport } from "../reporting/redirect-probe-report.ts";
import { checkActionAuthorization, type AuthorizationRegistry } from "../scope/authorization-registry.ts";
import { checkUrlScope, type ScopeConfig } from "../scope/scope-guard.ts";

const EVIDENCE_ID = /^EV-\d{14}-[a-f0-9]{8}$/u;
const REDIRECT_PARAMETER = /^(?:next|return|return_url|redirect|redirect_url|url|destination|target|continue)$/iu;
const STATE_CHANGING_PATH = /(?:^|\/)(?:login|logout|register|delete|remove|update|pay|transfer|checkout)(?:\/|$)/iu;

export interface AuthorizedRedirectProbeInput {
  evidence_id: string;
  form_index: number;
  parameter_name: string;
  authorization_reference: string;
}

function headerValue(headers: Record<string, string | string[]>, name: string) {
  const value = Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
  return Array.isArray(value) ? value.join(";") : value;
}

/** Two bounded GETs against a verified form; only 3xx headers are observed, never followed. */
export async function runAuthorizedRedirectProbe(projectRoot: string, input: AuthorizedRedirectProbeInput,
  control: HttpRequestControl = {}, artifactNamespace: "opencode" | "hermes" = "opencode") {
  if (!input || !EVIDENCE_ID.test(input.evidence_id) ||
      !Number.isInteger(input.form_index) || input.form_index < 1 || input.form_index > 50 ||
      typeof input.parameter_name !== "string" || !REDIRECT_PARAMETER.test(input.parameter_name) ||
      typeof input.authorization_reference !== "string") {
    return { ok: false as const, code: "INVALID_INPUT", reason: "需要可信 EV、GET 表单序号、跳转参数名与授权引用" };
  }
  const root = path.resolve(projectRoot);
  let evidenceFile: string;
  try {
    const canonicalRoot = await realpath(root);
    const relative = path.join("evidence", artifactNamespace, `${input.evidence_id}.json`);
    evidenceFile = await realpath(path.join(canonicalRoot, relative));
    if (path.relative(canonicalRoot, evidenceFile) !== relative) throw new Error("PATH_REJECTED");
  } catch {
    return { ok: false as const, code: "EVIDENCE_NOT_FOUND", reason: "来源 EV 不在项目固定证据目录" };
  }
  const loaded = await loadVerifiedEvidenceFile(evidenceFile);
  if (!loaded.ok) return loaded;
  if (loaded.record.evidence_id !== input.evidence_id) {
    return { ok: false as const, code: "INVALID_EVIDENCE_FILE", reason: "证据编号与文件不符" };
  }
  const source = loaded.record.observation;
  if (!headerValue(source.response.headers, "content-type")?.toLowerCase().includes("text/html")) {
    return { ok: false as const, code: "NOT_HTML", reason: "来源证据不是 HTML 页面" };
  }
  const form = inventoryPageInputs(source.response.body, source.request.url).forms
    .find(item => item.index === input.form_index);
  if (!form || form.method !== "get" || !form.action_valid || !form.action ||
      form.same_origin !== true || form.action_query_parameters.length ||
      !form.parameter_names.includes(input.parameter_name) ||
      !form.controls.some(item => item.name === input.parameter_name && !item.disabled &&
        !["password", "file", "hidden"].includes(item.type)) ||
      STATE_CHANGING_PATH.test(new URL(form.action).pathname)) {
    return { ok: false as const, code: "FORM_NOT_ALLOWED",
      reason: "仅接受可信 HTML 中同源、无现有查询串、非敏感路径的 GET 跳转参数" };
  }

  let scope: ScopeConfig;
  let policy: HttpGetPolicy;
  let registry: AuthorizationRegistry;
  try {
    [scope, policy, registry] = await Promise.all([
      readFile(path.join(root, "configs", "scope.local.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "configs", "http.local.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "configs", "authorization.local.json"), "utf8").then(JSON.parse),
    ]);
    if (validatePolicy(policy)) throw new Error();
  } catch {
    return { ok: false as const, code: "CONFIG_ERROR", reason: "范围、HTTP 或主动检查授权配置不可用" };
  }
  const endpoint = new URL(form.action);
  if (!["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname.toLowerCase())) {
    return { ok: false as const, code: "LOCAL_LAB_ONLY",
      reason: "当前重定向观察原型仅允许本机靶场" };
  }
  const scoped = checkUrlScope(endpoint.href, scope);
  if (!scoped.allowed || !scoped.target) {
    return { ok: false as const, code: "SCOPE_DENIED", reason: scoped.reason };
  }
  const authorization = checkActionAuthorization(scoped.target.url,
    input.authorization_reference, "redirect_probe", registry);
  if (!authorization.authorized) {
    return { ok: false as const, code: "AUTHORIZATION_DENIED", reason: authorization.reason };
  }
  const bounded: HttpGetPolicy = { ...policy, timeout_ms: Math.min(policy.timeout_ms, 3000),
    max_response_bytes: Math.min(policy.max_response_bytes, 16384), max_redirects: 0 };
  const store = new EvidenceStore({ output_dir: path.join(root, "evidence", artifactNamespace) });
  const samples: RedirectProbeSample[] = [];
  const evidenceIds: string[] = [];
  for (let index = 0; index < 2; index++) {
    const destination = `https://phantomveil-probe.invalid/${randomUUID().replaceAll("-", "")}`;
    const requestUrl = new URL(endpoint.href);
    requestUrl.searchParams.set(input.parameter_name, destination);
    const requestScope = checkUrlScope(requestUrl.href, scope);
    if (!requestScope.allowed || !requestScope.target) {
      return { ok: false as const, code: "SCOPE_DENIED", reason: requestScope.reason,
        probe_evidence_ids: evidenceIds };
    }
    const response = await restrictedHttpGet(requestScope.target.url, scope, bounded, control,
      { observe_first_redirect: true });
    if (!response.ok || !response.response) {
      return { ok: false as const, code: "HTTP_REJECTED", reason: response.reason,
        request_code: response.code, probe_evidence_ids: evidenceIds };
    }
    const saved = await store.saveHttpGet(response);
    if (!saved.ok) {
      return { ok: false as const, code: "EVIDENCE_ERROR", reason: saved.reason,
        probe_evidence_ids: evidenceIds };
    }
    evidenceIds.push(saved.evidence_id);
    samples.push({ request_url: requestScope.target.url, expected_destination: destination,
      status: response.response.status, headers: response.response.headers });
  }
  const assessment = assessRedirectProbe(endpoint.href, samples);
  const result = { ...assessment, endpoint: endpoint.href,
    parameter_name: input.parameter_name, source_evidence_id: input.evidence_id,
    probe_evidence_ids: evidenceIds, destination_contacted: false as const };
  const report = await generateRedirectProbeReport({ endpoint: endpoint.href,
    parameter_name: input.parameter_name, source_evidence_id: input.evidence_id,
    probe_evidence_ids: evidenceIds, assessment }, path.join(root, "reports", artifactNamespace));
  if (!report.ok) return { ok: false as const, code: "REPORT_ERROR", reason: report.reason, result };
  return { ok: true as const, code: "REDIRECT_PROBE_COMPLETED", reason: "两次受控 GET 与首个重定向响应已记录",
    user_summary: report.user_summary, result,
    trace: { report_id: report.report_id, report_file: report.file_path, probe_evidence_ids: evidenceIds } };
}
