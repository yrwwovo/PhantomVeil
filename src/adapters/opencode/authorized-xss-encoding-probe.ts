import { readFile, realpath } from "node:fs/promises";
import path from "node:path";

import { restrictedHttpGet, validatePolicy, type HttpGetPolicy } from "../../../capabilities/web/restricted-http-get.ts";
import { analyzeXssEncodingObservation, createXssEncodingProbe } from "../../../capabilities/web/xss-encoding-observation.ts";
import { EvidenceStore, loadVerifiedEvidenceFile } from "../../evidence/evidence-store.ts";
import { generateXssEncodingReport } from "../../reporting/xss-encoding-report.ts";
import { checkActionAuthorization, type AuthorizationRegistry } from "../../scope/authorization-registry.ts";
import { checkUrlScope, type ScopeConfig } from "../../scope/scope-guard.ts";

const EVIDENCE_ID = /^EV-\d{14}-[a-f0-9]{8}$/u;
const REFLECTION_MARKER = /^PV-REFLECT-[a-f0-9]{16}$/u;

export interface AuthorizedXssEncodingProbeInput {
  evidence_id: string;
  authorization_reference: string;
}

function headerValue(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
  return Array.isArray(value) ? value.join(";") : value;
}

/**
 * 在一次已观察到反射的 GET 参数上发送一个非执行标点探针。
 * 只比较响应源码中的编码形式，不执行浏览器或确认 XSS。
 */
export async function runAuthorizedXssEncodingProbe(
  projectRoot: string,
  input: AuthorizedXssEncodingProbeInput,
) {
  if (!input || typeof input.evidence_id !== "string" || !EVIDENCE_ID.test(input.evidence_id) ||
      typeof input.authorization_reference !== "string") {
    return { ok: false as const, code: "INVALID_INPUT",
      reason: "请提供反射检查生成的完整 EV 编号和有效授权引用" };
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
      reason: missing ? "项目中找不到该反射证据" : "无法定位项目证据文件" };
  }

  const loaded = await loadVerifiedEvidenceFile(evidenceFile);
  if (!loaded.ok) return loaded;
  if (loaded.record.evidence_id !== input.evidence_id) {
    return { ok: false as const, code: "INVALID_EVIDENCE_FILE", reason: "证据编号与文件名不一致" };
  }
  const source = loaded.record.observation;
  const contentType = headerValue(source.response.headers, "content-type");
  if (!contentType?.toLowerCase().includes("text/html")) {
    return { ok: false as const, code: "NOT_HTML", reason: "来源反射证据不是 HTML 响应" };
  }

  let sourceUrl: URL;
  let parameterName: string;
  try {
    sourceUrl = new URL(source.request.url);
    const entries = [...sourceUrl.searchParams.entries()];
    const reflectedEntries = entries.filter(([, value]) => REFLECTION_MARKER.test(value));
    if (entries.length !== 1 || reflectedEntries.length !== 1) throw new Error();
    parameterName = reflectedEntries[0][0];
    if (!source.response.body.includes(reflectedEntries[0][1])) {
      return { ok: false as const, code: "REFLECTION_NOT_PROVEN",
        reason: "来源 EV 中没有观察到对应无害标记的反射，拒绝继续主动探针" };
    }
  } catch {
    return { ok: false as const, code: "INVALID_SOURCE_EVIDENCE",
      reason: "该 EV 不是可识别的单参数反射检查证据" };
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
    return { ok: false as const, code: "CONFIG_ERROR",
      reason: "无法读取有效的范围、HTTP 或编码探针授权配置" };
  }

  sourceUrl.search = "";
  sourceUrl.hash = "";
  const endpoint = sourceUrl.href;
  const endpointScope = checkUrlScope(endpoint, scope);
  if (!endpointScope.allowed || !endpointScope.target) {
    return { ok: false as const, code: "SCOPE_DENIED", reason: endpointScope.reason };
  }
  const authorization = checkActionAuthorization(
    endpointScope.target.url, input.authorization_reference, "xss_encoding_probe", registry,
  );
  if (!authorization.authorized) {
    return { ok: false as const, code: "AUTHORIZATION_DENIED", reason: authorization.reason };
  }

  const probe = createXssEncodingProbe();
  const target = new URL(endpointScope.target.url);
  target.searchParams.set(parameterName, probe.payload);
  const targetScope = checkUrlScope(target.href, scope);
  if (!targetScope.allowed || !targetScope.target) {
    return { ok: false as const, code: "SCOPE_DENIED", reason: targetScope.reason };
  }
  const boundedPolicy: HttpGetPolicy = {
    ...httpPolicy,
    timeout_ms: Math.min(httpPolicy.timeout_ms, 3000),
    max_response_bytes: Math.min(httpPolicy.max_response_bytes, 131072),
    max_redirects: 0,
  };
  const http = await restrictedHttpGet(targetScope.target.url, scope, boundedPolicy);
  if (!http.ok || !http.response) {
    return { ok: false as const, code: "HTTP_REJECTED", cause: http.code,
      reason: `编码探针未取得响应（${http.code}）；没有生成成功证据` };
  }
  const saved = await new EvidenceStore({ output_dir: path.join(root, "evidence", "opencode") }).saveHttpGet(http);
  if (!saved.ok) {
    return { ok: false as const, code: "EVIDENCE_ERROR", reason: "响应已取得，但编码探针证据保存失败" };
  }

  const observation = analyzeXssEncodingObservation(http.response.body, probe);
  const report = await generateXssEncodingReport({
    endpoint, parameter_name: parameterName, http_status: http.response.status,
    source_evidence_id: input.evidence_id, request_evidence_id: saved.evidence_id, observation,
  }, path.join(root, "reports", "opencode"));
  const trace = { source_evidence_id: input.evidence_id, evidence_id: saved.evidence_id,
    evidence_file: saved.file_path };
  if (!report.ok) {
    return { ok: false as const, code: "REPORT_ERROR", reason: report.reason,
      result: { endpoint, parameter_name: parameterName, http_status: http.response.status, observation }, trace };
  }
  return {
    ok: true as const, code: "XSS_ENCODING_PROBE_COMPLETED",
    reason: "一次非执行 XSS 特殊字符编码观察已完成",
    user_summary: report.user_summary,
    result: { endpoint, parameter_name: parameterName, http_status: http.response.status, observation },
    trace: { ...trace, report_id: report.report_id, report_file: report.file_path },
  };
}
