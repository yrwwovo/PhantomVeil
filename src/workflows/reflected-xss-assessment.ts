import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { HttpRequestControl } from "../../capabilities/web/restricted-http-get.ts";
import { TASK_BUDGET_EXHAUSTED, TASK_BUDGET_UNAVAILABLE } from "../budget/session-request-budget.ts";

import { runAuthorizedParameterReflectionCheck } from "./parameter-reflection-check.ts";
import { runAuthorizedXssEncodingProbe } from "./xss-encoding-probe.ts";
import { runEvidenceInputInventory } from "./evidence-input-inventory.ts";
import { runEvidenceReflectionContext } from "./evidence-reflection-context.ts";
import { checkActionAuthorization, type AuthorizationRegistry } from "../scope/authorization-registry.ts";
import { checkUrlScope, type ScopeConfig } from "../scope/scope-guard.ts";
import { runWebCrawl } from "./web-crawl.ts";
import { runXssHypothesisTriage } from "./xss-hypothesis-triage.ts";

export interface ReflectedXssAssessmentPolicy {
  max_parameters: number;
  delay_ms: number;
}

export const DEFAULT_REFLECTED_XSS_ASSESSMENT_POLICY: Readonly<ReflectedXssAssessmentPolicy> =
  Object.freeze({ max_parameters: 10, delay_ms: 300 });

export interface ReflectedXssAssessmentInput {
  url: string;
  authorization_reference: string;
}

export interface ReflectedXssAssessmentDependencies {
  artifactNamespace?: "opencode" | "hermes";
  approve?: (details: {
    target: string;
    max_parameters: number;
    max_encoding_probes: number;
    may_write_hypotheses: true;
  }) => Promise<void>;
  wait?: (milliseconds: number) => Promise<void>;
  request_control?: HttpRequestControl;
}

interface Candidate {
  source_evidence_id: string;
  endpoint: string;
  form_index: number;
  parameter_name: string;
}

interface AssessmentItem {
  endpoint: string;
  parameter_name: string;
  source_evidence_id: string;
  request_evidence_id?: string;
  reflection: "reflected" | "not_reflected" | "inconclusive" | "failed";
  context?: string;
  encoding_evidence_id?: string;
  encoding_outcome?: string;
  hypothesis_action?: string;
  hypothesis_id?: string;
  code: string;
  reason: string;
}

const HIGH_IMPACT_PATH = /(?:^|[\/_-])(?:activate|approve|cancel|create|deactivate|delete|destroy|disable|logout|remove|reset|revoke|save|submit|update)(?=$|[\/_-])/iu;
const SENSITIVE_PARAMETER = /(?:csrf|delete|file|logout|password|passwd|remove|secret|token)/iu;
const SAFE_CONTROL_TYPES = new Set(["text", "search", "email", "url", "tel", "number", "textarea", "select"]);
const FATAL_CODES = new Set([
  "AUTHORIZATION_DENIED", "CONFIG_ERROR", "EVIDENCE_ERROR", "HTTP_REJECTED", "SCOPE_DENIED",
  TASK_BUDGET_EXHAUSTED, TASK_BUDGET_UNAVAILABLE,
]);

function validPolicy(value: unknown): value is ReflectedXssAssessmentPolicy {
  if (!value || typeof value !== "object") return false;
  const policy = value as ReflectedXssAssessmentPolicy;
  return Number.isInteger(policy.max_parameters) && policy.max_parameters >= 1 && policy.max_parameters <= 20 &&
    Number.isInteger(policy.delay_ms) && policy.delay_ms >= 100 && policy.delay_ms <= 5000;
}

function safeText(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replace(/[\\`*_[\]|]/gu, "\\$&").replace(/[\r\n]/gu, " ");
}

function safeCandidate(endpoint: string, parameter: string, controlTypes: string[]): boolean {
  try {
    const url = new URL(endpoint);
    return !HIGH_IMPACT_PATH.test(url.pathname) && !SENSITIVE_PARAMETER.test(parameter) &&
      controlTypes.some(type => SAFE_CONTROL_TYPES.has(type));
  } catch {
    return false;
  }
}

async function saveAssessmentReport(
  root: string,
  target: string,
  policy: ReflectedXssAssessmentPolicy,
  discovered: number,
  skippedHighImpact: number,
  items: AssessmentItem[],
  artifactNamespace: "opencode" | "hermes",
) {
  const generatedAt = new Date().toISOString();
  const reportId = `AXSS-${generatedAt.replace(/[-:.TZ]/gu, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
  const filePath = path.join(root, "reports", artifactNamespace, `${reportId}.md`);
  const reflected = items.filter(item => item.reflection === "reflected").length;
  const sensitive = items.filter(item => item.context === "sensitive_context_observed").length;
  const encodingChecks = items.filter(item => item.encoding_evidence_id).length;
  const rawCandidates = items.filter(item =>
    item.encoding_outcome === "raw_special_characters_observed").length;
  const hypotheses = items.filter(item => item.hypothesis_id).length;
  const markdown = [
    "# 授权反射型 XSS 主动评估", "",
    `- 目标：${safeText(target)}`,
    `- 生成时间：${generatedAt}`,
    `- 候选参数：${discovered}`,
    `- 实际检查：${items.length} / ${policy.max_parameters}`,
    `- 跳过高影响候选：${skippedHighImpact}`,
    `- 观察到反射：${reflected}`,
    `- 敏感上下文：${sensitive}`, "",
    `- 编码观察：${encodingChecks}`,
    `- 原样字符候选：${rawCandidates}`,
    `- 已关联 HYP：${hypotheses}`, "",
    "| 端点 | 参数 | 反射结果 | 上下文 | 编码观察 | HYP 处理 | 请求证据 |", "|---|---|---|---|---|---|---|",
    ...(items.length ? items.map(item =>
      `| ${safeText(item.endpoint)} | ${safeText(item.parameter_name)} | ${item.reflection} | ${item.context ?? "—"} | ${item.encoding_outcome ?? "—"} | ${item.hypothesis_action ?? "—"}${item.hypothesis_id ? ` (${item.hypothesis_id})` : ""} | ${item.request_evidence_id ?? "—"} |`) :
      ["| — | — | 未发现可安全检查的 GET 参数 | — | — | — | — |"]), "",
    "本任务在一次批准后连续执行有限数量的低影响 GET 参数检查和候选 HYP 关联。反射、敏感上下文或原样字符都不是已确认 XSS。", "",
  ].join("\n");
  try {
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, `${markdown}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    return { ok: true as const, report_id: reportId, report_file: filePath };
  } catch {
    return { ok: false as const, reason: "主动评估已完成，但汇总报告保存失败" };
  }
}

/** 一次任务审批后，在既有 Scope 与授权引用内连续执行有限的非破坏性反射检查。 */
export async function runAuthorizedReflectedXssAssessment(
  projectRoot: string,
  input: ReflectedXssAssessmentInput,
  dependencies: ReflectedXssAssessmentDependencies = {},
) {
  let target: URL;
  try {
    if (!input || typeof input.url !== "string" || typeof input.authorization_reference !== "string") throw new Error();
    target = new URL(input.url);
    if (!["http:", "https:"].includes(target.protocol) || target.username || target.password || target.search) throw new Error();
    target.hash = "";
  } catch {
    return { ok: false as const, code: "INVALID_INPUT",
      reason: "请提供不含账号密码、查询参数的完整 HTTP(S) 目标和有效授权引用" };
  }

  const root = path.resolve(projectRoot);
  const artifactNamespace = dependencies.artifactNamespace ?? "opencode";
  let scope: ScopeConfig;
  let registry: AuthorizationRegistry;
  let policy: ReflectedXssAssessmentPolicy = { ...DEFAULT_REFLECTED_XSS_ASSESSMENT_POLICY };
  try {
    [scope, registry] = await Promise.all([
      readFile(path.join(root, "configs", "scope.local.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "configs", "authorization.local.json"), "utf8").then(JSON.parse),
    ]);
    try {
      policy = JSON.parse(await readFile(path.join(root, "configs", "active-assessment.local.json"), "utf8"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (!validPolicy(policy)) throw new Error();
  } catch {
    return { ok: false as const, code: "CONFIG_ERROR",
      reason: "无法读取有效的范围、授权登记或主动评估配置" };
  }
  const scoped = checkUrlScope(target.href, scope);
  if (!scoped.allowed || !scoped.target) {
    return { ok: false as const, code: "SCOPE_DENIED", reason: scoped.reason };
  }
  for (const action of [
    "parameter_reflection_check", "xss_encoding_probe", "hypothesis_create",
  ] as const) {
    const authorization = checkActionAuthorization(
      scoped.target.url, input.authorization_reference, action, registry,
    );
    if (!authorization.authorized) {
      return { ok: false as const, code: "AUTHORIZATION_DENIED",
        reason: `完整 XSS 评估缺少 ${action} 授权：${authorization.reason}` };
    }
  }
  if (!dependencies.approve) {
    return { ok: false as const, code: "APPROVAL_UNAVAILABLE",
      reason: "当前运行环境无法进行任务级批准，主动评估已停止且未发送请求" };
  }
  try {
    await dependencies.approve({
      target: scoped.target.url,
      max_parameters: policy.max_parameters,
      max_encoding_probes: policy.max_parameters,
      may_write_hypotheses: true,
    });
  } catch {
    return { ok: false as const, code: "APPROVAL_DENIED",
      reason: "用户未批准本次主动评估；未执行网络请求" };
  }

  const crawl = await runWebCrawl(root, scoped.target.url, dependencies.request_control,
    artifactNamespace);
  if (!("pages" in crawl)) {
    return { ok: false as const, code: "CRAWL_FAILED", reason: crawl.reason };
  }
  if (crawl.stop_reason === TASK_BUDGET_EXHAUSTED || crawl.stop_reason === TASK_BUDGET_UNAVAILABLE) {
    return { ok: false as const, code: crawl.stop_reason,
      reason: "整次会话请求预算耗尽或不可用，主动评估已停止", crawl_report_file: crawl.report_file };
  }

  const candidates: Candidate[] = [];
  const seen = new Set<string>();
  let skippedHighImpact = 0;
  for (const page of crawl.pages) {
    if (!page.evidence_id) continue;
    const inventory = await runEvidenceInputInventory(root, { evidence_id: page.evidence_id },
      artifactNamespace);
    if (!inventory.ok) continue;
    for (const form of inventory.result.forms) {
      if (form.method !== "get" || !form.action || !form.action_valid || form.same_origin !== true ||
          form.action_query_parameters.length > 0) continue;
      for (const parameter of form.parameter_names) {
        const types = form.controls.filter(control => control.name === parameter && !control.disabled)
          .map(control => control.type);
        if (!safeCandidate(form.action, parameter, types)) {
          skippedHighImpact++;
          continue;
        }
        const key = `${form.action}\u0000${parameter}`;
        if (seen.has(key)) continue;
        seen.add(key);
        candidates.push({ source_evidence_id: page.evidence_id, endpoint: form.action,
          form_index: form.index, parameter_name: parameter });
      }
    }
  }

  const selected = candidates.slice(0, policy.max_parameters);
  const items: AssessmentItem[] = [];
  let stoppedEarly = false;
  let stopReason: string | null = null;
  const wait = dependencies.wait ?? (milliseconds => delay(milliseconds).then(() => undefined));
  for (const candidate of selected) {
    await wait(policy.delay_ms);
    const reflection = await runAuthorizedParameterReflectionCheck(root, {
      evidence_id: candidate.source_evidence_id,
      form_index: candidate.form_index,
      parameter_name: candidate.parameter_name,
      authorization_reference: input.authorization_reference,
    }, dependencies.request_control, artifactNamespace);
    if (!reflection.ok) {
      items.push({ ...candidate, reflection: "failed", code: reflection.code, reason: reflection.reason });
      if (FATAL_CODES.has(reflection.code)) {
        stoppedEarly = true;
        stopReason = reflection.code;
        break;
      }
      continue;
    }
    const item: AssessmentItem = {
      ...candidate, request_evidence_id: reflection.trace.evidence_id,
      reflection: reflection.result.outcome, code: reflection.code, reason: reflection.reason,
    };
    if (reflection.result.outcome === "reflected") {
      const context = await runEvidenceReflectionContext(root,
        { evidence_id: reflection.trace.evidence_id }, artifactNamespace);
      item.context = context.ok ? context.result.outcome : `context_${context.code.toLowerCase()}`;
      await wait(policy.delay_ms);
      const encoding = await runAuthorizedXssEncodingProbe(root, {
        evidence_id: reflection.trace.evidence_id,
        authorization_reference: input.authorization_reference,
      }, dependencies.request_control, artifactNamespace);
      if (!encoding.ok) {
        item.encoding_outcome = `failed_${encoding.code.toLowerCase()}`;
        item.code = encoding.code;
        item.reason = encoding.reason;
        items.push(item);
        if (FATAL_CODES.has(encoding.code)) {
          stoppedEarly = true;
          stopReason = encoding.code;
          break;
        }
        continue;
      }
      item.encoding_evidence_id = encoding.trace.evidence_id;
      item.encoding_outcome = encoding.result.observation.outcome;
      const triage = await runXssHypothesisTriage(root, {
        reflection_evidence_id: reflection.trace.evidence_id,
        encoding_evidence_id: encoding.trace.evidence_id,
        authorization_reference: input.authorization_reference,
      }, {
        artifactNamespace,
        // 整项任务已在任何网络请求前获得一次明确批准，不再逐参数重复询问。
        approve: async () => {},
      });
      item.hypothesis_action = triage.code;
      if ("hypothesis_id" in triage) item.hypothesis_id = triage.hypothesis_id;
      if (!triage.ok) {
        item.code = triage.code;
        item.reason = triage.reason;
        items.push(item);
        stoppedEarly = true;
        stopReason = triage.code;
        break;
      }
    }
    items.push(item);
  }

  const report = await saveAssessmentReport(
    root, scoped.target.url, policy, candidates.length, skippedHighImpact, items,
    artifactNamespace,
  );
  if (!report.ok) {
    return { ok: false as const, code: "REPORT_ERROR", reason: report.reason,
      result: { candidates_discovered: candidates.length, checked: items.length, items } };
  }
  const reflected = items.filter(item => item.reflection === "reflected").length;
  const sensitive = items.filter(item => item.context === "sensitive_context_observed").length;
  const encodingChecked = items.filter(item => item.encoding_evidence_id).length;
  const rawCandidates = items.filter(item =>
    item.encoding_outcome === "raw_special_characters_observed").length;
  const hypothesesLinked = items.filter(item => item.hypothesis_id).length;
  const userSummary = [
    `目标：${scoped.target.url}`,
    `一次任务批准后的主动评估已结束：发现 ${candidates.length} 个可检查 GET 参数，实际检查 ${items.length} 个。`,
    `观察到反射 ${reflected} 个，其中敏感上下文 ${sensitive} 个；本轮未确认 XSS。`,
    `对 ${encodingChecked} 个反射参数完成编码观察，发现 ${rawCandidates} 个原样字符候选，关联 ${hypothesesLinked} 个 HYP。`,
    `跳过 ${skippedHighImpact} 个密码、文件、秘密参数或明显高影响路径候选。`,
    candidates.length > policy.max_parameters ? `达到本次参数上限 ${policy.max_parameters}，其余候选未执行。` :
      "未达到本次参数检查上限。",
    stoppedEarly ? `遇到 ${stopReason} 后提前停止，未绕过限制重试。` :
      "没有执行 POST、登录注册、数据修改、脚本载荷或高风险操作；HYP 只会记录为 suspected。",
  ].join("\n");
  return {
    ok: !stoppedEarly, code: stoppedEarly ? "ASSESSMENT_PARTIAL" : "ASSESSMENT_COMPLETED",
    reason: stoppedEarly ? "主动评估部分完成" : "授权范围内的反射型 XSS 主动评估已完成",
    user_summary: userSummary,
    result: { policy, candidates_discovered: candidates.length, skipped_high_impact: skippedHighImpact,
      checked: items.length, reflected, sensitive_contexts: sensitive,
      encoding_checked: encodingChecked, raw_character_candidates: rawCandidates,
      hypotheses_linked: hypothesesLinked, stopped_early: stoppedEarly,
      stop_reason: stopReason, items },
    trace: { report_id: report.report_id, report_file: report.report_file },
  };
}
