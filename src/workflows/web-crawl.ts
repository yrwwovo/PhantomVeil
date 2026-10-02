import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { extractPageLinks } from "../../capabilities/web/crawl-links.ts";
import { inventoryPageInputs, type PageInputInventory } from "../../capabilities/web/input-inventory.ts";
import { restrictedHttpGet, validatePolicy, type HttpGetPolicy, type HttpRequestControl } from "../../capabilities/web/restricted-http-get.ts";
import { TASK_BUDGET_EXHAUSTED, TASK_BUDGET_UNAVAILABLE } from "../budget/session-request-budget.ts";
import { EvidenceStore } from "../evidence/evidence-store.ts";
import { generateHeaderCheckReport } from "../reporting/header-check-report.ts";
import { checkUrlScope, type ScopeConfig } from "../scope/scope-guard.ts";

export interface CrawlPolicy {
  max_pages: number;
  max_depth: number;
  max_requests: number;
  delay_ms: number;
}
export const DEFAULT_CRAWL_POLICY: Readonly<CrawlPolicy> = Object.freeze({
  max_pages: 10, max_depth: 2, max_requests: 20, delay_ms: 300,
});

function validPolicy(value: unknown): value is CrawlPolicy {
  if (!value || typeof value !== "object") return false;
  const p = value as CrawlPolicy;
  return Number.isInteger(p.max_pages) && p.max_pages >= 1 && p.max_pages <= 30 &&
    Number.isInteger(p.max_depth) && p.max_depth >= 0 && p.max_depth <= 4 &&
    Number.isInteger(p.max_requests) && p.max_requests >= 1 && p.max_requests <= 60 &&
    Number.isInteger(p.delay_ms) && p.delay_ms >= 100 && p.delay_ms <= 5000;
}

interface CrawlPage {
  url: string;
  depth: number;
  code: string;
  http_status?: number;
  summary?: { pass: number; review: number; not_applicable: number };
  evidence_id?: string;
  evidence_file?: string;
  report_file?: string;
  input_summary?: PageInputInventory["summary"];
}

interface AggregatedInputEntry {
  method?: "get" | "post" | "dialog";
  endpoint: string | null;
  same_origin: boolean | null;
  parameter_names: Set<string>;
  observed_on: string[];
}

const MAX_AGGREGATED_INPUTS = 100;
const MAX_PARAMETERS_PER_INPUT = 100;

function addNames(target: Set<string>, values: string[]): boolean {
  let truncated = false;
  for (const value of values) {
    if (target.has(value)) continue;
    if (target.size >= MAX_PARAMETERS_PER_INPUT) { truncated = true; continue; }
    target.add(value);
  }
  return truncated;
}

function safeText(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replace(/[\\`*_[\]|]/gu, "\\$&").replace(/[\r\n]/gu, " ");
}

/** 有界、串行、同源的普通链接发现；模型只能提供起始 URL。 */
export async function runWebCrawl(projectRoot: string, targetUrl: string, control: HttpRequestControl = {}) {
  let seed: URL;
  try {
    if (typeof targetUrl !== "string") throw new Error();
    seed = new URL(targetUrl);
    if (!["http:", "https:"].includes(seed.protocol) || seed.username || seed.password || seed.search) throw new Error();
    seed.hash = "";
    seed.search = "";
  } catch {
    return { ok: false as const, code: "INVALID_INPUT", reason: "请输入不含账号密码、查询参数的完整 HTTP(S) 起始 URL" };
  }
  const root = path.resolve(projectRoot);
  let scope: ScopeConfig;
  let httpPolicy: HttpGetPolicy;
  let policy: CrawlPolicy = { ...DEFAULT_CRAWL_POLICY };
  try {
    scope = JSON.parse(await readFile(path.join(root, "configs/scope.local.json"), "utf8"));
    httpPolicy = JSON.parse(await readFile(path.join(root, "configs/http.local.json"), "utf8"));
    try {
      policy = JSON.parse(await readFile(path.join(root, "configs/crawl.local.json"), "utf8"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (!validPolicy(policy) || validatePolicy(httpPolicy)) throw new Error();
  } catch {
    return { ok: false as const, code: "CONFIG_ERROR", reason: "范围、HTTP 或爬取配置无效，未启动爬取" };
  }
  if (!checkUrlScope(seed.href, scope).allowed) {
    return { ok: false as const, code: "SCOPE_DENIED", reason: "起始 URL 不在项目授权范围内" };
  }
  // 上限只收紧既有策略，不扩大网络权限。
  const boundedHttp = { ...httpPolicy, timeout_ms: Math.min(httpPolicy.timeout_ms, 5000),
    max_response_bytes: Math.min(httpPolicy.max_response_bytes, 262144),
    max_redirects: Math.min(httpPolicy.max_redirects, 5) };
  const queue = [{ url: seed.href, depth: 0 }];
  const discovered = new Set([seed.href]);
  const requested = new Set<string>();
  const pages: CrawlPage[] = [];
  const skipped: Record<string, number> = {};
  const skip = (reason: string) => { skipped[reason] = (skipped[reason] ?? 0) + 1; };
  let lastRequest = -Infinity;
  let requests = 0;
  let stopReason = "queue_exhausted";
  let storageFailure = false;
  let inputMapTruncated = false;
  let observedForms = 0;
  let observedControls = 0;
  const pagesWithInputs = new Set<string>();
  const formMap = new Map<string, AggregatedInputEntry>();
  const queryMap = new Map<string, AggregatedInputEntry>();

  const mergeInputInventory = (inventory: PageInputInventory) => {
    if (inventory.truncated) inputMapTruncated = true;
    observedForms += inventory.summary.forms;
    observedControls += inventory.summary.controls;
    if (inventory.summary.forms || inventory.summary.query_endpoints) pagesWithInputs.add(inventory.page_url);
    for (const form of inventory.forms) {
      const key = `${form.method}\0${form.action ?? `invalid:${inventory.page_url}:${form.index}`}`;
      let entry = formMap.get(key);
      if (!entry) {
        if (formMap.size >= MAX_AGGREGATED_INPUTS) { inputMapTruncated = true; continue; }
        entry = { method: form.method, endpoint: form.action, same_origin: form.same_origin,
          parameter_names: new Set(), observed_on: [] };
        formMap.set(key, entry);
      }
      if (addNames(entry.parameter_names, [...form.action_query_parameters, ...form.parameter_names])) {
        inputMapTruncated = true;
      }
      if (!entry.observed_on.includes(inventory.page_url)) entry.observed_on.push(inventory.page_url);
    }
    for (const query of inventory.query_endpoints) {
      let entry = queryMap.get(query.endpoint);
      if (!entry) {
        if (queryMap.size >= MAX_AGGREGATED_INPUTS) { inputMapTruncated = true; continue; }
        entry = { endpoint: query.endpoint, same_origin: query.same_origin,
          parameter_names: new Set(), observed_on: [] };
        queryMap.set(query.endpoint, entry);
      }
      if (addNames(entry.parameter_names, query.parameter_names)) inputMapTruncated = true;
      if (!entry.observed_on.includes(inventory.page_url)) entry.observed_on.push(inventory.page_url);
    }
  };

  const eligible = (value: string, base: string): string | undefined => {
    try {
      const url = new URL(value, base);
      if (url.origin !== seed.origin || url.username || url.password || url.search) return undefined;
      url.hash = "";
      url.search = "";
      return checkUrlScope(url.href, scope).allowed ? url.href : undefined;
    } catch { return undefined; }
  };

  const store = new EvidenceStore({ output_dir: path.join(root, "evidence/opencode") });
  while (queue.length) {
    if (pages.length >= policy.max_pages) { stopReason = "page_limit"; break; }
    if (requests >= policy.max_requests) { stopReason = "request_limit"; break; }
    const item = queue.shift()!;
    if (requested.has(item.url)) { skip("duplicate"); continue; }
    let blockReason: string | undefined;
    const response = await restrictedHttpGet(item.url, scope, boundedHttp, {
      before_request: async value => {
        const url = eligible(value, seed.href);
        if (!url) return blockReason = "origin_or_query_blocked";
        if (requested.has(url)) return blockReason = "duplicate";
        if (requests >= policy.max_requests) return blockReason = "request_limit";
        const remaining = policy.delay_ms - (performance.now() - lastRequest);
        if (remaining > 0) await delay(remaining);
        const budgetBlock = await control.before_request?.(url);
        if (budgetBlock) return blockReason = budgetBlock;
        requested.add(url);
        requests++;
        lastRequest = performance.now();
        return undefined;
      },
    });
    if (!response.ok || !response.response) {
      pages.push({ ...item, code: blockReason ?? response.code });
      if (blockReason === "request_limit") { stopReason = "request_limit"; break; }
      if (blockReason === TASK_BUDGET_EXHAUSTED || blockReason === TASK_BUDGET_UNAVAILABLE) {
        stopReason = blockReason; break;
      }
      continue;
    }
    const final = response.response;
    final.url = eligible(final.url, seed.href)!;
    const saved = await store.saveHttpGet(response);
    if (!saved.ok) {
      pages.push({ url: final.url, depth: item.depth, code: "EVIDENCE_ERROR" });
      storageFailure = true; stopReason = "storage_error"; break;
    }
    const report = await generateHeaderCheckReport(saved.file_path, path.join(root, "reports/opencode"));
    const page: CrawlPage = { url: final.url, depth: item.depth, code: report.ok ? "CHECKED" : "REPORT_ERROR",
      http_status: final.status, evidence_id: saved.evidence_id, evidence_file: saved.file_path };
    if (!report.ok) {
      pages.push(page); storageFailure = true; stopReason = "storage_error"; break;
    }
    page.summary = report.result.summary;
    page.report_file = report.file_path;
    pages.push(page);
    const type = final.headers["content-type"];
    const encoding = final.headers["content-encoding"];
    if (final.status < 200 || final.status >= 300 || typeof type !== "string" ||
        !/^text\/html(?:\s*;|$)/iu.test(type) || (encoding && encoding !== "identity")) continue;
    const inputInventory = inventoryPageInputs(final.body, final.url);
    page.input_summary = inputInventory.summary;
    mergeInputInventory(inputInventory);
    const links = extractPageLinks(final.body, final.url);
    if (links.truncated) skip("links_per_page_limit");
    for (const href of links.links) {
      const url = eligible(href, links.base_url);
      if (!url) { skip("scope_origin_or_query"); continue; }
      if (discovered.has(url) || requested.has(url)) { skip("duplicate"); continue; }
      if (item.depth >= policy.max_depth) { skip("depth_limit"); continue; }
      if (discovered.size >= 200) { skip("discovery_limit"); continue; }
      discovered.add(url);
      queue.push({ url, depth: item.depth + 1 });
    }
  }
  const checked = pages.filter(p => p.code === "CHECKED");
  const failed = pages.length - checked.length;
  const reviewPages = checked.filter(p => (p.summary?.review ?? 0) > 0).length;
  const forms = [...formMap.values()].map(entry => ({ ...entry, parameter_names: [...entry.parameter_names] }));
  const queryEndpoints = [...queryMap.values()].map(entry => ({
    endpoint: entry.endpoint!, same_origin: entry.same_origin!,
    parameter_names: [...entry.parameter_names], observed_on: entry.observed_on,
  }));
  const inputMap = {
    summary: { pages_with_inputs: pagesWithInputs.size, forms_observed: observedForms,
      controls_observed: observedControls, unique_form_actions: forms.length,
      unique_query_endpoints: queryEndpoints.length },
    forms, query_endpoints: queryEndpoints, truncated: inputMapTruncated,
    conclusion: "输入入口来自静态 HTML，只用于后续测试规划；未执行 JavaScript、提交表单或确认漏洞。",
  };
  const stopLabels: Record<string, string> = { queue_exhausted: "本次可跟进链接已处理", page_limit: "达到页面上限",
    request_limit: "达到请求上限", storage_error: "保存记录失败",
    [TASK_BUDGET_EXHAUSTED]: "达到整次会话请求预算",
    [TASK_BUDGET_UNAVAILABLE]: "无法读取整次会话请求预算，已停止" };
  const userSummary = [
    `目标：${seed.href}`, `有限范围信息收集结束：${stopLabels[stopReason]}。`,
    `检查 ${checked.length} 个响应；未完成 ${failed} 项；请求尝试 ${requests} 次（含重定向）。`,
    `其中 ${reviewPages} 个响应有配置复核建议，尚未确认漏洞。`,
    `静态 HTML 中发现 ${observedForms} 个表单、${observedControls} 个控件，汇总为 ${forms.length} 个表单目标和 ${queryEndpoints.length} 个查询端点。`,
    `限制：最多 ${policy.max_pages} 页、深度 ${policy.max_depth}、间隔 ${policy.delay_ms} 毫秒。`,
    "仅发现普通 HTML 链接，不执行 JavaScript、不提交表单；本次结果不代表已覆盖全站。",
  ].join("\n");
  const result = { start_url: seed.href, policy, requests, checked: checked.length, failed,
    stop_reason: stopReason, skipped, pages, input_map: inputMap, user_summary: userSummary };
  const reportPath = path.join(root, "reports/opencode", `CRAWL-${Date.now()}-${randomUUID().slice(0, 8)}.md`);
  const markdown = ["# 受限爬取与响应头检查", "", ...userSummary.split("\n").map(safeText), "",
    "| 页面 | 深度 | HTTP | 结果 | 需复核项 | 证据 |", "|---|---:|---:|---|---:|---|",
    ...pages.map(p => `| ${safeText(p.url)} | ${p.depth} | ${p.http_status ?? "—"} | ${p.code} | ${p.summary?.review ?? "—"} | ${p.evidence_id ?? "—"} |`),
    "", "## 静态表单与参数入口", "",
    `观察到 ${observedForms} 个表单、${observedControls} 个控件；合并后 ${forms.length} 个表单目标、${queryEndpoints.length} 个查询端点。`,
    inputMapTruncated ? "结果达到清点上限，以下列表可能不完整。" : "清点未达到聚合上限。",
    "", "### 表单目标", "", "| 方法 | 目标 | 同源 | 参数名称 | 出现页面 |", "|---|---|---|---|---|",
    ...(forms.length ? forms.map(form => `| ${form.method?.toUpperCase()} | ${safeText(form.endpoint ?? "无效 action")} | ${form.same_origin === null ? "—" : form.same_origin ? "是" : "否"} | ${safeText(form.parameter_names.join(", ") || "无命名参数")} | ${safeText(form.observed_on.join(", "))} |`) : ["| — | 未发现 | — | — | — |"]),
    "", "### 查询参数端点", "", "| 目标 | 同源 | 参数名称 | 出现页面 |", "|---|---|---|---|",
    ...(queryEndpoints.length ? queryEndpoints.map(query => `| ${safeText(query.endpoint)} | ${query.same_origin ? "是" : "否"} | ${safeText(query.parameter_names.join(", "))} | ${safeText(query.observed_on.join(", "))} |`) : ["| 未发现 | — | — | — |"]),
    "", `停止原因：${stopReason}`, `跳过统计：${JSON.stringify(skipped)}`, "",
    "网页内容没有作为执行指令。输入入口仅来自静态 HTML，未提交表单，也不表示存在漏洞。完整单页规则结果见同目录下引用该证据编号的报告。", "",
  ].join("\n");
  try {
    await mkdir(path.dirname(reportPath), { recursive: true });
    await writeFile(reportPath, markdown, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch {
    return { ok: false as const, code: "REPORT_ERROR", reason: "爬取汇总报告保存失败", ...result };
  }
  return { ok: !storageFailure && failed === 0, code: storageFailure || failed ? "CRAWL_PARTIAL" : "CRAWL_COMPLETED",
    ...result, report_file: reportPath };
}
