import { appendFile, lstat, open, readFile, realpath, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { approveSessionRequestBudget, reserveSessionRequest } from "../../budget/session-request-budget.ts";
import { checkUrlScope, validateScopeConfig } from "../../scope/scope-guard.ts";
import { checkHttpSecurityHeaders } from "../../../capabilities/web/security-header-check.ts";
import { loadVerifiedEvidenceFile } from "../../evidence/evidence-store.ts";
import { generateHeaderCheckReport } from "../../reporting/header-check-report.ts";
import { checkActionAuthorization, type AuthorizationAction } from "../../scope/authorization-registry.ts";
import { runTargetSetup } from "../../scope/target-setup.ts";
import { runAuthorizedParameterReflectionCheck } from "../../workflows/parameter-reflection-check.ts";
import { runAuthorizedRedirectProbe } from "../../workflows/redirect-probe.ts";
import { runEvidenceReflectionContext } from "../../workflows/evidence-reflection-context.ts";
import { runAuthorizedXssEncodingProbe } from "../../workflows/xss-encoding-probe.ts";
import { runXssHypothesisTriage } from "../../workflows/xss-hypothesis-triage.ts";
import { runAuthorizedHypothesisCreate } from "../../workflows/authorized-hypothesis-create.ts";
import { runHypothesisGet } from "../../workflows/hypothesis-get.ts";
import { runAuthorizedReflectedXssAssessment } from "../../workflows/reflected-xss-assessment.ts";
import { runEvidenceInputInventory } from "../../workflows/evidence-input-inventory.ts";
import { runEvidenceLinkInventory } from "../../workflows/evidence-link-inventory.ts";
import { runAuthorizedWebObservation } from "../../workflows/web-observation.ts";
import { runWebCrawl } from "../../workflows/web-crawl.ts";

export interface HermesTaskGrant {
  task_id: string;
  authorization_reference: string;
  allowed_urls: string[];
  pending_target?: true;
  crawl?: { seed_url: string; path_prefix: string; max_pages?: number; max_requests?: number };
  active?: { kind: "reflection" | "redirect" | "encoding" | "assessment";
    seed_url: string; path_prefix: string };
}

export interface HermesServiceOptions {
  projectRoot: string;
  task: HermesTaskGrant;
  taskFile?: string;
  sourceConfigRoot?: string;
  budgetRoot: string;
  auditFile: string;
}

function validTask(task: HermesTaskGrant): boolean {
  return typeof task?.task_id === "string" && /^[a-zA-Z0-9._-]{6,100}$/u.test(task.task_id) &&
    typeof task.authorization_reference === "string" &&
    Array.isArray(task.allowed_urls) &&
    (task.pending_target === true
      ? task.allowed_urls.length === 0 && task.authorization_reference === "" &&
        !task.crawl && !task.active
      : task.allowed_urls.length > 0) &&
    task.allowed_urls.length <= 10 && task.allowed_urls.every(url => {
      if (typeof url !== "string") return false;
      try { return new URL(url).href === url; } catch { return false; }
    }) && !(task.crawl && task.active) && (!task.crawl || (typeof task.crawl.seed_url === "string" &&
      task.allowed_urls.includes(task.crawl.seed_url) &&
      new URL(task.crawl.seed_url).pathname === task.crawl.path_prefix &&
      !new URL(task.crawl.seed_url).search)) &&
    (!task.active || (["reflection", "redirect", "encoding", "assessment"].includes(task.active.kind) &&
      task.allowed_urls.includes(task.active.seed_url) &&
      new URL(task.active.seed_url).pathname === task.active.path_prefix &&
      !new URL(task.active.seed_url).search));
}

function inCrawlBranch(url: string, crawl: NonNullable<HermesTaskGrant["crawl"]>): boolean {
  try {
    const candidate = new URL(url);
    const seed = new URL(crawl.seed_url);
    const prefix = crawl.path_prefix;
    return candidate.href === url && candidate.origin === seed.origin && !candidate.search &&
      !candidate.hash && (candidate.pathname === prefix ||
        candidate.pathname.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`));
  } catch { return false; }
}

function inActiveBranch(url: string, active: NonNullable<HermesTaskGrant["active"]>): boolean {
  try {
    const candidate = new URL(url);
    const seed = new URL(active.seed_url);
    const prefix = active.path_prefix;
    return candidate.href === url && candidate.origin === seed.origin && !candidate.hash &&
      (candidate.pathname === prefix ||
        candidate.pathname.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`));
  } catch { return false; }
}

/** Only the launcher supplies task, workspace and budget paths; the model supplies tool arguments. */
export class HermesTaskService {
  readonly projectRoot: string;
  task: HermesTaskGrant;
  readonly taskFile: string | null;
  readonly sourceConfigRoot: string | null;
  readonly budgetRoot: string;
  readonly auditFile: string;
  private authorizingTask = false;

  constructor(options: HermesServiceOptions) {
    if (!validTask(options.task)) throw new Error("invalid Hermes task grant");
    if (options.task.pending_target && !options.taskFile) throw new Error("pending target requires task file");
    if (!options.auditFile) throw new Error("Hermes audit path is required");
    this.projectRoot = path.resolve(options.projectRoot);
    this.task = options.task;
    this.taskFile = options.taskFile ? path.resolve(options.taskFile) : null;
    this.sourceConfigRoot = options.sourceConfigRoot ? path.resolve(options.sourceConfigRoot) : null;
    this.budgetRoot = path.resolve(options.budgetRoot);
    this.auditFile = options.auditFile;
  }

  private async audit(record: Record<string, unknown>): Promise<void> {
    await appendFile(this.auditFile,
      `${JSON.stringify({ at: new Date().toISOString(), task_id: this.task.task_id, ...record })}\n`,
      { encoding: "utf8", mode: 0o600 });
  }

  /** Bind one user-approved target to a previously unbound, read-only task. */
  async bindTarget(url: string, approve: (details: { target: string;
    allowed_path: string }) => Promise<boolean>) {
    if (!this.task.pending_target || !this.taskFile) {
      return { ok: false as const, code: "TARGET_ALREADY_BOUND", reason: "本次会话已绑定目标；新目标须另起会话" };
    }
    const lockFile = `${this.taskFile}.bind.lock`;
    let lock;
    try { lock = await open(lockFile, "wx", 0o600); }
    catch { return { ok: false as const, code: "BIND_IN_PROGRESS", reason: "目标绑定正在处理或已锁定" }; }
    try {
      const info = await lstat(this.taskFile);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error("task file is not regular");
      const persisted = JSON.parse(await readFile(this.taskFile, "utf8")) as HermesTaskGrant;
      if (!validTask(persisted) || !persisted.pending_target ||
          persisted.task_id !== this.task.task_id) {
        return { ok: false as const, code: "TARGET_ALREADY_BOUND", reason: "本次会话已绑定目标或任务状态已改变" };
      }
      if (this.sourceConfigRoot) {
        const sourceConfigDir = path.join(this.sourceConfigRoot, "configs");
        const sourceScopeFile = path.join(sourceConfigDir, "scope.local.json");
        try {
          const directoryInfo = await lstat(sourceConfigDir);
          if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
            throw new Error("invalid source config directory");
          }
          const sourceInfo = await lstat(sourceScopeFile);
          if (!sourceInfo.isFile() || sourceInfo.isSymbolicLink()) throw new Error("invalid scope file");
          const sourceScope = JSON.parse(await readFile(sourceScopeFile, "utf8"));
          if (!validateScopeConfig(sourceScope).valid) throw new Error("invalid scope");
          const sourceDecision = checkUrlScope(url, sourceScope);
          if (["PATH_DENIED", "HOST_DENIED"].includes(sourceDecision.code)) {
            await this.audit({ kind: "target_bind", code: "SOURCE_SCOPE_DENIED", approved: false });
            return { ok: false as const, code: "SOURCE_SCOPE_DENIED",
              reason: "目标命中项目现有的明确禁止主机或路径" };
          }
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            await this.audit({ kind: "target_bind", code: "SOURCE_SCOPE_INVALID", approved: false });
            return { ok: false as const, code: "SOURCE_SCOPE_INVALID",
              reason: "项目现有 Scope 配置不可用，未登记目标" };
          }
        }
      }
      const setup = await runTargetSetup(this.projectRoot, { url }, { approve: async details => {
        const approved = await approve({ target: details.target, allowed_path: details.allowed_path });
        await this.audit({ kind: "approval", tool: "authorized_target_bind",
          target: details.target, approved });
        if (!approved) throw new Error("approval denied");
      } });
      if (!setup.ok) {
        await this.audit({ kind: "target_bind", code: setup.code, approved: false });
        return setup;
      }
      const registryFile = path.join(this.projectRoot, "configs", "authorization.local.json");
      const registry = JSON.parse(await readFile(registryFile, "utf8"));
      const grant = registry.grants?.find((item: { reference: string }) =>
        item.reference === setup.authorization_reference);
      if (!grant || !checkActionAuthorization(setup.target, grant.reference,
        "web_observe", registry).authorized) throw new Error("generated authorization invalid");
      grant.actions = ["web_observe"];
      await writeFile(registryFile, JSON.stringify({ schema_version: 1, grants: [grant] }), { mode: 0o600 });
      const bound: HermesTaskGrant = { task_id: this.task.task_id,
        authorization_reference: setup.authorization_reference,
        allowed_urls: [setup.target] };
      if (!validTask(bound)) throw new Error("generated task invalid");
      await this.audit({ kind: "target_bind", code: "TARGET_BIND_APPROVED", target: setup.target,
        authorization_reference: setup.authorization_reference, approved: true });
      await writeFile(this.taskFile, JSON.stringify(bound), { mode: 0o600 });
      this.task = bound;
      return { ok: true as const, code: "TARGET_BOUND", reason: "已在本次隔离会话绑定只读目标；尚未发送 HTTP 请求",
        target: setup.target, authorization_reference: setup.authorization_reference };
    } catch {
      await this.audit({ kind: "target_bind", code: "BIND_FAILED", approved: false });
      return { ok: false as const, code: "BIND_FAILED", reason: "目标绑定状态保存失败，未开放请求" };
    } finally {
      await lock.close().catch(() => {});
      await rm(lockFile, { force: true }).catch(() => {});
    }
  }

  /** A separate human approval upgrades only this isolated bound task. */
  async authorizeTask(input: { max_pages: number; max_requests: number },
    approve: (details: { target: string; path_prefix: string; max_pages: number;
      max_requests: number; max_depth: number }) => Promise<boolean>) {
    if (this.task.pending_target || !this.taskFile || this.task.allowed_urls.length !== 1 ||
        this.task.crawl || this.task.active) {
      return { ok: false as const, code: "TASK_MODE_DENIED", reason: "须先绑定目标，且本任务尚未开放爬取" };
    }
    if (!Number.isInteger(input?.max_pages) || input.max_pages < 1 || input.max_pages > 5 ||
        !Number.isInteger(input?.max_requests) || input.max_requests < 1 || input.max_requests > 20) {
      return { ok: false as const, code: "INVALID_LIMITS", reason: "页数须为 1–5，总请求预算须为 1–20" };
    }
    if (this.authorizingTask) return { ok: false as const, code: "TASK_BUSY" };
    this.authorizingTask = true;
    let lock;
    try {
      lock = await open(`${this.taskFile}.bind.lock`, "wx", 0o600);
      const persisted = JSON.parse(await readFile(this.taskFile, "utf8"));
      if (JSON.stringify(persisted) !== JSON.stringify(this.task)) throw new Error("stale task");
      const target = this.task.allowed_urls[0];
      const url = new URL(target);
      if (url.search || url.hash || url.username || url.password) throw new Error("invalid target");
      const registry = JSON.parse(await readFile(path.join(this.projectRoot,
        "configs", "authorization.local.json"), "utf8"));
      if (!checkActionAuthorization(target, this.task.authorization_reference,
        "web_observe", registry).authorized) throw new Error("authorization denied");
      const details = { target, path_prefix: url.pathname, ...input, max_depth: 2 };
      const approved = await approve(details);
      await this.audit({ kind: "approval", tool: "authorized_task_authorize", ...details, approved });
      if (!approved) return { ok: false as const, code: "APPROVAL_DENIED" };
      // Survives a crash: an incomplete approval transaction must never enlarge observation access.
      await writeFile(`${this.taskFile}.crawl-pending`, "pending", { mode: 0o600 });
      await writeFile(path.join(this.projectRoot, "configs", "crawl.local.json"),
        JSON.stringify({ ...input, max_depth: 2, delay_ms: 300 }), { mode: 0o600 });
      if (!await approveSessionRequestBudget(this.projectRoot, this.task.task_id,
        this.budgetRoot, input.max_requests)) throw new Error("budget unavailable");
      const next: HermesTaskGrant = { ...this.task,
        crawl: { seed_url: target, path_prefix: url.pathname, ...input } };
      await writeFile(this.taskFile, JSON.stringify(next), { mode: 0o600 });
      this.task = next;
      await rm(`${this.taskFile}.crawl-pending`);
      return { ok: true as const, code: "CRAWL_TASK_AUTHORIZED", ...details,
        reason: "已确认本次有界爬取；总预算包含已用请求，尚未发送新请求" };
    } catch {
      return { ok: false as const, code: "TASK_AUTHORIZATION_FAILED", reason: "任务授权保存失败或授权无效" };
    } finally {
      if (lock) { await lock.close(); await rm(`${this.taskFile}.bind.lock`, { force: true }); }
      this.authorizingTask = false;
    }
  }

  private async authorize(url: string, discovered = false) {
    if (this.authorizingTask) return { authorized: false as const, code: "TASK_BUSY", reason: "任务确认处理中" };
    if (this.taskFile) {
      try {
        await lstat(`${this.taskFile}.crawl-pending`);
        return { authorized: false as const, code: "TASK_APPROVAL_INCOMPLETE", reason: "爬取授权事务未完成" };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT")
          return { authorized: false as const, code: "TASK_APPROVAL_INCOMPLETE", reason: "无法核对授权事务" };
      }
    }
    if (this.task.crawl?.max_pages && this.sourceConfigRoot) {
      try {
        const scope = JSON.parse(await readFile(path.join(this.sourceConfigRoot, "configs", "scope.local.json"), "utf8"));
        if (!validateScopeConfig(scope).valid || !checkUrlScope(url, scope).allowed)
          return { authorized: false as const, code: "SOURCE_SCOPE_DENIED", reason: "请求不在项目 Scope 内" };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT")
          return { authorized: false as const, code: "SOURCE_SCOPE_INVALID", reason: "项目 Scope 无效" };
      }
    }
    if (!this.task.allowed_urls.includes(url) &&
        !(discovered && this.task.crawl && inCrawlBranch(url, this.task.crawl))) {
      return { authorized: false as const, code: "TASK_TARGET_DENIED", reason: "目标不在本次任务清单" };
    }
    let registry: unknown;
    try {
      registry = JSON.parse(await readFile(path.join(this.projectRoot, "configs", "authorization.local.json"), "utf8"));
    } catch {
      return { authorized: false as const, code: "INVALID_REGISTRY", reason: "本次任务授权登记不可用" };
    }
    return checkActionAuthorization(url, this.task.authorization_reference, "web_observe", registry);
  }

  private async authorizeActive(url: string, action: AuthorizationAction) {
    if (!this.task.active || !inActiveBranch(url, this.task.active)) {
      return { authorized: false as const, code: "TASK_TARGET_DENIED", reason: "主动检查目标不在本次任务路径分支" };
    }
    try {
      const registry = JSON.parse(await readFile(path.join(this.projectRoot,
        "configs", "authorization.local.json"), "utf8"));
      return checkActionAuthorization(url, this.task.authorization_reference, action, registry);
    } catch {
      return { authorized: false as const, code: "INVALID_REGISTRY", reason: "本次任务授权登记不可用" };
    }
  }

  async observe(url: string) {
    if (this.task.crawl || this.task.active?.kind === "assessment") {
      return { ok: false as const, code: "TASK_MODE_DENIED",
        reason: "当前任务不能用单页工具发起请求" };
    }
    if (typeof url !== "string") return { ok: false as const, code: "INVALID_URL", reason: "目标 URL 无效" };
    const initial = await this.authorize(url);
    await this.audit({ kind: "authorization", url, code: initial.code, approved: initial.authorized });
    if (!initial.authorized) return { ok: false as const, code: "AUTHORIZATION_DENIED", reason: initial.reason,
      authorization_code: initial.code };
    const control = { before_request: async (hopUrl: string) => {
      const decision = await this.authorize(hopUrl);
      if (!decision.authorized) {
        await this.audit({ kind: "request_decision", url: hopUrl, code: decision.code, sent: false });
        return `AUTHORIZATION_${decision.code}`;
      }
      const budget = await reserveSessionRequest(this.projectRoot, this.task.task_id,
        hopUrl, this.budgetRoot);
      await this.audit({ kind: "request_decision", url: hopUrl, code: budget.code,
        sent: budget.allowed, used_requests: budget.used_requests ?? null });
      return budget.allowed ? undefined : budget.code;
    } };
    const result = await runAuthorizedWebObservation(this.projectRoot, url, control, "hermes");
    await this.audit({ kind: "tool_result", tool: "authorized_web_observe", code: result.code,
      evidence_id: result.ok ? result.evidence_id : null });
    return result;
  }

  private async verifiedTaskEvidence(evidenceId: string) {
    if (typeof evidenceId !== "string" || !/^EV-\d{14}-[a-f0-9]{8}$/u.test(evidenceId)) {
      return { ok: false as const, code: "INVALID_ID", reason: "证据编号无效" };
    }
    let evidenceFile: string;
    try {
      const root = await realpath(this.projectRoot);
      const relative = path.join("evidence", "hermes", `${evidenceId}.json`);
      const candidate = path.join(root, relative);
      const info = await lstat(candidate);
      if (!info.isFile() || info.isSymbolicLink() ||
          path.relative(root, await realpath(candidate)) !== relative) {
        return { ok: false as const, code: "INVALID_EVIDENCE", reason: "证据文件不在本次任务目录" };
      }
      evidenceFile = candidate;
    } catch {
      return { ok: false as const, code: "INVALID_EVIDENCE", reason: "本次任务没有该证据" };
    }
    const verified = await loadVerifiedEvidenceFile(evidenceFile);
    if (!verified.ok || verified.record.evidence_id !== evidenceId) {
      return { ok: false as const, code: "INVALID_EVIDENCE", reason: "证据完整性校验失败" };
    }
    const sourceUrl = verified.record.observation.request.url;
    let decision = await this.authorize(sourceUrl, true);
    if (!decision.authorized && this.task.active && inActiveBranch(sourceUrl, this.task.active)) {
      const marker = new URL(sourceUrl).searchParams.values().next().value ?? "";
      decision = await this.authorizeActive(sourceUrl,
        this.task.active.kind === "redirect" ? "redirect_probe" :
          this.task.active.kind === "encoding" && /^PV-ENC-/u.test(marker)
            ? "xss_encoding_probe" : "parameter_reflection_check");
    }
    if (!decision.authorized) {
      return { ok: false as const, code: "AUTHORIZATION_DENIED", reason: decision.reason,
        authorization_code: decision.code };
    }
    return { ok: true as const, evidenceFile, record: verified.record };
  }

  async headerCheck(evidenceId: string) {
    const evidence = await this.verifiedTaskEvidence(evidenceId);
    if (!evidence.ok) return evidence;
    const result = { ok: true as const, code: "HEADER_CHECK_COMPLETED", evidence_id: evidenceId,
      result: checkHttpSecurityHeaders(evidence.record) };
    await this.audit({ kind: "tool_result", tool: "evidence_header_check", code: result.code,
      evidence_id: evidenceId });
    return result;
  }

  async webCheck(url: string) {
    const observed = await this.observe(url);
    if (!observed.ok) return observed;
    const evidence = await this.verifiedTaskEvidence(observed.evidence_id);
    if (!evidence.ok) return evidence;
    const report = await generateHeaderCheckReport(evidence.evidenceFile,
      path.join(this.projectRoot, "reports", "hermes"));
    if (!report.ok) return { ok: false as const, code: "REPORT_ERROR", reason: report.reason,
      evidence_id: observed.evidence_id };
    const result = { ok: true as const, code: "WEB_CHECK_COMPLETED",
      user_summary: report.user_summary, result: report.result,
      trace: { evidence_id: observed.evidence_id, evidence_file: evidence.evidenceFile,
        report_id: report.report_id, report_file: report.file_path } };
    await this.audit({ kind: "tool_result", tool: "authorized_web_check", code: result.code,
      evidence_id: observed.evidence_id, report_id: report.report_id });
    return result;
  }

  async crawl(url: string) {
    if (!this.task.crawl || url !== this.task.crawl.seed_url) {
      return { ok: false as const, code: "TASK_MODE_DENIED", reason: "本次任务未授权该起点的有界爬取" };
    }
    if (this.task.crawl.max_pages) {
      try {
        const policy = JSON.parse(await readFile(path.join(this.projectRoot, "configs", "crawl.local.json"), "utf8"));
        if (policy.max_pages !== this.task.crawl.max_pages || policy.max_requests !== this.task.crawl.max_requests ||
            policy.max_depth !== 2 || policy.delay_ms !== 300) throw new Error("changed policy");
      } catch { return { ok: false as const, code: "CRAWL_POLICY_CHANGED" }; }
    }
    const initial = await this.authorize(url);
    await this.audit({ kind: "authorization", url, code: initial.code, approved: initial.authorized,
      tool: "authorized_web_crawl" });
    if (!initial.authorized) return { ok: false as const, code: "AUTHORIZATION_DENIED",
      reason: initial.reason, authorization_code: initial.code };
    const control = { before_request: async (hopUrl: string) => {
      const decision = await this.authorize(hopUrl, true);
      if (!decision.authorized) {
        await this.audit({ kind: "request_decision", url: hopUrl, code: decision.code, sent: false });
        return `AUTHORIZATION_${decision.code}`;
      }
      const budget = await reserveSessionRequest(this.projectRoot, this.task.task_id,
        hopUrl, this.budgetRoot);
      await this.audit({ kind: "request_decision", url: hopUrl, code: budget.code,
        sent: budget.allowed, used_requests: budget.used_requests ?? null });
      return budget.allowed ? undefined : budget.code;
    } };
    const result = await runWebCrawl(this.projectRoot, url, control, "hermes");
    if ("pages" in result) for (const page of result.pages) {
      if (!page.evidence_id) continue;
      const ev = await this.verifiedTaskEvidence(page.evidence_id);
      if (ev.ok) await this.audit({ kind: "crawl_evidence", evidence_id: page.evidence_id,
        evidence_sha256: ev.record.integrity.payload_sha256 });
    }
    await this.audit({ kind: "tool_result", tool: "authorized_web_crawl", code: result.code,
      requests: "requests" in result ? result.requests : null });
    return result;
  }

  async reflection(input: { evidence_id: string; form_index: number; parameter_name: string },
    approve: (details: { endpoint: string; parameter_name: string }) => Promise<boolean>) {
    if (!this.task.active || !["reflection", "encoding"].includes(this.task.active.kind)) return { ok: false as const,
      code: "TASK_MODE_DENIED", reason: "本次任务未启用参数反射检查" };
    const evidence = await this.verifiedTaskEvidence(input?.evidence_id);
    if (!evidence.ok) return evidence;
    const inputs = await runEvidenceInputInventory(this.projectRoot,
      { evidence_id: input.evidence_id }, "hermes");
    if (!inputs.ok) return inputs;
    const form = inputs.result.forms.find(item => item.index === input.form_index);
    if (!form || form.method !== "get" || !form.action_valid || !form.action ||
        form.same_origin !== true || form.action_query_parameters.length ||
        !form.parameter_names.includes(input.parameter_name)) {
      return { ok: false as const, code: "FORM_NOT_ALLOWED",
        reason: "来源 EV 中没有可用于本次检查的同源 GET 表单参数" };
    }
    const authorization = await this.authorizeActive(form.action, "parameter_reflection_check");
    if (!authorization.authorized) return { ok: false as const, code: "AUTHORIZATION_DENIED",
      reason: authorization.reason, authorization_code: authorization.code };
    let approved = false;
    try { approved = await approve({ endpoint: form.action, parameter_name: input.parameter_name }); }
    catch { /* missing approval surface fails closed */ }
    await this.audit({ kind: "approval", tool: "authorized_parameter_reflection_check",
      endpoint: form.action, parameter_name: input.parameter_name, approved });
    if (!approved) return { ok: false as const, code: "APPROVAL_DENIED", reason: "本次主动检查未获用户批准" };
    const control = { before_request: async (url: string) => {
      const decision = await this.authorizeActive(url, "parameter_reflection_check");
      if (!decision.authorized) {
        await this.audit({ kind: "request_decision", url, code: decision.code, sent: false });
        return `AUTHORIZATION_${decision.code}`;
      }
      const budget = await reserveSessionRequest(this.projectRoot, this.task.task_id,
        url, this.budgetRoot);
      await this.audit({ kind: "request_decision", url, code: budget.code,
        sent: budget.allowed, used_requests: budget.used_requests ?? null });
      return budget.allowed ? undefined : budget.code;
    } };
    const result = await runAuthorizedParameterReflectionCheck(this.projectRoot,
      { ...input, authorization_reference: this.task.authorization_reference }, control, "hermes");
    await this.audit({ kind: "tool_result", tool: "authorized_parameter_reflection_check",
      code: result.code, evidence_id: result.ok ? result.trace.evidence_id : null });
    return result;
  }

  async redirectProbe(input: { evidence_id: string; form_index: number; parameter_name: string },
    approve: (details: { endpoint: string; parameter_name: string }) => Promise<boolean>) {
    if (this.task.active?.kind !== "redirect") return { ok: false as const,
      code: "TASK_MODE_DENIED", reason: "本次任务未启用重定向参数观察" };
    const evidence = await this.verifiedTaskEvidence(input?.evidence_id);
    if (!evidence.ok) return evidence;
    const inputs = await runEvidenceInputInventory(this.projectRoot,
      { evidence_id: input.evidence_id }, "hermes");
    if (!inputs.ok) return inputs;
    const form = inputs.result.forms.find(item => item.index === input.form_index);
    if (!form || form.method !== "get" || !form.action_valid || !form.action ||
        form.same_origin !== true || form.action_query_parameters.length ||
        !/^(?:next|return|return_url|redirect|redirect_url|url|destination|target|continue)$/iu
          .test(input.parameter_name) || !form.parameter_names.includes(input.parameter_name) ||
        !["localhost", "127.0.0.1", "[::1]"].includes(new URL(form.action).hostname.toLowerCase())) {
      return { ok: false as const, code: "FORM_NOT_ALLOWED",
        reason: "只允许本机可信 EV 中的同源 GET 跳转参数" };
    }
    const authorization = await this.authorizeActive(form.action, "redirect_probe");
    if (!authorization.authorized) return { ok: false as const, code: "AUTHORIZATION_DENIED",
      reason: authorization.reason, authorization_code: authorization.code };
    let approved = false;
    try { approved = await approve({ endpoint: form.action, parameter_name: input.parameter_name }); }
    catch { /* missing approval surface fails closed */ }
    await this.audit({ kind: "approval", tool: "authorized_redirect_probe",
      endpoint: form.action, parameter_name: input.parameter_name, approved });
    if (!approved) return { ok: false as const, code: "APPROVAL_DENIED", reason: "本次重定向观察未获用户批准" };
    const control = { before_request: async (url: string) => {
      const decision = await this.authorizeActive(url, "redirect_probe");
      if (!decision.authorized) {
        await this.audit({ kind: "request_decision", url, code: decision.code, sent: false });
        return `AUTHORIZATION_${decision.code}`;
      }
      const budget = await reserveSessionRequest(this.projectRoot, this.task.task_id,
        url, this.budgetRoot);
      await this.audit({ kind: "request_decision", url, code: budget.code,
        sent: budget.allowed, used_requests: budget.used_requests ?? null });
      return budget.allowed ? undefined : budget.code;
    } };
    const result = await runAuthorizedRedirectProbe(this.projectRoot,
      { ...input, authorization_reference: this.task.authorization_reference }, control, "hermes");
    await this.audit({ kind: "tool_result", tool: "authorized_redirect_probe", code: result.code,
      evidence_ids: result.ok ? result.trace.probe_evidence_ids : [] });
    return result;
  }

  async reflectionContext(evidenceId: string) {
    if (!this.task.active || !["reflection", "encoding"].includes(this.task.active.kind)) {
      return { ok: false as const, code: "TASK_MODE_DENIED", reason: "本次任务未启用反射位置分析" };
    }
    const evidence = await this.verifiedTaskEvidence(evidenceId);
    if (!evidence.ok) return evidence;
    const result = await runEvidenceReflectionContext(this.projectRoot,
      { evidence_id: evidenceId }, "hermes");
    await this.audit({ kind: "tool_result", tool: "evidence_reflection_context",
      code: result.code, evidence_id: evidenceId });
    return result;
  }

  async encodingProbe(evidenceId: string,
    approve: (details: { endpoint: string; parameter_name: string }) => Promise<boolean>) {
    if (this.task.active?.kind !== "encoding") return { ok: false as const,
      code: "TASK_MODE_DENIED", reason: "本次任务未启用特殊字符编码观察" };
    const evidence = await this.verifiedTaskEvidence(evidenceId);
    if (!evidence.ok) return evidence;
    const sourceUrl = new URL(evidence.record.observation.request.url);
    const values = [...sourceUrl.searchParams.entries()];
    if (values.length !== 1 || !/^PV-REFLECT-[a-f0-9]{16}$/u.test(values[0][1]) ||
        !evidence.record.observation.response.body.includes(values[0][1])) {
      return { ok: false as const, code: "REFLECTION_NOT_PROVEN",
        reason: "本次 EV 中没有可用于编码观察的单参数反射标记" };
    }
    const parameterName = values[0][0];
    sourceUrl.search = "";
    const authorization = await this.authorizeActive(sourceUrl.href, "xss_encoding_probe");
    if (!authorization.authorized) return { ok: false as const, code: "AUTHORIZATION_DENIED",
      reason: authorization.reason, authorization_code: authorization.code };
    let approved = false;
    try { approved = await approve({ endpoint: sourceUrl.href, parameter_name: parameterName }); }
    catch { /* missing approval surface fails closed */ }
    await this.audit({ kind: "approval", tool: "authorized_xss_encoding_probe",
      endpoint: sourceUrl.href, parameter_name: parameterName, approved });
    if (!approved) return { ok: false as const, code: "APPROVAL_DENIED", reason: "本次编码观察未获用户批准" };
    const control = { before_request: async (url: string) => {
      const decision = await this.authorizeActive(url, "xss_encoding_probe");
      if (!decision.authorized) {
        await this.audit({ kind: "request_decision", url, code: decision.code, sent: false });
        return `AUTHORIZATION_${decision.code}`;
      }
      const budget = await reserveSessionRequest(this.projectRoot, this.task.task_id,
        url, this.budgetRoot);
      await this.audit({ kind: "request_decision", url, code: budget.code,
        sent: budget.allowed, used_requests: budget.used_requests ?? null });
      return budget.allowed ? undefined : budget.code;
    } };
    const result = await runAuthorizedXssEncodingProbe(this.projectRoot,
      { evidence_id: evidenceId, authorization_reference: this.task.authorization_reference },
      control, "hermes");
    await this.audit({ kind: "tool_result", tool: "authorized_xss_encoding_probe",
      code: result.code, evidence_id: result.ok ? result.trace.evidence_id : null });
    return result;
  }

  async xssHypothesisTriage(reflectionEvidenceId: string, encodingEvidenceId: string,
    approve: (details: { endpoint: string; parameter_name: string }) => Promise<boolean>) {
    if (this.task.active?.kind !== "encoding") return { ok: false as const,
      code: "TASK_MODE_DENIED", reason: "本次任务未启用 XSS 候选关联" };
    const [reflection, encoding] = await Promise.all([
      this.verifiedTaskEvidence(reflectionEvidenceId),
      this.verifiedTaskEvidence(encodingEvidenceId),
    ]);
    if (!reflection.ok) return reflection;
    if (!encoding.ok) return encoding;
    const result = await runXssHypothesisTriage(this.projectRoot, {
      reflection_evidence_id: reflectionEvidenceId,
      encoding_evidence_id: encodingEvidenceId,
      authorization_reference: this.task.authorization_reference,
    }, { artifactNamespace: "hermes", approve: async details => {
      let approved = false;
      try { approved = await approve({ endpoint: details.endpoint,
        parameter_name: details.parameter_name }); }
      catch { /* missing approval surface fails closed */ }
      await this.audit({ kind: "approval", tool: "authorized_xss_hypothesis_triage",
        endpoint: details.endpoint, parameter_name: details.parameter_name, approved });
      if (!approved) throw new Error("approval denied");
    } });
    await this.audit({ kind: "tool_result", tool: "authorized_xss_hypothesis_triage",
      code: result.code, hypothesis_id: "hypothesis_id" in result ? result.hypothesis_id : null,
      evidence_ids: [reflectionEvidenceId, encodingEvidenceId] });
    return result;
  }

  async hypothesisCreate(input: { target_url: string; title: string;
    description: string; reason: string },
    approve: (details: { target: string; title: string }) => Promise<boolean>) {
    if (!input || typeof input.target_url !== "string" ||
        !this.task.allowed_urls.includes(input.target_url)) {
      return { ok: false as const, code: "TASK_TARGET_DENIED",
        reason: "假设目标不在本次任务清单" };
    }
    const decision = await this.authorizeActiveHypothesis(input.target_url);
    await this.audit({ kind: "authorization", tool: "authorized_hypothesis_create",
      url: input.target_url, code: decision.code, approved: decision.authorized });
    if (!decision.authorized) return { ok: false as const, code: "AUTHORIZATION_DENIED",
      reason: decision.reason, authorization_code: decision.code };
    let approved = false;
    try { approved = await approve({ target: input.target_url, title: input.title }); }
    catch { /* missing approval surface fails closed */ }
    await this.audit({ kind: "approval", tool: "authorized_hypothesis_create",
      url: input.target_url, approved });
    if (!approved) return { ok: false as const, code: "APPROVAL_DENIED",
      reason: "本次 HYP 写入未获用户批准" };
    const result = await runAuthorizedHypothesisCreate(this.projectRoot,
      { ...input, authorization_reference: this.task.authorization_reference }, "hermes");
    await this.audit({ kind: "tool_result", tool: "authorized_hypothesis_create",
      code: result.code, hypothesis_id: result.ok ? result.hypothesis_id : null });
    return result;
  }

  private async authorizeActiveHypothesis(url: string) {
    try {
      const registry = JSON.parse(await readFile(path.join(this.projectRoot,
        "configs", "authorization.local.json"), "utf8"));
      return checkActionAuthorization(url, this.task.authorization_reference,
        "hypothesis_create", registry);
    } catch {
      return { authorized: false as const, code: "INVALID_REGISTRY",
        reason: "本次任务授权登记不可用" };
    }
  }

  async hypothesisGet(hypothesisId: string) {
    const result = await runHypothesisGet(this.projectRoot,
      { hypothesis_id: hypothesisId }, "hermes");
    await this.audit({ kind: "tool_result", tool: "hypothesis_get",
      code: result.code, hypothesis_id: hypothesisId });
    return result;
  }

  async reflectedXssAssessment(url: string,
    approve: (details: { target: string; max_parameters: number }) => Promise<boolean>) {
    if (this.task.active?.kind !== "assessment" || url !== this.task.active.seed_url) {
      return { ok: false as const, code: "TASK_MODE_DENIED",
        reason: "本次任务未授权该目标的完整反射型 XSS 评估" };
    }
    for (const action of ["web_observe", "parameter_reflection_check",
      "xss_encoding_probe", "hypothesis_create"] as const) {
      const decision = action === "hypothesis_create"
        ? await this.authorizeActiveHypothesis(url)
        : await this.authorizeActive(url, action);
      await this.audit({ kind: "authorization", tool: "authorized_reflected_xss_assessment",
        url, action, code: decision.code, approved: decision.authorized });
      if (!decision.authorized) return { ok: false as const, code: "AUTHORIZATION_DENIED",
        reason: decision.reason, authorization_code: decision.code };
    }
    const control = { before_request: async (requestUrl: string) => {
      let action: "web_observe" | "parameter_reflection_check" | "xss_encoding_probe";
      try {
        const values = [...new URL(requestUrl).searchParams.values()];
        if (values.length === 0) action = "web_observe";
        else if (values.length === 1 && /^PV-REFLECT-[a-f0-9]{16}$/u.test(values[0])) {
          action = "parameter_reflection_check";
        } else if (values.length === 1 && /^PV-ENC-[a-f0-9]{16}/u.test(values[0])) {
          action = "xss_encoding_probe";
        } else {
          await this.audit({ kind: "request_decision", url: requestUrl,
            code: "TASK_QUERY_DENIED", sent: false });
          return "TASK_QUERY_DENIED";
        }
      } catch { return "TASK_URL_INVALID"; }
      const decision = await this.authorizeActive(requestUrl, action);
      if (!decision.authorized) {
        await this.audit({ kind: "request_decision", url: requestUrl,
          action, code: decision.code, sent: false });
        return `AUTHORIZATION_${decision.code}`;
      }
      const budget = await reserveSessionRequest(this.projectRoot, this.task.task_id,
        requestUrl, this.budgetRoot);
      await this.audit({ kind: "request_decision", url: requestUrl, action,
        code: budget.code, sent: budget.allowed, used_requests: budget.used_requests ?? null });
      return budget.allowed ? undefined : budget.code;
    } };
    const result = await runAuthorizedReflectedXssAssessment(this.projectRoot,
      { url, authorization_reference: this.task.authorization_reference }, {
        artifactNamespace: "hermes", request_control: control,
        approve: async details => {
          let approved = false;
          try { approved = await approve({ target: details.target,
            max_parameters: details.max_parameters }); }
          catch { /* missing approval surface fails closed */ }
          await this.audit({ kind: "approval", tool: "authorized_reflected_xss_assessment",
            url, max_parameters: details.max_parameters, approved });
          if (!approved) throw new Error("approval denied");
        },
      });
    await this.audit({ kind: "tool_result", tool: "authorized_reflected_xss_assessment",
      code: result.code, report_id: "trace" in result ? result.trace?.report_id : null });
    return result;
  }

  async inventory(evidenceId: string) {
    const evidence = await this.verifiedTaskEvidence(evidenceId);
    if (!evidence.ok) return evidence;
    const [links, inputs] = await Promise.all([
      runEvidenceLinkInventory(this.projectRoot, { evidence_id: evidenceId }, "hermes"),
      runEvidenceInputInventory(this.projectRoot, { evidence_id: evidenceId }, "hermes"),
    ]);
    if (!links.ok || !inputs.ok) return { ok: false as const, code: "INVENTORY_REJECTED",
      reason: !links.ok ? links.reason : inputs.reason };
    const result = { ok: true as const, code: "INVENTORY_COMPLETED", evidence_id: evidenceId,
      links: links.result, inputs: inputs.result };
    await this.audit({ kind: "tool_result", tool: "evidence_entry_inventory", code: result.code,
      evidence_id: evidenceId });
    return result;
  }

  async linkInventory(evidenceId: string) {
    const evidence = await this.verifiedTaskEvidence(evidenceId);
    if (!evidence.ok) return evidence;
    const result = await runEvidenceLinkInventory(this.projectRoot,
      { evidence_id: evidenceId }, "hermes");
    await this.audit({ kind: "tool_result", tool: "evidence_link_inventory",
      code: result.code, evidence_id: evidenceId });
    return result;
  }

  async inputInventory(evidenceId: string) {
    const evidence = await this.verifiedTaskEvidence(evidenceId);
    if (!evidence.ok) return evidence;
    if (this.task.crawl?.max_pages) {
      try {
        const events = (await readFile(this.auditFile, "utf8")).trim().split("\n").map(line => JSON.parse(line));
        if (!events.some(event => event.task_id === this.task.task_id && event.kind === "crawl_evidence" &&
          event.evidence_id === evidenceId && event.evidence_sha256 === evidence.record.integrity.payload_sha256))
          return { ok: false as const, code: "EVIDENCE_NOT_IN_TASK" };
      } catch { return { ok: false as const, code: "EVIDENCE_NOT_IN_TASK" }; }
    }
    const result = await runEvidenceInputInventory(this.projectRoot,
      { evidence_id: evidenceId }, "hermes");
    await this.audit({ kind: "tool_result", tool: "evidence_input_inventory",
      code: result.code, evidence_id: evidenceId });
    if (!result.ok) return result;
    const pageUrl = new URL(evidence.record.observation.request.url);
    pageUrl.search = ""; pageUrl.hash = "";
    return { ok: true as const, code: result.code, evidence_id: evidenceId,
      page_url: pageUrl.href, query_endpoints: result.result.query_endpoints.map(item => ({
        url: item.endpoint, parameter_names: item.parameter_names, evidence_id: evidenceId })),
      truncated: result.result.truncated };
  }
}
