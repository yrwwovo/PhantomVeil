import { createHash } from "node:crypto";

/**
 * APK 静态线路 → ReconLab 回写助手（PhantomVeil 侧）。
 *
 * 架构师硬约束：cwe / locator / confidence / severity 是 Agent 推理后传入的入参，
 * 本模块绝不自行推断它们；只负责按设计 §3 组装 ScanFinding 并经既有 client 回写。
 * 状态纪律（§7 红线）：静态段默认 status=suspected，强证据可传 testing，读不动传 blocked；
 * 任何情况下都不得写 auto_verified / confirmed（本模块对此直接拒绝，视为契约违例）。
 */

/** confidence 两档（§3，保留不变）。 */
export type ApkConfidence = "static-candidate" | "static-strong";
/** 静态段允许写入的 status（绝不含 auto_verified / confirmed）。 */
export type ApkStaticStatus = "suspected" | "testing" | "blocked";
export type ApkStage = "acquire_unpack" | "decompile_manifest" | "dex_smali_audit" | "so_static_audit";

export interface ApkScopeBinding {
  apk_sha256: string;
  package_name?: string | null;
  version_name?: string | null;
  signing_cert_sha256?: string | null;
}

export interface ApkFindingLocator {
  stage: ApkStage;
  component?: string | null;
  component_type?: "activity" | "service" | "receiver" | "provider" | null;
  class?: string | null;
  method?: string | null;
  so_file?: string | null;
  so_symbol?: string | null;
  so_offset?: string | null;
  smali_ref?: string | null;
}

export interface ApkVerifyHooks {
  /** §8 决策 10：apk.exported_component_poc / apk.signature_bypass / apk.unidbg_repro / apk.frida_runtime。 */
  verifier_plugin: string | null;
  dynamic_refs: string[];
  repro_hint: string;
  status_gate: string;
  executed: boolean;
}

export interface ApkFinding {
  id: string;
  title: string;
  category: string;
  severity: string;
  confidence: ApkConfidence;
  /** findings.confidence_tier。文本档位，不是数字列 confidence。 */
  confidence_tier: ApkConfidence;
  scope: ApkScopeBinding;
  locator: ApkFindingLocator;
  service: string;
  version?: string;
  fingerprint: Record<string, unknown>;
  cve_candidates: string[];
  cwe: string;
  evidence_refs: string[];
  evidence_summary: string;
  status: ApkStaticStatus;
  status_reason: string;
  verify_hooks: ApkVerifyHooks;
  created_at: string;
  source_pipeline: "apk-static-recon-v2";
}

/** Agent 组装 finding 的入参。cwe/locator/confidence/severity 必填且由 Agent 判定传入。 */
export interface BuildApkFindingInput {
  seq: number | string;
  // —— 由 Agent 推理后传入（本模块不推断）——
  cwe: string;
  locator: ApkFindingLocator;
  confidence: ApkConfidence;
  severity: string;
  title: string;
  category?: string;            // 默认取 cwe
  // —— 证据与绑定（来自 capability 事实 + Scope）——
  scope: ApkScopeBinding;
  evidence_refs: string[];
  evidence_summary: string;
  service: string;
  version?: string;
  fingerprint?: Record<string, unknown>;
  cve_candidates?: string[];
  // —— 状态（默认 suspected；绝不接受 auto_verified/confirmed）——
  status?: ApkStaticStatus;
  status_reason?: string;
  verify_hooks?: Partial<ApkVerifyHooks>;
  now?: () => Date;
}

const ALLOWED_STATUS: ReadonlySet<string> = new Set(["suspected", "testing", "blocked"]);
const ALLOWED_CONFIDENCE: ReadonlySet<string> = new Set(["static-candidate", "static-strong"]);

/** confidence → 默认 status 映射（§3）：static-candidate→suspected，static-strong→testing。 */
function defaultStatusFor(confidence: ApkConfidence): ApkStaticStatus {
  return confidence === "static-strong" ? "testing" : "suspected";
}

/**
 * 组装一条 APK 静态 ScanFinding。cwe/locator/confidence/severity 来自调用方(Agent)。
 * 对静态段红线做强校验：confidence 必须两档之一；status 只能 suspected/testing/blocked。
 */
export function buildApkFinding(input: BuildApkFindingInput): ApkFinding {
  if (!ALLOWED_CONFIDENCE.has(input.confidence)) {
    throw new TypeError(`apk-writeback: 非法 confidence=${input.confidence}（只允许 static-candidate / static-strong）`);
  }
  const status = input.status ?? defaultStatusFor(input.confidence);
  if (!ALLOWED_STATUS.has(status)) {
    // 红线：静态段绝不产 auto_verified / confirmed。
    throw new TypeError(`apk-writeback: 静态段不得写 status=${status}（只允许 suspected / testing / blocked；auto_verified/confirmed 归动态/人工）`);
  }
  if (status === "testing" && input.confidence !== "static-strong") {
    throw new TypeError("apk-writeback: status=testing 只允许 confidence_tier=static-strong");
  }
  if (!input.evidence_refs || input.evidence_refs.length === 0) {
    throw new TypeError("apk-writeback: evidence_refs 必填且不可为空（§3 对接约定）");
  }
  const createdAt = (input.now ? input.now() : new Date()).toISOString();
  const shortSha = input.scope.apk_sha256.slice(0, 12);
  const verifyHooks: ApkVerifyHooks = {
    verifier_plugin: input.verify_hooks?.verifier_plugin ?? null,
    dynamic_refs: input.verify_hooks?.dynamic_refs ?? [],
    repro_hint: input.verify_hooks?.repro_hint ?? "",
    status_gate: input.verify_hooks?.status_gate ?? "suspected->testing->auto_verified",
    executed: false, // 本期恒 false：只登记不执行
  };
  return {
    id: `pv-apk-${shortSha}-${input.seq}`,
    title: input.title,
    category: input.category ?? input.cwe,
    severity: input.severity,
    confidence: input.confidence,
    confidence_tier: input.confidence,
    scope: input.scope,
    locator: input.locator,
    service: input.service,
    ...(input.version ? { version: input.version } : {}),
    fingerprint: input.fingerprint ?? {},
    cve_candidates: input.cve_candidates ?? [],
    cwe: input.cwe,
    evidence_refs: input.evidence_refs,
    evidence_summary: input.evidence_summary,
    status,
    status_reason: input.status_reason ?? "static-decidable；待动态 verifier 复现 + 人工签字",
    verify_hooks: verifyHooks,
    created_at: createdAt,
    source_pipeline: "apk-static-recon-v2",
  };
}

/**
 * findings 集合上的记录。cwe / locator / verify_hooks / confidence_tier / status
 * 只放这里。不写数字列 confidence（档位也不折成数字）。
 * queue_item_id 在队列项创建之后才填。
 * evidence_refs 只在 findings 上确有该列时写入，值是 POST /api/evidence 的 id。
 */
export function toApkFindingsRecord(
  finding: ApkFinding,
  extras: { queueItemId?: string; writeEvidenceRefs?: boolean } = {},
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    title: finding.title,
    status: finding.status,
    cwe: finding.cwe,
    locator: finding.locator,
    verify_hooks: finding.verify_hooks,
    confidence_tier: finding.confidence_tier,
    severity: finding.severity,
    category: finding.category,
  };
  if (extras.queueItemId) body.queue_item_id = extras.queueItemId;
  if (extras.writeEvidenceRefs) body.evidence_refs = [...finding.evidence_refs];
  return body;
}

export interface ApkQueueTransport {
  endpoint?: string;
  target?: string;
  parameter?: string;
  location?: string;
  /**
   * 队列路由把 scope_id 当成 scopes 集合记录 id 来过滤。
   * APK SHA-256 不是这个 id，不能塞进该字段，否则现算直接 scope_not_found。
   */
  scopeId?: string;
}

/** POST /api/evidence 返回的 id。sha256 可选，带上时路由会核对。 */
export interface ApkEvidenceId {
  id: string;
  sha256?: string;
}

/**
 * 队列项只表示「有东西待验证」。
 * 对外 state 恒为 suspected。不放 cwe / locator / verify_hooks / confidence_tier / status，
 * 也不放数字 confidence。evidence 只放 POST /api/evidence 返回的 id（路由写入 evidence_ids）。
 * 不放 finding id，也不 PATCH evidence_ids。
 */
export function toApkQueueBody(
  finding: ApkFinding,
  evidenceIds: readonly ApkEvidenceId[],
  transport: ApkQueueTransport = {},
): Record<string, unknown> {
  const evidence = evidenceIds.filter((ref) => ref.id.length > 0);
  if (evidence.length === 0) {
    throw new TypeError("apk-writeback: 队列 evidence 必须是 POST /api/evidence 返回的 id，且不可为空");
  }
  return {
    kind: "apk_static",
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    // 静态阶段队列对外恒为 suspected。suspected/testing 只在 finding 的 status + confidence_tier。
    state: "suspected",
    service: finding.service,
    ...(finding.version ? { version: finding.version } : {}),
    fingerprint: finding.fingerprint,
    ...(finding.cve_candidates.length > 0 ? { cve_candidates: finding.cve_candidates } : {}),
    evidence: evidence.map((ref) => (ref.sha256 ? { id: ref.id, sha256: ref.sha256 } : { id: ref.id })),
    evidence_summary: finding.evidence_summary,
    source: "apk-static-recon-v2",
    source_finding_id: finding.id,
    ...(transport.endpoint ? { endpoint: transport.endpoint } : {}),
    ...(transport.target ? { target: transport.target } : {}),
    ...(transport.parameter ? { parameter: transport.parameter } : {}),
    ...(transport.location ? { location: transport.location } : {}),
    ...(transport.scopeId ? { scope_id: transport.scopeId } : {}),
  };
}

/** 既有证据通道：JSON content_base64 + Content-Digest（sha-256=:BASE64:）。 */
export interface ApkEvidenceUpload {
  content: Uint8Array | string;
  contentType?: string;
  kind?: string;
  note?: string;
  filename?: string;
}

/**
 * report 对齐既有 ReconLabClient.report（POST /api/verification/queue）。
 * postEvidence 是 POST /api/evidence。createFinding 是 POST /api/collections/findings/records。
 */
export interface ApkFindingReportClient {
  postEvidence(item: ApkEvidenceUpload): Promise<{ id: string; sha256: string }>;
  report(
    finding: Record<string, unknown>,
    opts?: { idempotencyKey?: string },
  ): Promise<{ item?: { id?: string }; replay?: boolean; status?: number }>;
  /** POST /api/collections/findings/records。没有这条方法时回写不得假装已经落库。 */
  createFinding(body: Record<string, unknown>): Promise<{ id: string; record?: Record<string, unknown> }>;
  /** findings 上是否已有该列。没有 evidence_refs 时不得另造列。 */
  findingsHasField(name: string): Promise<boolean>;
}

export interface WriteApkFindingOptions {
  /** 无 live ReconLab 时走 dry-run：只记日志、不发请求。 */
  dryRun?: boolean;
  idempotencyKey?: string;
  logger?: (line: string) => void;
  /** 队列契约要求的定位字段，不属于 finding 载荷。 */
  endpoint?: string;
  target?: string;
  parameter?: string;
  location?: string;
  /** scopes 集合记录 id。不要传 apk_sha256。 */
  scopeId?: string;
  /**
   * 静态证据原文。省略时按 finding.evidence_refs 各生成一份 text/plain，
   * 仍走同一条 POST /api/evidence + Content-Digest 通道。
   */
  evidence?: ApkEvidenceUpload[];
}

export interface WriteApkFindingResult {
  ok: boolean;
  mode: "live" | "dry-run";
  finding_id: string;
  /** PocketBase findings 记录 id。dry-run 时没有。 */
  finding_record_id?: string;
  queue_id?: string;
  replay?: boolean;
  body: Record<string, unknown>;
  findings_body: Record<string, unknown>;
  /** 本次 POST /api/evidence 返回的 id。dry-run 为空。 */
  evidence_ids: string[];
  /** 回写后 in-memory finding.evidence_refs（live 成功上传后等于 evidence_ids）。 */
  evidence_refs: string[];
  /** findings.evidence_refs 列是否写入。列不存在时为 false。 */
  evidence_refs_written: boolean;
  error?: string;
}

function defaultEvidenceUploads(finding: ApkFinding): ApkEvidenceUpload[] {
  return finding.evidence_refs.map((ref, index) => ({
    content: [
      "APK STATIC EVIDENCE",
      `ref=${ref}`,
      `summary=${finding.evidence_summary}`,
      `finding=${finding.id}`,
      `created=${finding.created_at}`,
      `seq=${index}`,
    ].join("\n") + "\n",
    contentType: "text/plain",
    kind: "apk_static",
    note: "apk-static",
    filename: `apk-static-${index}.txt`,
  }));
}

function failure(
  finding: ApkFinding,
  findingsBody: Record<string, unknown>,
  body: Record<string, unknown>,
  error: unknown,
  extra: Partial<WriteApkFindingResult> = {},
): WriteApkFindingResult {
  return {
    ok: false,
    mode: "live",
    finding_id: finding.id,
    body,
    findings_body: findingsBody,
    evidence_ids: extra.evidence_ids ?? [],
    evidence_refs: extra.evidence_refs ?? [...finding.evidence_refs],
    evidence_refs_written: false,
    ...(extra.queue_id ? { queue_id: extra.queue_id } : {}),
    ...(extra.finding_record_id ? { finding_record_id: extra.finding_record_id } : {}),
    error: error instanceof Error ? error.message : String(error),
  };
}

/**
 * 回写一条 finding。顺序固定：
 * 1. POST /api/evidence，只收集返回的 evidence id；
 * 2. POST /api/verification/queue，state=suspected，evidence 只含这些 id；
 * 3. 再建 findings 行，queue_item_id 指向该队列项。
 * 不 PATCH review_queue.evidence_ids，也不把 finding id 写进证据链。
 */
export async function writeApkFinding(
  client: ApkFindingReportClient | null,
  finding: ApkFinding,
  opts: WriteApkFindingOptions = {},
): Promise<WriteApkFindingResult> {
  const idempotencyKey = opts.idempotencyKey ?? `apk:${finding.scope.apk_sha256}:${finding.cwe}:${finding.id}`;
  const log = opts.logger ?? ((l: string) => process.stdout.write(`${l}\n`));
  const transport: ApkQueueTransport = {
    ...(opts.endpoint ? { endpoint: opts.endpoint } : {}),
    ...(opts.target ? { target: opts.target } : {}),
    ...(opts.parameter ? { parameter: opts.parameter } : {}),
    ...(opts.location ? { location: opts.location } : {}),
    ...(opts.scopeId ? { scopeId: opts.scopeId } : {}),
  };
  if (opts.dryRun || client === null) {
    const findingsBody = toApkFindingsRecord(finding);
    const body = toApkQueueBody(finding, finding.evidence_refs.map((id) => ({ id })), transport);
    log(`[apk-writeback][dry-run] evidence channel skipped; live path POSTs /api/evidence before the queue`);
    log(`[apk-writeback][dry-run] findings ${finding.id} status=${finding.status} cwe=${finding.cwe} tier=${finding.confidence_tier}`);
    log(`[apk-writeback][dry-run] findings_body=${JSON.stringify(findingsBody)}`);
    log(`[apk-writeback][dry-run] report ${finding.id} key=${idempotencyKey}`);
    log(`[apk-writeback][dry-run] body=${JSON.stringify(body)}`);
    return {
      ok: true, mode: "dry-run", finding_id: finding.id, body, findings_body: findingsBody,
      evidence_ids: [], evidence_refs: [...finding.evidence_refs], evidence_refs_written: false,
    };
  }

  const uploads = opts.evidence && opts.evidence.length > 0 ? opts.evidence : defaultEvidenceUploads(finding);
  const posted: ApkEvidenceId[] = [];
  try {
    for (const item of uploads) posted.push(await client.postEvidence(item));
  } catch (error) {
    return failure(finding, toApkFindingsRecord(finding), {}, error, {
      evidence_ids: posted.map((item) => item.id),
    });
  }
  const evidenceIds = posted.map((item) => item.id);
  finding.evidence_refs = evidenceIds;
  const queueBody = toApkQueueBody(finding, posted, transport);
  let queueId = "";
  let replay = false;
  try {
    const res = await client.report(queueBody, { idempotencyKey });
    queueId = res.item?.id ?? "";
    replay = res.replay === true;
    if (!queueId) throw new Error("apk-writeback: 队列创建没有返回 id");
  } catch (error) {
    return failure(finding, toApkFindingsRecord(finding), queueBody, error, {
      evidence_ids: evidenceIds,
      evidence_refs: evidenceIds,
    });
  }

  let writeEvidenceRefs = false;
  try {
    writeEvidenceRefs = await client.findingsHasField("evidence_refs");
  } catch (error) {
    return failure(finding, toApkFindingsRecord(finding), queueBody, error, {
      evidence_ids: evidenceIds,
      evidence_refs: evidenceIds,
      queue_id: queueId,
    });
  }
  const findingsBody = toApkFindingsRecord(finding, { queueItemId: queueId, writeEvidenceRefs });
  try {
    const created = await client.createFinding(findingsBody);
    if (!created?.id) throw new Error("apk-writeback: findings 创建没有返回 id");
    log(`[apk-writeback] evidence_ids=${JSON.stringify(evidenceIds)} queue_id=${queueId} finding_record_id=${created.id} queue_item_id=${queueId} evidence_refs_written=${writeEvidenceRefs}`);
    return {
      ok: true, mode: "live", finding_id: finding.id, finding_record_id: created.id,
      queue_id: queueId, replay, body: queueBody, findings_body: findingsBody,
      evidence_ids: evidenceIds, evidence_refs: [...finding.evidence_refs],
      evidence_refs_written: writeEvidenceRefs,
    };
  } catch (error) {
    return failure(finding, findingsBody, queueBody, error, {
      evidence_ids: evidenceIds,
      evidence_refs: evidenceIds,
      queue_id: queueId,
    });
  }
}

interface FetchLike {
  (url: string, init: { method: string; headers: Record<string, string>; body?: string }): Promise<{
    status: number;
    text(): Promise<string>;
  }>;
}

export interface ApkWritebackClientOptions {
  baseUrl: string;
  /** PocketBase 用户/超管令牌，用于 findings 集合。 */
  collectionAuthorization: string;
  /** 队列与证据通道的 Agent 令牌，已含或不含 Bearer 前缀均可。 */
  queueAuthorization: string;
  fetchImpl?: FetchLike;
}

async function httpJson(
  fetchImpl: FetchLike,
  method: string,
  url: string,
  authorization: string,
  body?: Record<string, unknown>,
  extraHeaders?: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const headers: Record<string, string> = { Accept: "application/json", Authorization: authorization };
  if (extraHeaders) Object.assign(headers, extraHeaders);
  let payload: string | undefined;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetchImpl(url, { method, headers, ...(payload !== undefined ? { body: payload } : {}) });
  const text = await res.text();
  let parsed: unknown = {};
  if (text) {
    try { parsed = JSON.parse(text); } catch { parsed = { _raw: text.slice(0, 500) }; }
  }
  const record = parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : { _raw: parsed };
  return { status: res.status, body: record };
}

function evidenceBytes(content: Uint8Array | string): Buffer {
  return typeof content === "string" ? Buffer.from(content, "utf8") : Buffer.from(content);
}

/**
 * 窄客户端。证据走 POST /api/evidence（Content-Digest），队列走 POST /api/verification/queue。
 * 队列 evidence_ids 只在创建时由路由从 evidence 写入。不再 PATCH finding id。
 */
export class ApkWritebackClient implements ApkFindingReportClient {
  private readonly baseUrl: string;
  private readonly collectionAuthorization: string;
  private readonly queueAuthorization: string;
  private readonly fetchImpl: FetchLike;

  constructor(options: ApkWritebackClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/u, "");
    this.collectionAuthorization = options.collectionAuthorization;
    const queue = options.queueAuthorization;
    this.queueAuthorization = queue.startsWith("Bearer ") ? queue : `Bearer ${queue}`;
    this.fetchImpl = options.fetchImpl ?? (fetch as unknown as FetchLike);
  }

  async postEvidence(item: ApkEvidenceUpload): Promise<{ id: string; sha256: string }> {
    const bytes = evidenceBytes(item.content);
    const hash = createHash("sha256").update(bytes).digest();
    const sha256 = hash.toString("hex");
    const res = await httpJson(
      this.fetchImpl, "POST", `${this.baseUrl}/api/evidence`,
      this.queueAuthorization,
      {
        content_base64: bytes.toString("base64"),
        content_type: item.contentType ?? "text/plain",
        kind: item.kind ?? "apk_static",
        note: item.note ?? "apk-static",
        filename: item.filename ?? "apk-static.txt",
      },
      { "Content-Digest": `sha-256=:${hash.toString("base64")}:` },
    );
    const evidence = res.body.evidence && typeof res.body.evidence === "object"
      ? res.body.evidence as Record<string, unknown>
      : {};
    const id = typeof evidence.id === "string" ? evidence.id : "";
    if ((res.status !== 200 && res.status !== 201) || !id) {
      throw new Error(`apk-writeback: 证据上传失败 status=${res.status} body=${JSON.stringify(res.body).slice(0, 400)}`);
    }
    const stored = typeof evidence.sha256 === "string" && evidence.sha256.length > 0 ? evidence.sha256 : sha256;
    return { id, sha256: stored };
  }

  async findingsHasField(name: string): Promise<boolean> {
    const res = await httpJson(
      this.fetchImpl, "GET", `${this.baseUrl}/api/collections/findings`,
      this.collectionAuthorization,
    );
    if (res.status !== 200) {
      throw new Error(`apk-writeback: 读取 findings schema 失败 status=${res.status} body=${JSON.stringify(res.body).slice(0, 300)}`);
    }
    const fields = Array.isArray(res.body.fields) ? res.body.fields : [];
    return fields.some((field) => {
      if (!field || typeof field !== "object") return false;
      return (field as { name?: unknown }).name === name;
    });
  }

  async createFinding(body: Record<string, unknown>): Promise<{ id: string; record?: Record<string, unknown> }> {
    const res = await httpJson(
      this.fetchImpl, "POST", `${this.baseUrl}/api/collections/findings/records`,
      this.collectionAuthorization, body,
    );
    const id = typeof res.body.id === "string" ? res.body.id : "";
    if ((res.status !== 200 && res.status !== 201) || !id) {
      throw new Error(`apk-writeback: findings 创建失败 status=${res.status} body=${JSON.stringify(res.body).slice(0, 400)}`);
    }
    return { id, record: res.body };
  }

  async report(
    finding: Record<string, unknown>,
    opts: { idempotencyKey?: string } = {},
  ): Promise<{ item?: { id?: string }; replay?: boolean; status?: number }> {
    const headers: Record<string, string> = {};
    if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;
    const res = await httpJson(
      this.fetchImpl, "POST", `${this.baseUrl}/api/verification/queue`,
      this.queueAuthorization, finding, headers,
    );
    const item = res.body.item && typeof res.body.item === "object"
      ? res.body.item as { id?: string }
      : undefined;
    if (res.status !== 200 && res.status !== 201) {
      throw new Error(`apk-writeback: 队列创建失败 status=${res.status} body=${JSON.stringify(res.body).slice(0, 400)}`);
    }
    const replay = res.body.replay === true || res.body.deduplicated === true;
    return { item, replay, status: res.status };
  }
}
