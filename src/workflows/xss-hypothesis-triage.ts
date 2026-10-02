import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, rm } from "node:fs/promises";
import path from "node:path";

import { analyzeReflectionContext } from "../../capabilities/web/reflection-context.ts";
import {
  analyzeXssEncodingObservation,
  createXssEncodingProbe,
} from "../../capabilities/web/xss-encoding-observation.ts";
import { loadVerifiedEvidenceFile, type EvidenceRecord } from "../evidence/evidence-store.ts";
import {
  attachHypothesisEvidence,
  createHypothesisWithEvidence,
  type HypothesisCandidateIdentity,
} from "../hypotheses/hypothesis-manager.ts";
import { HypothesisStore } from "../hypotheses/hypothesis-store.ts";
import {
  checkHypothesisCreateAuthorization,
  type AuthorizationRegistry,
} from "../scope/authorization-registry.ts";
import { checkUrlScope, type ScopeConfig } from "../scope/scope-guard.ts";

const EVIDENCE_ID = /^EV-\d{14}-[a-f0-9]{8}$/u;
const REFLECTION_MARKER = /^PV-REFLECT-([a-f0-9]{16})$/u;
const ENCODING_MARKER = /^PV-ENC-([a-f0-9]{16})/u;

export interface XssHypothesisTriageInput {
  reflection_evidence_id: string;
  encoding_evidence_id: string;
  authorization_reference: string;
}

export interface XssHypothesisApprovalDetails {
  permission: "xss_hypothesis_record";
  endpoint: string;
  parameter_name: string;
  candidate_fingerprint: string;
  evidence_ids: string[];
}

export interface XssHypothesisTriageOptions {
  approve?: (details: XssHypothesisApprovalDetails) => Promise<void>;
}

function headerValue(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
  return Array.isArray(value) ? value.join(";") : value;
}

async function loadProjectEvidence(root: string, evidenceId: string) {
  if (!EVIDENCE_ID.test(evidenceId)) {
    return { ok: false as const, code: "INVALID_INPUT", reason: "证据编号格式无效" };
  }
  let filePath: string;
  try {
    const canonicalRoot = await realpath(root);
    const relativeFile = path.join("evidence", "opencode", `${evidenceId}.json`);
    filePath = await realpath(path.join(canonicalRoot, relativeFile));
    if (path.relative(canonicalRoot, filePath) !== relativeFile) {
      return { ok: false as const, code: "PATH_REJECTED", reason: "证据文件被重定向到项目外部" };
    }
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    return { ok: false as const, code: missing ? "NOT_FOUND" : "IO_ERROR",
      reason: missing ? `找不到证据 ${evidenceId}` : "无法定位项目证据文件" };
  }
  const loaded = await loadVerifiedEvidenceFile(filePath);
  if (!loaded.ok) return { ...loaded, file_path: filePath };
  if (loaded.record.evidence_id !== evidenceId) {
    return { ok: false as const, code: "INVALID_EVIDENCE_FILE",
      reason: "证据编号与文件名不一致", file_path: filePath };
  }
  return { ok: true as const, record: loaded.record, file_path: filePath };
}

function singleParameter(record: EvidenceRecord, markerPattern: RegExp) {
  try {
    const url = new URL(record.observation.request.url);
    const entries = [...url.searchParams.entries()];
    if (entries.length !== 1 || !markerPattern.test(entries[0][1])) return undefined;
    const value = entries[0][1];
    url.search = "";
    url.hash = "";
    return { endpoint: url.href, parameterName: entries[0][0], value };
  } catch {
    return undefined;
  }
}

function fingerprint(endpoint: string, parameterName: string): string {
  return createHash("sha256")
    .update(`reflected_xss\n${endpoint}\n${parameterName}`, "utf8")
    .digest("hex");
}

function evidenceIds(recordIds: string[]): string[] {
  return [...new Set(recordIds)];
}

/**
 * 对两份已保存 EV 做离线关联：只有观察到原样边界字符时才记录 suspected HYP。
 * 本流程不发送请求、不执行脚本，也不会把候选自动确认为漏洞。
 */
export async function runXssHypothesisTriage(
  projectRoot: string,
  input: XssHypothesisTriageInput,
  options: XssHypothesisTriageOptions = {},
) {
  if (!input || typeof input.reflection_evidence_id !== "string" ||
      typeof input.encoding_evidence_id !== "string" ||
      typeof input.authorization_reference !== "string" ||
      input.reflection_evidence_id === input.encoding_evidence_id) {
    return { ok: false as const, code: "INVALID_INPUT",
      reason: "请提供两条不同的完整 EV 编号和本地授权引用" };
  }
  const root = path.resolve(projectRoot);
  const [reflection, encoding] = await Promise.all([
    loadProjectEvidence(root, input.reflection_evidence_id),
    loadProjectEvidence(root, input.encoding_evidence_id),
  ]);
  if (!reflection.ok) return reflection;
  if (!encoding.ok) return encoding;
  if (!headerValue(reflection.record.observation.response.headers, "content-type")
    ?.toLowerCase().includes("text/html") ||
      !headerValue(encoding.record.observation.response.headers, "content-type")
        ?.toLowerCase().includes("text/html")) {
    return { ok: false as const, code: "NOT_HTML", reason: "两份证据都必须来自 HTML 响应" };
  }

  const reflected = singleParameter(reflection.record, REFLECTION_MARKER);
  const encoded = singleParameter(encoding.record, ENCODING_MARKER);
  if (!reflected || !encoded || !reflection.record.observation.response.body.includes(reflected.value)) {
    return { ok: false as const, code: "INVALID_EVIDENCE_PAIR",
      reason: "第一份 EV 未证明单个 GET 参数反射，或第二份 EV 不是编码探针证据" };
  }
  if (reflected.endpoint !== encoded.endpoint || reflected.parameterName !== encoded.parameterName) {
    return { ok: false as const, code: "EVIDENCE_MISMATCH",
      reason: "两份 EV 不是同一规范化端点和同一参数，拒绝关联" };
  }
  if (!reflected.parameterName || reflected.parameterName.length > 256) {
    return { ok: false as const, code: "INVALID_EVIDENCE_PAIR", reason: "参数名为空或过长" };
  }

  const nonce = encoded.value.match(ENCODING_MARKER)?.[1];
  if (!nonce) {
    return { ok: false as const, code: "INVALID_EVIDENCE_PAIR", reason: "无法恢复编码探针编号" };
  }
  const probe = createXssEncodingProbe(nonce);
  if (encoded.value !== probe.payload) {
    return { ok: false as const, code: "INVALID_EVIDENCE_PAIR",
      reason: "第二份 EV 的请求值不是项目定义的完整非执行编码探针" };
  }
  const context = analyzeReflectionContext(
    reflection.record.observation.response.body,
    reflected.value,
  );
  const observation = analyzeXssEncodingObservation(
    encoding.record.observation.response.body,
    probe,
  );
  const base = {
    endpoint: reflected.endpoint,
    parameter_name: reflected.parameterName,
    reflection_context: context.outcome,
    encoding_outcome: observation.outcome,
    evidence_ids: evidenceIds([
      reflection.record.evidence_id,
      encoding.record.evidence_id,
    ]),
  };

  if (observation.outcome === "all_observed_characters_encoded") {
    return { ok: true as const, code: "NO_HYPOTHESIS_NEEDED",
      reason: "本次五个边界字符均被编码，不为这次观察创建漏洞假设", result: base };
  }
  if (observation.outcome !== "raw_special_characters_observed") {
    return { ok: true as const, code: "TRIAGE_INCONCLUSIVE",
      reason: "编码观察不足以形成稳定候选，保留 EV 但不创建漏洞假设", result: base };
  }

  const candidateIdentity: HypothesisCandidateIdentity = {
    kind: "reflected_xss",
    endpoint: reflected.endpoint,
    parameter_name: reflected.parameterName,
    fingerprint: fingerprint(reflected.endpoint, reflected.parameterName),
  };
  let scope: ScopeConfig;
  let registry: AuthorizationRegistry;
  try {
    const [scopeJson, registryJson] = await Promise.all([
      readFile(path.join(root, "configs", "scope.local.json"), "utf8"),
      readFile(path.join(root, "configs", "authorization.local.json"), "utf8"),
    ]);
    scope = JSON.parse(scopeJson) as ScopeConfig;
    registry = JSON.parse(registryJson) as AuthorizationRegistry;
  } catch {
    return { ok: false as const, code: "CONFIG_ERROR",
      reason: "无法读取范围配置或本地授权登记；未写入 HYP" };
  }
  const scoped = checkUrlScope(reflected.endpoint, scope);
  if (!scoped.allowed || !scoped.target) {
    return { ok: false as const, code: "SCOPE_DENIED", reason: scoped.reason };
  }
  const authorization = checkHypothesisCreateAuthorization(
    scoped.target.url,
    input.authorization_reference,
    registry,
  );
  if (!authorization.authorized) {
    return { ok: false as const, code: "AUTHORIZATION_DENIED", reason: authorization.reason };
  }

  const store = new HypothesisStore(path.join(root, "hypotheses", "opencode"));
  const listed = await store.list();
  if (!listed.ok) return listed;
  const existing = listed.records.find(item =>
    item.hypothesis.candidate_identity?.fingerprint === candidateIdentity.fingerprint);
  const missingEvidence = existing ? base.evidence_ids.filter(id =>
    !existing.hypothesis.evidence.some(ref => ref.evidence_id === id)) : base.evidence_ids;
  if (existing && (missingEvidence.length === 0 ||
      existing.hypothesis.status === "confirmed" || existing.hypothesis.status === "rejected")) {
    return { ok: true as const, code: "HYPOTHESIS_REUSED",
      reason: missingEvidence.length === 0
        ? "同一端点、参数和漏洞类型已有 HYP，未重复创建"
        : "同一候选已有终态 HYP；复用编号但不自动改写终态记录",
      hypothesis_id: existing.hypothesis.hypothesis_id,
      status: existing.hypothesis.status,
      result: base,
    };
  }
  if (typeof options.approve !== "function") {
    return { ok: false as const, code: "APPROVAL_UNAVAILABLE",
      reason: "当前运行环境无法确认本地 HYP 写入；未修改假设记录" };
  }
  try {
    await options.approve({
      permission: "xss_hypothesis_record",
      endpoint: reflected.endpoint,
      parameter_name: reflected.parameterName,
      candidate_fingerprint: candidateIdentity.fingerprint,
      evidence_ids: base.evidence_ids,
    });
  } catch {
    return { ok: false as const, code: "APPROVAL_DENIED",
      reason: "用户未批准本次候选关联；未修改假设记录" };
  }

  await mkdir(store.outputDir, { recursive: true });
  const lockPath = path.join(store.outputDir, `.candidate-${candidateIdentity.fingerprint}.lock`);
  try {
    await mkdir(lockPath);
  } catch {
    return { ok: false as const, code: "VERSION_CONFLICT",
      reason: "同一候选正在由另一个流程处理；请稍后重试，未创建重复 HYP" };
  }
  try {
    const refreshed = await store.list();
    if (!refreshed.ok) return refreshed;
    const current = refreshed.records.find(item =>
      item.hypothesis.candidate_identity?.fingerprint === candidateIdentity.fingerprint);
    if (current) {
      const missing = base.evidence_ids.filter(id =>
        !current.hypothesis.evidence.some(ref => ref.evidence_id === id));
      if (missing.length === 0 || current.hypothesis.status === "confirmed" ||
          current.hypothesis.status === "rejected") {
        return { ok: true as const, code: "HYPOTHESIS_REUSED",
          reason: "并发复核后发现已有同一候选 HYP，未重复创建",
          hypothesis_id: current.hypothesis.hypothesis_id,
          status: current.hypothesis.status,
          result: base };
      }
      const fileById = new Map([
        [reflection.record.evidence_id, reflection.file_path],
        [encoding.record.evidence_id, encoding.file_path],
      ]);
      const attached = await attachHypothesisEvidence(
        current.hypothesis,
        missing.map(id => fileById.get(id)!),
        "同一反射型 XSS 候选产生了新的已校验证据；仅追加证据，不改变状态",
      );
      if (!attached.ok) return attached;
      const saved = await store.update(attached.hypothesis, current.payload_sha256);
      if (!saved.ok) return saved;
      return { ok: true as const, code: "HYPOTHESIS_EVIDENCE_LINKED",
        reason: "新 EV 已关联到原 HYP，状态未自动改变",
        hypothesis_id: saved.hypothesis.hypothesis_id, status: saved.hypothesis.status,
        file_path: saved.file_path, result: base };
    }

    const created = await createHypothesisWithEvidence({
      title: "反射型 XSS 候选（待验证）",
      description: `参数 ${JSON.stringify(reflected.parameterName)} 的无害标记发生反射，且非执行编码探针观察到原样 HTML 边界字符。该结果只是候选，不代表浏览器中可执行脚本。`,
      target_url: reflected.endpoint,
      reason: "两份通过完整性校验的 EV 形成同一端点和参数的待复核候选",
      authorization_reference: input.authorization_reference,
      candidate_identity: candidateIdentity,
    }, [reflection.file_path, encoding.file_path]);
    if (!created.ok) return created;
    const saved = await store.create(created.hypothesis);
    if (!saved.ok) return saved;
    return { ok: true as const, code: "HYPOTHESIS_RECORDED",
      reason: "已创建 suspected HYP 并关联两份 EV；尚未确认 XSS",
      hypothesis_id: saved.hypothesis.hypothesis_id, status: saved.hypothesis.status,
      file_path: saved.file_path, candidate_fingerprint: candidateIdentity.fingerprint,
      result: base };
  } finally {
    await rm(lockPath, { recursive: true, force: true }).catch(() => {});
  }
}
