import { createHash, randomUUID } from "node:crypto";
import { link, mkdir, readFile, readdir, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import { loadVerifiedEvidenceFile } from "../evidence/evidence-store.ts";
import type { Hypothesis, HypothesisStatus } from "./hypothesis-manager.ts";

const HYPOTHESIS_ID = /^HYP-\d{14}-[a-f0-9]{8}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_FILE_BYTES = 1024 * 1024;
const PARAMETER_LOCATIONS = new Set(["query", "body", "header", "cookie", "path"]);
const STATUSES = new Set<HypothesisStatus>([
  "suspected",
  "testing",
  "confirmed",
  "rejected",
  "inconclusive",
]);
const ALLOWED_TRANSITIONS: Record<HypothesisStatus, HypothesisStatus[]> = {
  suspected: ["testing", "rejected", "inconclusive"],
  testing: ["confirmed", "rejected", "inconclusive"],
  inconclusive: ["testing", "rejected"],
  confirmed: [],
  rejected: [],
};

interface StoredHypothesis {
  schema_version: 1;
  hypothesis: Hypothesis;
  integrity: {
    algorithm: "sha256";
    payload_sha256: string;
  };
}

export type HypothesisStoreResult =
  | {
      ok: true;
      code: "HYPOTHESIS_SAVED" | "HYPOTHESIS_LOADED";
      reason: string;
      hypothesis: Hypothesis;
      file_path: string;
      payload_sha256: string;
    }
  | {
      ok: false;
      code:
        | "INVALID_ID"
        | "INVALID_HYPOTHESIS"
        | "ALREADY_EXISTS"
        | "NOT_FOUND"
        | "INVALID_FILE"
        | "HASH_MISMATCH"
        | "VERSION_CONFLICT"
        | "IO_ERROR";
      reason: string;
    };

export type HypothesisListResult =
  | {
      ok: true;
      code: "HYPOTHESES_LISTED";
      reason: string;
      records: Array<{
        hypothesis: Hypothesis;
        file_path: string;
        payload_sha256: string;
      }>;
    }
  | {
      ok: false;
      code: "INVALID_FILE" | "IO_ERROR";
      reason: string;
    };

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function timestamp(value: unknown): value is string {
  return typeof value === "string" &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}

function status(value: unknown): value is HypothesisStatus {
  return typeof value === "string" && STATUSES.has(value as HypothesisStatus);
}

function validHypothesis(value: unknown): value is Hypothesis {
  if (!object(value)) return false;
  if (
    value.schema_version !== 1 ||
    typeof value.hypothesis_id !== "string" ||
    !HYPOTHESIS_ID.test(value.hypothesis_id) ||
    (value.authorization_reference !== undefined &&
      (typeof value.authorization_reference !== "string" ||
        !/^[A-Z0-9][A-Z0-9._-]{5,63}$/u.test(value.authorization_reference))) ||
    !nonEmpty(value.title) ||
    !nonEmpty(value.description) ||
    !nonEmpty(value.target_url) ||
    !status(value.status) ||
    !timestamp(value.created_at) ||
    !timestamp(value.updated_at) ||
    !Array.isArray(value.evidence) ||
    !Array.isArray(value.reproduction_steps) ||
    !Array.isArray(value.history) ||
    value.history.length === 0
  ) return false;

  if (value.candidate_identity !== undefined) {
    const candidate = value.candidate_identity;
    if (!object(candidate) || candidate.kind !== "reflected_xss" ||
        !nonEmpty(candidate.parameter_name) || candidate.parameter_name.length > 256 ||
        typeof candidate.fingerprint !== "string" || !SHA256.test(candidate.fingerprint) ||
        (candidate.location !== undefined &&
          (typeof candidate.location !== "string" || !PARAMETER_LOCATIONS.has(candidate.location))) ||
        !nonEmpty(candidate.endpoint)) return false;
    try {
      const endpoint = new URL(candidate.endpoint);
      if ((endpoint.protocol !== "http:" && endpoint.protocol !== "https:") ||
          endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
          endpoint.href !== value.target_url) return false;
    } catch {
      return false;
    }
  }

  try {
    const url = new URL(value.target_url);
    if ((url.protocol !== "http:" && url.protocol !== "https:") ||
        url.username || url.password) return false;
  } catch {
    return false;
  }

  const evidenceIds = new Set<string>();
  for (const ref of value.evidence) {
    if (
      !object(ref) ||
      !nonEmpty(ref.evidence_id) ||
      !nonEmpty(ref.file_path) ||
      typeof ref.payload_sha256 !== "string" ||
      !SHA256.test(ref.payload_sha256) ||
      evidenceIds.has(ref.evidence_id)
    ) return false;
    evidenceIds.add(ref.evidence_id);
  }
  if (value.reproduction_steps.some((step) => !nonEmpty(step))) return false;
  if (
    value.status === "confirmed" &&
    (value.evidence.length === 0 || value.reproduction_steps.length === 0)
  ) return false;

  let previous: HypothesisStatus | null = null;
  let previousTime = 0;
  for (const [index, entry] of value.history.entries()) {
    if (
      !object(entry) ||
      !status(entry.to) ||
      !timestamp(entry.changed_at) ||
      !nonEmpty(entry.reason) ||
      (entry.reason_code !== undefined && !nonEmpty(entry.reason_code)) ||
      (entry.event !== undefined && entry.event !== "status_change" &&
        entry.event !== "evidence_attached")
    ) return false;
    if (index === 0) {
      if (entry.from !== null || entry.to !== "suspected" ||
          entry.changed_at !== value.created_at) return false;
    } else {
      if (entry.from !== previous || previous === null) return false;
      if (entry.event === "evidence_attached") {
        if (entry.to !== previous) return false;
      } else if (!ALLOWED_TRANSITIONS[previous].includes(entry.to)) return false;
    }
    const changedAt = Date.parse(entry.changed_at);
    if (changedAt < previousTime) return false;
    previousTime = changedAt;
    previous = entry.to;
  }
  return previous === value.status &&
    value.updated_at === value.history.at(-1)?.changed_at;
}

function makeRecord(hypothesis: Hypothesis): StoredHypothesis {
  const payload = { schema_version: 1 as const, hypothesis };
  return {
    ...payload,
    integrity: { algorithm: "sha256", payload_sha256: digest(payload) },
  };
}

function failure(code: Extract<HypothesisStoreResult, { ok: false }>["code"], reason: string): HypothesisStoreResult {
  return { ok: false, code, reason };
}

export class HypothesisStore {
  readonly outputDir: string;

  constructor(outputDir = "hypotheses") {
    this.outputDir = path.resolve(outputDir);
  }

  private filePath(id: string): string | undefined {
    return HYPOTHESIS_ID.test(id) ? path.join(this.outputDir, `${id}.json`) : undefined;
  }

  async load(id: string): Promise<HypothesisStoreResult> {
    const filePath = this.filePath(id);
    if (!filePath) return failure("INVALID_ID", "假设编号格式无效");

    let contents: string;
    try {
      if ((await stat(filePath)).size > MAX_FILE_BYTES) {
        return failure("INVALID_FILE", "假设文件超过 1 MiB 限制");
      }
      contents = await readFile(filePath, "utf8");
    } catch (error) {
      if (object(error) && error.code === "ENOENT") {
        return failure("NOT_FOUND", "找不到该假设文件");
      }
      return failure("IO_ERROR", "读取假设文件失败");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(contents);
    } catch {
      return failure("INVALID_FILE", "假设文件不是有效 JSON");
    }
    if (!object(parsed) || parsed.schema_version !== 1 ||
        !object(parsed.integrity) || parsed.integrity.algorithm !== "sha256" ||
        typeof parsed.integrity.payload_sha256 !== "string" ||
        !SHA256.test(parsed.integrity.payload_sha256)) {
      return failure("INVALID_FILE", "假设文件结构或完整性字段无效");
    }
    const payload = { schema_version: parsed.schema_version, hypothesis: parsed.hypothesis };
    if (digest(payload) !== parsed.integrity.payload_sha256) {
      return failure("HASH_MISMATCH", "假设文件内容与保存时的 SHA-256 不一致");
    }
    if (!validHypothesis(parsed.hypothesis) || parsed.hypothesis.hypothesis_id !== id) {
      return failure("INVALID_FILE", "假设内容或状态历史不符合格式要求");
    }
    return {
      ok: true,
      code: "HYPOTHESIS_LOADED",
      reason: "假设文件和状态历史校验通过",
      hypothesis: parsed.hypothesis,
      file_path: filePath,
      payload_sha256: parsed.integrity.payload_sha256,
    };
  }

  async list(): Promise<HypothesisListResult> {
    let entries;
    try {
      entries = await readdir(this.outputDir, { withFileTypes: true });
    } catch (error) {
      if (object(error) && error.code === "ENOENT") {
        return { ok: true, code: "HYPOTHESES_LISTED", reason: "假设目录尚不存在", records: [] };
      }
      return { ok: false, code: "IO_ERROR", reason: "无法读取假设目录" };
    }
    const ids = entries.filter(entry => entry.isFile() && HYPOTHESIS_ID.test(
      entry.name.replace(/\.json$/u, ""),
    ) && entry.name.endsWith(".json")).map(entry => entry.name.slice(0, -5)).sort();
    const records: Extract<HypothesisListResult, { ok: true }>["records"] = [];
    for (const id of ids) {
      const loaded = await this.load(id);
      if (!loaded.ok) {
        return { ok: false, code: "INVALID_FILE",
          reason: `无法安全枚举假设：${id} 未通过校验（${loaded.reason}）` };
      }
      records.push({ hypothesis: loaded.hypothesis, file_path: loaded.file_path,
        payload_sha256: loaded.payload_sha256 });
    }
    return { ok: true, code: "HYPOTHESES_LISTED", reason: "假设列表校验完成", records };
  }

  async create(hypothesis: Hypothesis): Promise<HypothesisStoreResult> {
    if (!validHypothesis(hypothesis) || hypothesis.status !== "suspected" ||
        hypothesis.history.length !== 1) {
      return failure("INVALID_HYPOTHESIS", "只能保存结构有效的新建 suspected 假设");
    }
    const filePath = this.filePath(hypothesis.hypothesis_id)!;
    const record = makeRecord(hypothesis);
    const serialized = `${JSON.stringify(record, null, 2)}\n`;
    if (Buffer.byteLength(serialized, "utf8") > MAX_FILE_BYTES) {
      return failure("INVALID_HYPOTHESIS", "假设内容超过 1 MiB 限制");
    }
    const temporaryPath = path.join(this.outputDir, `.${hypothesis.hypothesis_id}.${randomUUID()}.tmp`);
    try {
      await mkdir(this.outputDir, { recursive: true });
      await writeFile(temporaryPath, serialized, {
        encoding: "utf8", flag: "wx", mode: 0o600,
      });
      // 同目录硬链接仅在目标不存在时成功，避免覆盖已有假设。
      await link(temporaryPath, filePath);
      return {
        ok: true, code: "HYPOTHESIS_SAVED", reason: "新假设已保存到本地",
        hypothesis, file_path: filePath, payload_sha256: record.integrity.payload_sha256,
      };
    } catch (error) {
      if (object(error) && error.code === "EEXIST") {
        return failure("ALREADY_EXISTS", "该假设编号已存在，未覆盖原文件");
      }
      return failure("IO_ERROR", "保存新假设失败");
    } finally {
      await rm(temporaryPath, { force: true }).catch(() => {});
    }
  }

  async update(hypothesis: Hypothesis, expectedSha256: string): Promise<HypothesisStoreResult> {
    if (!validHypothesis(hypothesis)) {
      return failure("INVALID_HYPOTHESIS", "待保存的假设结构或历史无效");
    }
    if (!SHA256.test(expectedSha256)) {
      return failure("INVALID_HYPOTHESIS", "需要提供上次读取的有效版本指纹");
    }
    const current = await this.load(hypothesis.hypothesis_id);
    if (!current.ok) return current;
    if (current.payload_sha256 !== expectedSha256) {
      return failure("VERSION_CONFLICT", "假设已被更新；请重新读取后再修改");
    }
    if (
      hypothesis.created_at !== current.hypothesis.created_at ||
      hypothesis.authorization_reference !== current.hypothesis.authorization_reference ||
      JSON.stringify(hypothesis.candidate_identity) !==
        JSON.stringify(current.hypothesis.candidate_identity) ||
      hypothesis.title !== current.hypothesis.title ||
      hypothesis.description !== current.hypothesis.description ||
      hypothesis.target_url !== current.hypothesis.target_url ||
      hypothesis.history.length !== current.hypothesis.history.length + 1 ||
      JSON.stringify(hypothesis.history.slice(0, -1)) !== JSON.stringify(current.hypothesis.history) ||
      hypothesis.history.at(-1)?.from !== current.hypothesis.status
    ) {
      return failure("INVALID_HYPOTHESIS", "更新必须保留原始内容和历史，并只追加一次合法历史事件");
    }
    if (hypothesis.history.at(-1)?.event === "evidence_attached" &&
        hypothesis.evidence.length <= current.hypothesis.evidence.length) {
      return failure("INVALID_HYPOTHESIS", "证据关联事件必须至少追加一份新证据");
    }
    for (const previousRef of current.hypothesis.evidence) {
      if (!hypothesis.evidence.some((ref) =>
        ref.evidence_id === previousRef.evidence_id &&
        ref.file_path === previousRef.file_path &&
        ref.payload_sha256 === previousRef.payload_sha256
      )) {
        return failure("INVALID_HYPOTHESIS", "不能删改已有证据引用");
      }
    }
    if (!current.hypothesis.reproduction_steps.every((step) =>
      hypothesis.reproduction_steps.includes(step)
    )) {
      return failure("INVALID_HYPOTHESIS", "不能删改已有复现步骤");
    }
    for (const ref of hypothesis.evidence) {
      const loaded = await loadVerifiedEvidenceFile(ref.file_path);
      if (!loaded.ok || loaded.record.evidence_id !== ref.evidence_id ||
          loaded.record.integrity.payload_sha256 !== ref.payload_sha256) {
        return failure("INVALID_HYPOTHESIS", "证据引用未通过当前文件的完整性校验");
      }
    }

    const record = makeRecord(hypothesis);
    const serialized = `${JSON.stringify(record, null, 2)}\n`;
    if (Buffer.byteLength(serialized, "utf8") > MAX_FILE_BYTES) {
      return failure("INVALID_HYPOTHESIS", "假设内容超过 1 MiB 限制");
    }
    const temporaryPath = path.join(this.outputDir, `.${hypothesis.hypothesis_id}.${randomUUID()}.tmp`);
    try {
      await writeFile(temporaryPath, serialized, {
        encoding: "utf8", flag: "wx", mode: 0o600,
      });
      await rename(temporaryPath, current.file_path);
      return {
        ok: true, code: "HYPOTHESIS_SAVED", reason: "假设状态和历史已更新",
        hypothesis, file_path: current.file_path, payload_sha256: record.integrity.payload_sha256,
      };
    } catch {
      return failure("IO_ERROR", "更新假设文件失败，原文件未被主动删除");
    } finally {
      await rm(temporaryPath, { force: true }).catch(() => {});
    }
  }
}
