import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import type {
  HttpGetResult,
  RedirectRecord,
} from "../../capabilities/web/restricted-http-get.ts";

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  "proxy-authenticate",
  "set-cookie",
  "www-authenticate",
  "x-api-key",
]);
const SENSITIVE_QUERY_NAME =
  /^(?:access_token|api[-_]?key|auth|authorization|cookie|password|secret|session|token)$/iu;
const REDACTED = "[REDACTED]";

export interface HttpEvidenceObservation {
  request: {
    method: "GET";
    url: string;
    resolved_ip: string;
  };
  response: {
    status: number;
    headers: Record<string, string | string[]>;
    body: string;
    body_bytes: number;
    body_sha256: string;
  };
  redirects: RedirectRecord[];
}

export interface EvidencePayload {
  schema_version: 1;
  evidence_id: string;
  kind: "http_exchange";
  created_at: string;
  observation: HttpEvidenceObservation;
}

export interface EvidenceRecord extends EvidencePayload {
  integrity: {
    algorithm: "sha256";
    payload_sha256: string;
  };
}

export type EvidenceSaveResult =
  | {
      ok: true;
      code: "EVIDENCE_SAVED";
      reason: string;
      evidence_id: string;
      file_path: string;
      payload_sha256: string;
    }
  | {
      ok: false;
      code: "INVALID_OBSERVATION" | "WRITE_ERROR";
      reason: string;
    };

export type EvidenceVerifyResult =
  | {
      ok: true;
      code: "EVIDENCE_VALID";
      reason: string;
      evidence_id: string;
    }
  | {
      ok: false;
      code: "INVALID_EVIDENCE_FILE" | "HASH_MISMATCH" | "READ_ERROR";
      reason: string;
      evidence_id?: string;
    };

export type EvidenceLoadResult =
  | {
      ok: true;
      code: "EVIDENCE_VALID";
      reason: string;
      record: EvidenceRecord;
    }
  | {
      ok: false;
      code: "INVALID_EVIDENCE_FILE" | "HASH_MISMATCH" | "READ_ERROR";
      reason: string;
      evidence_id?: string;
    };

export interface EvidenceStoreOptions {
  output_dir?: string;
  now?: () => Date;
  id_factory?: () => string;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function redactUrl(value: string): string {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    for (const name of [...url.searchParams.keys()]) {
      if (SENSITIVE_QUERY_NAME.test(name)) {
        url.searchParams.set(name, REDACTED);
      }
    }
    return url.href;
  } catch {
    return value;
  }
}

function redactHeaders(
  headers: Record<string, string | string[]>,
): Record<string, string | string[]> {
  const redacted: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    redacted[name] = SENSITIVE_HEADERS.has(name.toLowerCase()) ? REDACTED : value;
  }
  return redacted;
}

function redactRedirects(redirects: RedirectRecord[]): RedirectRecord[] {
  return redirects.map((redirect) => ({
    ...redirect,
    from: redactUrl(redirect.from),
    to: redactUrl(redirect.to),
  }));
}

function isEvidenceRecord(value: unknown): value is EvidenceRecord {
  if (!value || typeof value !== "object") {
    return false;
  }
  const record = value as Partial<EvidenceRecord>;
  const observation = record.observation as
    | Partial<HttpEvidenceObservation>
    | undefined;
  const request = observation?.request;
  const response = observation?.response;
  return (
    record.schema_version === 1 &&
    typeof record.evidence_id === "string" &&
    record.kind === "http_exchange" &&
    typeof record.created_at === "string" &&
    request?.method === "GET" &&
    typeof request.url === "string" &&
    typeof request.resolved_ip === "string" &&
    typeof response?.status === "number" &&
    Boolean(response.headers) &&
    typeof response.body === "string" &&
    typeof response.body_bytes === "number" &&
    typeof response.body_sha256 === "string" &&
    Array.isArray(observation?.redirects) &&
    record.integrity?.algorithm === "sha256" &&
    typeof record.integrity.payload_sha256 === "string"
  );
}

export class EvidenceStore {
  readonly outputDir: string;
  private readonly now: () => Date;
  private readonly idFactory: () => string;

  constructor(options: EvidenceStoreOptions = {}) {
    this.outputDir = path.resolve(options.output_dir ?? "evidence");
    this.now = options.now ?? (() => new Date());
    this.idFactory = options.id_factory ?? randomUUID;
  }

  async saveHttpGet(result: HttpGetResult): Promise<EvidenceSaveResult> {
    if (!result.ok || !result.response) {
      return {
        ok: false,
        code: "INVALID_OBSERVATION",
        reason: "只有成功取得的 HTTP 响应可以保存为证据",
      };
    }

    const createdAt = this.now().toISOString();
    const compactDate = createdAt.replace(/[-:.TZ]/gu, "").slice(0, 14);
    const evidenceId = `EV-${compactDate}-${this.idFactory().slice(0, 8)}`;
    const bodySha256 = sha256(result.response.body);
    const payload: EvidencePayload = {
      schema_version: 1,
      evidence_id: evidenceId,
      kind: "http_exchange",
      created_at: createdAt,
      observation: {
        request: {
          method: "GET",
          url: redactUrl(result.response.url),
          resolved_ip: result.response.resolved_ip,
        },
        response: {
          status: result.response.status,
          headers: redactHeaders(result.response.headers),
          body: result.response.body,
          body_bytes: result.response.body_bytes,
          body_sha256: bodySha256,
        },
        redirects: redactRedirects(result.redirects),
      },
    };
    const payloadSha256 = sha256(JSON.stringify(payload));
    const record: EvidenceRecord = {
      ...payload,
      integrity: {
        algorithm: "sha256",
        payload_sha256: payloadSha256,
      },
    };
    const filePath = path.join(this.outputDir, `${evidenceId}.json`);
    const temporaryPath = path.join(
      this.outputDir,
      `.${evidenceId}.${randomUUID()}.tmp`,
    );

    try {
      await mkdir(this.outputDir, { recursive: true });
      await writeFile(temporaryPath, `${JSON.stringify(record, null, 2)}\n`, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
      await rename(temporaryPath, filePath);
      return {
        ok: true,
        code: "EVIDENCE_SAVED",
        reason: "HTTP 观察已保存为本地证据",
        evidence_id: evidenceId,
        file_path: filePath,
        payload_sha256: payloadSha256,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        ok: false,
        code: "WRITE_ERROR",
        reason: `证据写入失败：${message}`,
      };
    }
  }
}

export async function loadVerifiedEvidenceFile(
  filePath: string,
): Promise<EvidenceLoadResult> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(filePath, "utf8"));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      code: "READ_ERROR",
      reason: `无法读取证据文件：${message}`,
    };
  }

  if (!isEvidenceRecord(parsed)) {
    return {
      ok: false,
      code: "INVALID_EVIDENCE_FILE",
      reason: "文件不符合 evidence schema v1",
    };
  }

  const { integrity, ...payload } = parsed;
  const actualHash = sha256(JSON.stringify(payload));
  if (actualHash !== integrity.payload_sha256) {
    return {
      ok: false,
      code: "HASH_MISMATCH",
      reason: "证据内容与保存时的 SHA-256 不一致",
      evidence_id: parsed.evidence_id,
    };
  }

  return {
    ok: true,
    code: "EVIDENCE_VALID",
    reason: "证据结构和 SHA-256 校验通过",
    record: parsed,
  };
}

export async function verifyEvidenceFile(
  filePath: string,
): Promise<EvidenceVerifyResult> {
  const loaded = await loadVerifiedEvidenceFile(filePath);
  if (!loaded.ok) {
    return loaded;
  }
  return {
    ok: true,
    code: "EVIDENCE_VALID",
    reason: loaded.reason,
    evidence_id: loaded.record.evidence_id,
  };
}
