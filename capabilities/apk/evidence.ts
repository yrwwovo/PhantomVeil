import { createHash } from "node:crypto";

/**
 * capabilities/apk 的共用证据工具（脱敏 + 双存）。
 *
 * 设计定稿 §5 的硬约定，所有 apk capability 统一走这里，不各写一套：
 *   - 代码/数据片段：原始字节 SHA-256 + 脱敏文本两份并列（raw_sha256 + redacted_text）。
 *   - 密钥/凭据类：只留 算法类别 + 长度 + 前后掩码 + SHA-256，绝不存明文密钥。
 *   - 证书：只留指纹（SHA-256 fingerprint），不存整证书原文。
 *   - 大件（APK/dex/so 等）：只存 hash + 元数据，不落原始字节（stored="hash_only"）。
 *
 * 本模块只做“取证与脱敏”，不产生任何 CWE 判定或漏洞结论。
 */

export type ApkStage =
  | "acquire_unpack"
  | "decompile_manifest"
  | "dex_smali_audit"
  | "so_static_audit";

/** 单条证据超过此大小只存 hash + 元数据（脱敏片段仍可另给）。 */
export const MAX_SNIPPET_BYTES = 16 * 1024;

export interface EvidenceEntry {
  schema_version: 1;
  /** 片段级：脱敏前原始字节的 SHA-256，用作 evidence_id（§5）。 */
  evidence_id: string;
  stage: ApkStage;
  /** 来源文件（APK/dex/so/manifest）整文件 SHA-256；无来源文件为 null。 */
  source_file_sha256: string | null;
  /** 定位锚点字符串：manifest 节点 / 类#方法:行 / so 符号·偏移。 */
  locator: string;
  /** 原始片段字节的 SHA-256（片段场景等于 evidence_id；大件为文件 hash）。 */
  raw_sha256: string;
  /** 脱敏后文本；大件/只存 hash 时为元数据描述字符串。 */
  redacted_text: string;
  /** 原始片段/文件字节数。 */
  byte_length: number;
  /** snippet=双存脱敏片段；hash_only=只存 hash+元数据。 */
  stored: "snippet" | "hash_only";
  created_at: string;
}

export function sha256Hex(bytes: Uint8Array | Buffer | string): string {
  return createHash("sha256").update(bytes as Buffer).digest("hex");
}

/** 通用前后掩码：保留前后各 keep 个字符，中间用省略号，绝不回显完整值。 */
export function maskValue(value: string, keep = 3): string {
  const v = value.trim();
  if (v.length <= keep * 2) return "*".repeat(Math.max(v.length, 1));
  return `${v.slice(0, keep)}……${v.slice(-keep)}`;
}

/**
 * 密钥/凭据脱敏：只产出 算法类别 + 长度(字节) + 掩码 + SHA-256。
 * 绝不返回明文；完整值仅以 SHA-256 入库。
 */
export interface RedactedSecret {
  kind: "secret_material";
  algorithm_hint: string;
  byte_length: number;
  masked: string;
  sha256: string;
}

export function redactSecret(value: string, algorithmHint = "unknown"): RedactedSecret {
  const bytes = Buffer.from(value, "utf8");
  return {
    kind: "secret_material",
    algorithm_hint: algorithmHint,
    byte_length: bytes.length,
    masked: maskValue(value, 2),
    sha256: sha256Hex(bytes),
  };
}

/** 证书脱敏：只留指纹（SHA-256），不存整证书。 */
export interface CertFingerprint {
  kind: "cert_fingerprint";
  sha256: string;
  /** 可选：apksigner/keytool 已给出的指纹串（直接保留，不另存证书）。 */
  reported_fingerprint?: string;
}

export function certFingerprint(derOrReported: {
  der?: Uint8Array | Buffer;
  reported_sha256?: string;
}): CertFingerprint {
  const sha256 = derOrReported.der
    ? sha256Hex(derOrReported.der)
    : (derOrReported.reported_sha256 ?? "").replace(/[^a-fA-F0-9]/g, "").toLowerCase();
  return {
    kind: "cert_fingerprint",
    sha256,
    ...(derOrReported.reported_sha256 ? { reported_fingerprint: derOrReported.reported_sha256 } : {}),
  };
}

/** 对文本片段按通用规则脱敏：PEM 私钥块、长 hex/base64 串、BEGIN...KEY 等替换为掩码占位。 */
export function redactSnippet(text: string): string {
  let out = text;
  // PEM 私钥/证书块 -> 掩码（只保留头尾标记，中间以 hash 占位）。
  out = out.replace(/-----BEGIN ([A-Z ]+)-----[\s\S]*?-----END \1-----/g, (m, label) => {
    const sha = sha256Hex(m);
    return `-----BEGIN ${label}-----[REDACTED len=${m.length} sha256=${sha.slice(0, 16)}…]-----END ${label}-----`;
  });
  // 连续 32+ 位 hex（疑似密钥/盐/指纹常量）-> 掩码（§3.3 / flutter §5.3）。
  out = out.replace(/\b[0-9a-fA-F]{32,}\b/g, (m) => `${maskValue(m, 4)}[hex${m.length} sha256=${sha256Hex(m).slice(0, 12)}…]`);
  // 疑似 base64 密钥（40+）-> 掩码。
  out = out.replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, (m) => `${maskValue(m, 4)}[b64${m.length} sha256=${sha256Hex(m).slice(0, 12)}…]`);
  return out;
}

export interface MakeSnippetArgs {
  stage: ApkStage;
  locator: string;
  /** 脱敏前原始片段文本/字节。 */
  raw: string | Uint8Array | Buffer;
  sourceFileSha256?: string | null;
  /** 覆盖默认脱敏器（默认 redactSnippet）。 */
  redactor?: (text: string) => string;
  now?: () => Date;
}

/**
 * 片段级双存证据：raw 原始字节算 SHA-256 作 evidence_id，脱敏文本并列。
 * 超过 MAX_SNIPPET_BYTES 时自动退化为 hash_only（只存 hash + 元数据）。
 */
export function makeSnippetEvidence(args: MakeSnippetArgs): EvidenceEntry {
  const buf = typeof args.raw === "string" ? Buffer.from(args.raw, "utf8") : Buffer.from(args.raw);
  const rawSha = sha256Hex(buf);
  const createdAt = (args.now ? args.now() : new Date()).toISOString();
  if (buf.length > MAX_SNIPPET_BYTES) {
    return {
      schema_version: 1,
      evidence_id: rawSha,
      stage: args.stage,
      source_file_sha256: args.sourceFileSha256 ?? null,
      locator: args.locator,
      raw_sha256: rawSha,
      redacted_text: `[oversize snippet: ${buf.length}B 仅存 hash+元数据，原文不入库]`,
      byte_length: buf.length,
      stored: "hash_only",
      created_at: createdAt,
    };
  }
  const redactor = args.redactor ?? redactSnippet;
  const redacted = redactor(buf.toString("utf8"));
  return {
    schema_version: 1,
    evidence_id: rawSha,
    stage: args.stage,
    source_file_sha256: args.sourceFileSha256 ?? null,
    locator: args.locator,
    raw_sha256: rawSha,
    redacted_text: redacted,
    byte_length: buf.length,
    stored: "snippet",
    created_at: createdAt,
  };
}

export interface MakeLargeFileArgs {
  stage: ApkStage;
  locator: string;
  fileSha256: string;
  byteLength: number;
  /** 脱敏后的元数据描述（不含原始字节）。 */
  metadata: string;
  now?: () => Date;
}

/** 大件证据：只存 hash + 元数据 + 脱敏描述，原始大件不入库（§4 决策/§5）。 */
export function makeLargeFileEvidence(args: MakeLargeFileArgs): EvidenceEntry {
  const createdAt = (args.now ? args.now() : new Date()).toISOString();
  return {
    schema_version: 1,
    evidence_id: args.fileSha256,
    stage: args.stage,
    source_file_sha256: args.fileSha256,
    locator: args.locator,
    raw_sha256: args.fileSha256,
    redacted_text: args.metadata,
    byte_length: args.byteLength,
    stored: "hash_only",
    created_at: createdAt,
  };
}

/** 生成 ScanFinding.evidence_refs 的寻址串：ev://<apk_sha256>/<path>#<anchor>（§3/§5）。 */
export function evidenceRef(apkSha256: string, pathPart: string, anchor?: string): string {
  const base = `ev://${apkSha256}/${pathPart.replace(/^\/+/, "")}`;
  return anchor ? `${base}#${anchor}` : base;
}
