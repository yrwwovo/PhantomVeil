import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { runTool, toolAvailable, type ToolRunResult } from "./run-tool.ts";
import { makeSnippetEvidence, sha256Hex, type EvidenceEntry } from "./evidence.ts";

/**
 * ③ dex/smali 代码审计 · dex_smali_audit（STAGE ③，真实运行）。
 *
 * 用 jadx 反编译后，只输出“事实型候选定位”：哪些调用点出现在哪 类#方法 file:line，
 * 以及（给定 exported 组件时）各组件类里是否出现鉴权/调用方/签名读取类调用点。
 * 报告的是“存在/不存在某类调用点”这一事实与位置，绝不输出 CWE 判定或 if-else 漏洞结论。
 */

/** 中性的“调用点类别”——描述的是 API 面，不是漏洞定性。 */
export type CallSiteCategory =
  | "permission_check_call"   // checkCallingPermission / enforce* 等
  | "caller_identity_call"    // Binder.getCallingUid / getCallingPackage 等
  | "signature_read_call"     // getPackageInfo(GET_SIGNATURES) / signingInfo 等
  | "native_boundary"         // System.loadLibrary / native 方法声明
  | "secret_material_string"; // PEM / 长 hex / base64（脱敏后）

export interface CallSiteMarker {
  category: CallSiteCategory;
  id: string;
  pattern: RegExp;
}

/** 固定标记目录（白名单）；只做字符串/正则匹配，不含任何判定逻辑。 */
export const CALL_SITE_MARKERS: CallSiteMarker[] = [
  { category: "permission_check_call", id: "checkCallingPermission", pattern: /\bcheckCallingPermission\b/ },
  { category: "permission_check_call", id: "checkCallingOrSelfPermission", pattern: /\bcheckCallingOrSelfPermission\b/ },
  { category: "permission_check_call", id: "enforceCallingPermission", pattern: /\benforceCallingPermission\b/ },
  { category: "permission_check_call", id: "enforceCallingOrSelfPermission", pattern: /\benforceCallingOrSelfPermission\b/ },
  { category: "permission_check_call", id: "enforcePermission", pattern: /\benforcePermission\b/ },
  { category: "permission_check_call", id: "checkPermission", pattern: /\bcheckPermission\b/ },
  { category: "caller_identity_call", id: "getCallingUid", pattern: /Binder\.getCallingUid\b|\bgetCallingUid\b/ },
  { category: "caller_identity_call", id: "getCallingPid", pattern: /\bgetCallingPid\b/ },
  { category: "caller_identity_call", id: "getCallingPackage", pattern: /\bgetCallingPackage\b/ },
  { category: "signature_read_call", id: "GET_SIGNATURES", pattern: /GET_SIGNATURES\b/ },
  { category: "signature_read_call", id: "GET_SIGNING_CERTIFICATES", pattern: /GET_SIGNING_CERTIFICATES\b/ },
  { category: "signature_read_call", id: "getPackageInfo", pattern: /\bgetPackageInfo\b/ },
  { category: "signature_read_call", id: "signingInfo", pattern: /\bsigningInfo\b|\bgetSigningInfo\b/ },
  { category: "signature_read_call", id: "apkContentsSigners", pattern: /\bgetApkContentsSigners\b/ },
  { category: "native_boundary", id: "loadLibrary", pattern: /System\.loadLibrary\b|\bloadLibrary\b/ },
  { category: "native_boundary", id: "native_method", pattern: /\bnative\s+[\w<>\[\]]+\s+\w+\s*\(/ },
  { category: "secret_material_string", id: "pem_private_key", pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { category: "secret_material_string", id: "hex_const_32", pattern: /["'][0-9a-fA-F]{32}["']/ },
  { category: "secret_material_string", id: "hex_const_16", pattern: /["'][0-9a-fA-F]{16}["']/ },
];

/** 组件入口方法名（事实枚举用，非判定）。 */
export const ENTRY_METHODS = [
  "onCreate", "onStartCommand", "onReceive", "onBind", "onHandleIntent",
  "query", "insert", "update", "delete", "call", "openFile", "getType",
];

export interface CallSiteHit {
  category: CallSiteCategory;
  marker_id: string;
  class_name: string;
  method_name: string | null;
  file: string;
  line: number;
  evidence_id: string;
}

export interface ComponentCorrelation {
  component: string;
  component_type: string | null;
  source_file: string | null;
  entry_methods_present: string[];
  /** 事实：该组件类文件内是否出现鉴权类调用点（存在/不存在，非判定）。 */
  has_permission_check_call_site: boolean;
  has_caller_identity_call_site: boolean;
  has_signature_read_call_site: boolean;
  call_sites: CallSiteHit[];
}

export interface DexSmaliAuditResult {
  schema_version: 1;
  classification: "apk_dex_smali_facts";
  tool: { name: string; available: boolean; run?: Pick<ToolRunResult, "exit_code" | "timed_out" | "duration_ms">; stub: boolean };
  apk_sha256: string | null;
  scanned: { files: number; bytes: number; truncated: boolean };
  call_sites: CallSiteHit[];
  component_correlation: ComponentCorrelation[];
  summary: Record<CallSiteCategory, number> & { total: number };
  evidence: EvidenceEntry[];
  conclusion: string;
  limitations: string[];
}

const MAX_FILES = 4000;
const MAX_BYTES_PER_FILE = 2 * 1024 * 1024;
const SOURCE_EXT = new Set([".java", ".kt", ".smali"]);

async function walk(dir: string, acc: string[], limit: number): Promise<boolean> {
  let truncated = false;
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return false; }
  for (const e of entries) {
    if (acc.length >= limit) return true;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { if (await walk(full, acc, limit)) truncated = true; }
    else if (SOURCE_EXT.has(path.extname(e.name))) acc.push(full);
  }
  return truncated;
}

function classFromPath(file: string, root: string): string {
  // jadx 输出在 <out>/sources/<pkg>…，apktool 在 <out>/smali/<pkg>…：剥掉这些根段得到纯类名。
  const rel = path.relative(root, file).replace(/\\/g, "/").replace(/^(sources|resources|smali(_classes\d+)?)\//, "");
  return rel.replace(/\.(java|kt|smali)$/, "").replace(/\//g, ".");
}

const METHOD_RE = /(?:public|private|protected|static|final|synchronized|\s)*\b[\w<>\[\],.$]+\s+(\w+)\s*\([^;{]*\)\s*(?:throws[^;{]*)?\{/;
const SMALI_METHOD_RE = /^\.method\s+.*?\b(\w+)\s*\(/;

interface ComponentInput { name: string; type?: string | null }

/** 纯扫描：对已反编译源码目录做事实型调用点清点（无判定）。 */
export async function auditDecompiledSources(
  sourceDir: string,
  opts: { components?: ComponentInput[]; apkSha256?: string | null } = {},
): Promise<Omit<DexSmaliAuditResult, "tool">> {
  const files: string[] = [];
  const truncated = await walk(sourceDir, files, MAX_FILES);
  const callSites: CallSiteHit[] = [];
  const evidence: EvidenceEntry[] = [];
  const fileCache = new Map<string, string[]>();
  let totalBytes = 0;

  for (const file of files) {
    let text: string;
    try {
      const st = await stat(file);
      if (st.size > MAX_BYTES_PER_FILE) continue;
      text = await readFile(file, "utf8");
    } catch { continue; }
    totalBytes += Buffer.byteLength(text, "utf8");
    const lines = text.split(/\r?\n/);
    fileCache.set(file, lines);
    const className = classFromPath(file, sourceDir);
    const isSmali = file.endsWith(".smali");
    let currentMethod: string | null = null;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (isSmali) {
        const sm = SMALI_METHOD_RE.exec(line);
        if (sm) currentMethod = sm[1];
        else if (/^\.end method/.test(line)) currentMethod = null;
      } else {
        const mm = METHOD_RE.exec(line);
        if (mm) currentMethod = mm[1];
      }
      for (const marker of CALL_SITE_MARKERS) {
        if (marker.pattern.test(line)) {
          const ev = makeSnippetEvidence({
            stage: "dex_smali_audit",
            locator: `${className}#${currentMethod ?? "?"}@${path.relative(sourceDir, file)}:${i + 1}`,
            raw: line.trim().slice(0, 1000),
            sourceFileSha256: opts.apkSha256 ?? null,
          });
          evidence.push(ev);
          callSites.push({
            category: marker.category, marker_id: marker.id,
            class_name: className, method_name: currentMethod,
            file: path.relative(sourceDir, file), line: i + 1,
            evidence_id: ev.evidence_id,
          });
        }
      }
    }
  }

  // 组件关联（事实型：出现/未出现某类调用点 + 入口方法清单）。
  const correlation: ComponentCorrelation[] = [];
  for (const comp of opts.components ?? []) {
    const wantClass = comp.name;
    const matchFile = [...fileCache.keys()].find((f) => classFromPath(f, sourceDir) === wantClass);
    const compSites = callSites.filter((cs) => cs.class_name === wantClass);
    const lines = matchFile ? fileCache.get(matchFile) ?? [] : [];
    const entryPresent = ENTRY_METHODS.filter((m) => lines.some((l) => new RegExp(`\\b${m}\\s*\\(`).test(l)));
    correlation.push({
      component: comp.name,
      component_type: comp.type ?? null,
      source_file: matchFile ? path.relative(sourceDir, matchFile) : null,
      entry_methods_present: entryPresent,
      has_permission_check_call_site: compSites.some((c) => c.category === "permission_check_call"),
      has_caller_identity_call_site: compSites.some((c) => c.category === "caller_identity_call"),
      has_signature_read_call_site: compSites.some((c) => c.category === "signature_read_call"),
      call_sites: compSites,
    });
  }

  const summary = {
    permission_check_call: callSites.filter((c) => c.category === "permission_check_call").length,
    caller_identity_call: callSites.filter((c) => c.category === "caller_identity_call").length,
    signature_read_call: callSites.filter((c) => c.category === "signature_read_call").length,
    native_boundary: callSites.filter((c) => c.category === "native_boundary").length,
    secret_material_string: callSites.filter((c) => c.category === "secret_material_string").length,
    total: callSites.length,
  };

  return {
    schema_version: 1, classification: "apk_dex_smali_facts",
    apk_sha256: opts.apkSha256 ?? null,
    scanned: { files: files.length, bytes: totalBytes, truncated },
    call_sites: callSites, component_correlation: correlation, summary, evidence,
    conclusion: "已按固定标记目录清点调用点位置并与 exported 组件关联；报告的是“是否存在某类调用点”的事实，不含 CWE 判定。",
    limitations: [
      "命中的是 API 调用点/字符串位置这一事实，不代表存在或不存在漏洞；是否构成缺陷由 Agent 走读后判定。",
      "类#方法为启发式定位，file:line 为权威锚点；反编译器个别类报错不影响整体清点。",
      "secret_material_string 仅记脱敏后样貌与 hash，明文不入库。",
    ],
  };
}

export interface DexSmaliAuditOptions {
  jadxBin?: string;
  components?: ComponentInput[];
  /** 回退：直接给一个已反编译的源码目录（跳过 jadx 执行）。 */
  sourceDir?: string;
  workDir?: string;
  timeoutMs?: number;
}

/** 真实运行：jadx 反编译 apk 到源码目录，再做事实型清点。jadx 不可用则退化为 stub。 */
export async function runDexSmaliAudit(
  apkPath: string,
  opts: DexSmaliAuditOptions = {},
): Promise<DexSmaliAuditResult> {
  const apkBytes = await readFile(apkPath).catch(() => null);
  const apkSha = apkBytes ? sha256Hex(apkBytes) : null;
  const jadx = opts.jadxBin ?? "jadx";

  let sourceDir = opts.sourceDir ?? null;
  let toolRun: ToolRunResult | undefined;
  let available = false;
  let stub = false;
  let cleanup: string | null = null;

  if (sourceDir === null) {
    available = await toolAvailable(jadx);
    if (available) {
      const base = opts.workDir ?? (await mkdtemp(path.join(tmpdir(), "apk-jadx-")));
      cleanup = opts.workDir ? null : base;
      const outDir = path.join(base, "src");
      toolRun = await runTool(jadx, ["-d", outDir, "--no-res", "--no-debug-info", apkPath], { timeoutMs: opts.timeoutMs ?? 300_000 });
      sourceDir = outDir;
    }
  }

  if (sourceDir === null) {
    stub = true;
    return {
      schema_version: 1, classification: "apk_dex_smali_facts",
      tool: { name: jadx, available, stub: true },
      apk_sha256: apkSha, scanned: { files: 0, bytes: 0, truncated: false },
      call_sites: [], component_correlation: (opts.components ?? []).map((c) => ({
        component: c.name, component_type: c.type ?? null, source_file: null, entry_methods_present: [],
        has_permission_check_call_site: false, has_caller_identity_call_site: false, has_signature_read_call_site: false, call_sites: [],
      })),
      summary: { permission_check_call: 0, caller_identity_call: 0, signature_read_call: 0, native_boundary: 0, secret_material_string: 0, total: 0 },
      evidence: [],
      conclusion: "jadx 不可用或反编译失败；已按桩返回空清点，不做任何判定。",
      limitations: ["jadx 不可用，未能反编译；本结果为桩，仅保证结构与可编译性。"],
    };
  }

  const audited = await auditDecompiledSources(sourceDir, { components: opts.components, apkSha256: apkSha });
  if (cleanup) await rm(cleanup, { recursive: true, force: true }).catch(() => {});
  return {
    ...audited,
    tool: { name: jadx, available, stub, ...(toolRun ? { run: { exit_code: toolRun.exit_code, timed_out: toolRun.timed_out, duration_ms: toolRun.duration_ms } } : {}) },
  };
}
