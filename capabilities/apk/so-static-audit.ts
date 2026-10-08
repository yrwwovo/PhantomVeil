import { readFile } from "node:fs/promises";
import path from "node:path";

import { resolveSessionSoPath, type SoSessionBinding } from "./so-path.ts";
import { runTool, toolAvailable, type ToolRunResult } from "./run-tool.ts";
import { makeLargeFileEvidence, makeSnippetEvidence, redactSnippet, sha256Hex, type EvidenceEntry } from "./evidence.ts";

/**
 * ④ so 静态分析 · so_static_audit（脚手架，box 工具可达范围内真跑）。
 *
 * readelf / strings 为主（binutils，box 自带），rizin / LIEF 为可选增强。
 * 只输出事实：架构、动态导出符号（JNI Java_* 与导出函数）、导入符号、NEEDED 依赖、
 * 与签名/密钥相关的字符串命中（脱敏）。不输出 CWE 判定。
 * IDA-headless / Blutter 属受限 capability，归用户电脑段，本阶段不在 box 调起。
 */

export interface SoSymbol { name: string; bind: string | null; type: string | null; is_jni: boolean }

export interface SoStaticAuditResult {
  schema_version: 1;
  classification: "apk_so_facts";
  so_file: string;
  so_sha256: string | null;
  byte_length: number | null;
  arch: string | null;
  elf_class: string | null;
  tools: {
    readelf: { available: boolean; run?: Pick<ToolRunResult, "exit_code" | "timed_out"> };
    strings: { available: boolean };
    rizin: { available: boolean; stub: boolean };
    lief: { available: boolean; stub: boolean };
  };
  needed_libraries: string[];
  dynamic_exports: SoSymbol[];
  jni_exports: SoSymbol[];
  imported_symbols: string[];
  interesting_strings: Array<{ category: string; redacted: string; evidence_id: string }>;
  summary: { dynamic_exports: number; jni_exports: number; imported_symbols: number; needed: number; interesting_strings: number };
  evidence: EvidenceEntry[];
  conclusion: string;
  limitations: string[];
}

/** 与签名/鉴权/密钥材料相关的固定字符串标记（中性类别，不是判定）。 */
const STRING_MARKERS: Array<{ category: string; pattern: RegExp }> = [
  { category: "crypto_hint", pattern: /\b(aes|sm4|des|rsa|hmac|md5|sha1|sha256|cipher|salt|iv|key)\b/i },
  { category: "signature_hint", pattern: /\b(sign|signature|cert|pin|verify|fingerprint|signingInfo)\b/i },
  { category: "pem_block", pattern: /BEGIN [A-Z ]*(PRIVATE|PUBLIC) KEY|BEGIN CERTIFICATE/ },
  { category: "anti_analysis_hint", pattern: /\b(ptrace|frida|xposed|anti|debugger)\b/i },
  { category: "endpoint_hint", pattern: /https?:\/\/[^\s"']{4,}/ },
  { category: "jni_register", pattern: /RegisterNatives|JNI_OnLoad/ },
];

function parseReadelfDynSyms(output: string): SoSymbol[] {
  const syms: SoSymbol[] = [];
  for (const line of output.split(/\r?\n/)) {
    // Num:    Value  Size Type    Bind   Vis      Ndx Name
    const m = /^\s*\d+:\s+[0-9a-f]+\s+\d+\s+(\w+)\s+(\w+)\s+\w+\s+(\w+)\s+(.+?)\s*$/i.exec(line);
    if (!m) continue;
    const type = m[1]; const bind = m[2]; const ndx = m[3]; const name = m[4];
    if (!name || name === "Name") continue;
    const defined = ndx !== "UND";
    const sym: SoSymbol = { name, bind, type, is_jni: name.startsWith("Java_") };
    if (defined) syms.push(sym);
  }
  return syms;
}

function parseReadelfImports(output: string): string[] {
  const imports: string[] = [];
  for (const line of output.split(/\r?\n/)) {
    const m = /^\s*\d+:\s+[0-9a-f]+\s+\d+\s+(\w+)\s+(\w+)\s+\w+\s+UND\s+(.+?)\s*$/i.exec(line);
    if (m && m[3] && m[3] !== "Name") imports.push(m[3]);
  }
  return imports;
}

function parseNeeded(output: string): string[] {
  const needed: string[] = [];
  for (const line of output.split(/\r?\n/)) {
    const m = /\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]/.exec(line);
    if (m) needed.push(m[1]);
  }
  return needed;
}

function parseArch(headerOut: string): { arch: string | null; cls: string | null } {
  const arch = /Machine:\s+(.+)/.exec(headerOut)?.[1]?.trim() ?? null;
  const cls = /Class:\s+(ELF\d+)/.exec(headerOut)?.[1]?.trim() ?? null;
  return { arch, cls };
}

export interface SoStaticAuditOptions {
  readelfBin?: string;
  stringsBin?: string;
  rizinBin?: string;
  liefPython?: string; // venv python with lief
  maxStrings?: number;
  /** 当前 APK 会话。缺省时不打开任何文件。 */
  session?: SoSessionBinding;
}

function rejectedSoResult(soPath: string, reason: string): SoStaticAuditResult {
  return {
    schema_version: 1,
    classification: "apk_so_facts",
    so_file: path.basename(soPath || "so"),
    so_sha256: null,
    byte_length: null,
    arch: null,
    elf_class: null,
    tools: {
      readelf: { available: false },
      strings: { available: false },
      rizin: { available: false, stub: true },
      lief: { available: false, stub: true },
    },
    needed_libraries: [],
    dynamic_exports: [],
    jni_exports: [],
    imported_symbols: [],
    interesting_strings: [],
    summary: { dynamic_exports: 0, jni_exports: 0, imported_symbols: 0, needed: 0, interesting_strings: 0 },
    evidence: [],
    conclusion: reason,
    limitations: [reason],
  };
}

export async function runSoStaticAudit(soPath: string, opts: SoStaticAuditOptions = {}): Promise<SoStaticAuditResult> {
  // 打开文件前先把路径收进本会话的 workRoot/lib/<abi>/。未绑定会话则不读。
  const gate = resolveSessionSoPath(soPath, opts.session);
  if (!gate.ok) return rejectedSoResult(soPath, gate.reason);
  const opened = gate.resolved;
  const readelf = opts.readelfBin ?? "readelf";
  const stringsBin = opts.stringsBin ?? "strings";
  const rizin = opts.rizinBin ?? "rz-bin";
  const liefPy = opts.liefPython ?? "python3";

  const bytes = await readFile(opened).catch(() => null);
  const soSha = bytes ? sha256Hex(bytes) : null;
  const evidence: EvidenceEntry[] = [];
  if (soSha && bytes) {
    evidence.push(makeLargeFileEvidence({
      stage: "so_static_audit", locator: `so#${path.basename(opened)}`, fileSha256: soSha, byteLength: bytes.length,
      metadata: `so file ${path.basename(opened)} ${bytes.length}B（大件只存 hash+元数据）`,
    }));
  }

  const readelfAvail = await toolAvailable(readelf);
  const stringsAvail = await toolAvailable(stringsBin);
  const rizinAvail = await toolAvailable(rizin);

  let arch: string | null = null; let cls: string | null = null;
  let dynExports: SoSymbol[] = []; let imports: string[] = []; let needed: string[] = [];
  let headerRun: ToolRunResult | undefined;

  if (readelfAvail && bytes) {
    headerRun = await runTool(readelf, ["-h", opened], { timeoutMs: 30_000 });
    ({ arch, cls } = parseArch(headerRun.stdout));
    const dynRun = await runTool(readelf, ["-W", "--dyn-syms", opened], { timeoutMs: 60_000 });
    dynExports = parseReadelfDynSyms(dynRun.stdout);
    imports = parseReadelfImports(dynRun.stdout);
    const dRun = await runTool(readelf, ["-d", opened], { timeoutMs: 30_000 });
    needed = parseNeeded(dRun.stdout);
  }

  // lief 可选增强：仅在 readelf 不可用或需交叉核验时使用（本阶段作为探测记录）。
  let liefAvail = false;
  {
    const probe = await runTool(liefPy, ["-c", "import lief"], { timeoutMs: 15_000 });
    liefAvail = probe.ok;
  }

  const interesting: SoStaticAuditResult["interesting_strings"] = [];
  if (stringsAvail && bytes) {
    const strRun = await runTool(stringsBin, ["-a", "-n", "6", opened], { timeoutMs: 60_000 });
    const seen = new Set<string>();
    const max = opts.maxStrings ?? 300;
    for (const raw of strRun.stdout.split(/\r?\n/)) {
      if (interesting.length >= max) break;
      const s = raw.trim();
      if (s.length < 6 || seen.has(s)) continue;
      for (const marker of STRING_MARKERS) {
        if (marker.pattern.test(s)) {
          seen.add(s);
          const redacted = redactSnippet(s).slice(0, 300);
          const ev = makeSnippetEvidence({
            stage: "so_static_audit", locator: `so#${path.basename(opened)}:strings:${marker.category}`,
            raw: s.slice(0, 500), sourceFileSha256: soSha,
          });
          evidence.push(ev);
          interesting.push({ category: marker.category, redacted, evidence_id: ev.evidence_id });
          break;
        }
      }
    }
  }

  const jniExports = dynExports.filter((s) => s.is_jni);
  const stub = !(readelfAvail && bytes);

  return {
    schema_version: 1, classification: "apk_so_facts",
    so_file: path.basename(opened), so_sha256: soSha, byte_length: bytes ? bytes.length : null,
    arch, elf_class: cls,
    tools: {
      readelf: { available: readelfAvail, ...(headerRun ? { run: { exit_code: headerRun.exit_code, timed_out: headerRun.timed_out } } : {}) },
      strings: { available: stringsAvail },
      rizin: { available: rizinAvail, stub: !rizinAvail },
      lief: { available: liefAvail, stub: !liefAvail },
    },
    needed_libraries: needed, dynamic_exports: dynExports, jni_exports: jniExports, imported_symbols: imports,
    interesting_strings: interesting,
    summary: {
      dynamic_exports: dynExports.length, jni_exports: jniExports.length,
      imported_symbols: imports.length, needed: needed.length, interesting_strings: interesting.length,
    },
    evidence,
    conclusion: stub
      ? "readelf 不可用或 so 读取失败；已按脚手架返回结构，so 深度分析需 box 工具或用户电脑 IDA/Blutter。"
      : "已用 readelf/strings 列出 so 的架构、导出/导入符号、NEEDED 依赖与相关字符串（脱敏），均为事实，不含判定。",
    limitations: [
      "本阶段只做 box 可达的静态面（符号/字符串/依赖）；串加密、取串函数真值、OLLVM 反平坦化等需 rizin/IDA/Blutter 或动态段。",
      "字符串命中仅为材料面线索（脱敏后），不代表存在密钥硬编码或签名校验缺陷的结论。",
      "IDA-headless / Blutter 为受限 capability，归用户电脑段，本 box 阶段不调起。",
    ],
  };
}
