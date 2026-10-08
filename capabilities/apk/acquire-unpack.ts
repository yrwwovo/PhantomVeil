import { readFile } from "node:fs/promises";
import path from "node:path";

import { runTool, toolAvailable, type ToolRunResult } from "./run-tool.ts";
import { parseBadging } from "./decompile-manifest.ts";
import { certFingerprint, makeLargeFileEvidence, makeSnippetEvidence, sha256Hex, type EvidenceEntry } from "./evidence.ts";

/**
 * ① 获取与脱壳 · acquire_unpack（脚手架；强加固完整处理留待后续/动态段）。
 *
 * 只输出事实：APK 整包 SHA-256、zip 条目清单、签名方案/证书指纹（apksigner）、
 * 以及按“文件存在性启发式”得到的加固指示项（以事实列出命中的文件名，不下“已被脱壳/已被加固判死”的结论）。
 */

export interface ZipEntryFact { name: string; size: number | null }

/** 加固指示项目录（固定清单）：命中=该文件名存在这一事实，不等于判定壳类型。 */
export const PACKER_INDICATOR_FILES: Array<{ id: string; pattern: RegExp; note: string }> = [
  { id: "aijiami_dexhelper", pattern: /lib\/[^/]+\/libDexHelper(-x86)?\.so$/, note: "爱加密常见特征文件" },
  { id: "aijiami_dexjni", pattern: /lib\/[^/]+\/libdexjni\.so$/, note: "爱加密常见特征文件" },
  { id: "assets_dat", pattern: /assets\/.*\.dat$/, note: "assets 下 .dat（部分壳 RC4 载荷位）" },
  { id: "bangbang_mogosec", pattern: /assets\/mogosec_/, note: "梆梆占位特征" },
  { id: "bangbang_libkiwi", pattern: /lib\/[^/]+\/libkiwi\.so$/, note: "梆梆 VMP 特征" },
  { id: "flutter_libapp", pattern: /lib\/[^/]+\/libapp\.so$/, note: "Flutter AOT 产物" },
  { id: "flutter_libflutter", pattern: /lib\/[^/]+\/libflutter\.so$/, note: "Flutter 引擎" },
];

export interface AcquireUnpackResult {
  schema_version: 1;
  classification: "apk_acquire_facts";
  apk_path: string;
  apk_sha256: string | null;
  byte_length: number | null;
  tools: {
    unzip: { available: boolean };
    aapt2: { available: boolean; run?: Pick<ToolRunResult, "exit_code" | "timed_out"> };
    apksigner: { available: boolean; stub: boolean; run?: Pick<ToolRunResult, "exit_code" | "timed_out"> };
  };
  /** aapt2 dump badging 的 package name。工具不可用或没有 name 时为 null。只是事实，不是判定。 */
  package_name: string | null;
  zip_entries: ZipEntryFact[];
  zip_entry_count: number;
  dex_entries: string[];
  so_entries: string[];
  signature: {
    schemes: { v1: boolean | null; v2: boolean | null; v3: boolean | null; v4: boolean | null };
    verified: boolean | null;
    signer_cert_fingerprints: Array<{ sha256: string; reported_fingerprint?: string }>;
    raw_available: boolean;
  };
  packer_indicators: Array<{ id: string; file: string; note: string }>;
  evidence: EvidenceEntry[];
  conclusion: string;
  limitations: string[];
}

function parseZipList(output: string): ZipEntryFact[] {
  // `unzip -l` 输出：  Length      Date    Time    Name
  const entries: ZipEntryFact[] = [];
  for (const line of output.split(/\r?\n/)) {
    const m = /^\s*(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(.+?)\s*$/.exec(line);
    if (m) entries.push({ name: m[2], size: Number(m[1]) });
  }
  return entries;
}

function parseApksigner(output: string): { schemes: AcquireUnpackResult["signature"]["schemes"]; verified: boolean | null; fps: string[] } {
  const bool = (re: RegExp): boolean | null => {
    const m = re.exec(output);
    return m ? /true/i.test(m[1]) : null;
  };
  const schemes = {
    v1: bool(/Verified using v1 scheme \(JAR signing\):\s*(\w+)/),
    v2: bool(/Verified using v2 scheme \(APK Signature Scheme v2\):\s*(\w+)/),
    v3: bool(/Verified using v3 scheme \(APK Signature Scheme v3\):\s*(\w+)/),
    v4: bool(/Verified using v4 scheme \(APK Signature Scheme v4\):\s*(\w+)/),
  };
  const verified = /^Verifies\b/m.test(output) ? true : (/DOES NOT VERIFY|ERROR/i.test(output) ? false : null);
  const fps: string[] = [];
  const fpRe = /Signer #?\d*.*certificate SHA-256 digest:\s*([0-9a-fA-F]{64})/g;
  let m: RegExpExecArray | null;
  while ((m = fpRe.exec(output)) !== null) fps.push(m[1].toLowerCase());
  return { schemes, verified, fps };
}

export interface AcquireUnpackOptions {
  unzipBin?: string;
  /** 与 decompile-manifest 相同：默认 aapt2。 */
  aapt2Bin?: string;
  apksignerBin?: string;
  timeoutMs?: number;
}

export async function runAcquireUnpack(apkPath: string, opts: AcquireUnpackOptions = {}): Promise<AcquireUnpackResult> {
  const unzip = opts.unzipBin ?? "unzip";
  const aapt2 = opts.aapt2Bin ?? "aapt2";
  const apksigner = opts.apksignerBin ?? "apksigner";
  const bytes = await readFile(apkPath).catch(() => null);
  const apkSha = bytes ? sha256Hex(bytes) : null;
  const evidence: EvidenceEntry[] = [];
  if (apkSha && bytes) {
    evidence.push(makeLargeFileEvidence({
      stage: "acquire_unpack", locator: `apk#${path.basename(apkPath)}`, fileSha256: apkSha, byteLength: bytes.length,
      metadata: `APK ${path.basename(apkPath)} ${bytes.length}B（Scope 主键 apk_sha256，大件只存 hash+元数据）`,
    }));
  }

  const unzipAvail = await toolAvailable(unzip);
  let entries: ZipEntryFact[] = [];
  if (unzipAvail && bytes) {
    const listRun = await runTool(unzip, ["-l", apkPath], { timeoutMs: opts.timeoutMs ?? 60_000 });
    entries = parseZipList(listRun.stdout);
  }
  const names = entries.map((e) => e.name);
  const dexEntries = names.filter((n) => /\.dex$/.test(n));
  const soEntries = names.filter((n) => /^lib\/.*\.so$/.test(n));

  const packer: AcquireUnpackResult["packer_indicators"] = [];
  for (const n of names) {
    for (const ind of PACKER_INDICATOR_FILES) {
      if (ind.pattern.test(n)) packer.push({ id: ind.id, file: n, note: ind.note });
    }
  }

  const aapt2Avail = bytes ? await toolAvailable(aapt2) : false;
  let packageName: string | null = null;
  let aapt2Run: ToolRunResult | undefined;
  if (aapt2Avail && bytes) {
    aapt2Run = await runTool(aapt2, ["dump", "badging", apkPath], { timeoutMs: opts.timeoutMs ?? 60_000 });
    const parsedName = parseBadging(`${aapt2Run.stdout}\n${aapt2Run.stderr}`).package_name;
    packageName = parsedName && parsedName.length > 0 ? parsedName : null;
  }

  // 签名方案 / 证书指纹（apksigner）；不可用则退化，v1 可从 META-INF 存在性旁证。
  const apksignerAvail = await toolAvailable(apksigner);
  let schemes: AcquireUnpackResult["signature"]["schemes"] = { v1: null, v2: null, v3: null, v4: null };
  let verified: boolean | null = null;
  let fps: string[] = [];
  let apksignerRun: ToolRunResult | undefined;
  if (apksignerAvail && bytes) {
    apksignerRun = await runTool(apksigner, ["verify", "--verbose", "--print-certs", apkPath], { timeoutMs: opts.timeoutMs ?? 60_000 });
    const out = `${apksignerRun.stdout}\n${apksignerRun.stderr}`;
    const parsed = parseApksigner(out);
    schemes = parsed.schemes; verified = parsed.verified; fps = parsed.fps;
    if (out.trim()) {
      evidence.push(makeSnippetEvidence({
        stage: "acquire_unpack", locator: `apk#${path.basename(apkPath)}:apksigner`, raw: out.slice(0, 4000), sourceFileSha256: apkSha,
      }));
    }
  } else {
    // 旁证：仅凭 META-INF/*.RSA|DSA|EC 存在性标 v1 scheme 的“迹象”（事实），v2/v3 需 apksigner。
    schemes = { v1: names.some((n) => /^META-INF\/.*\.(RSA|DSA|EC)$/i.test(n)) ? true : null, v2: null, v3: null, v4: null };
  }
  const certFps = fps.map((fp) => certFingerprint({ reported_sha256: fp }));

  const stub = !apksignerAvail;
  return {
    schema_version: 1, classification: "apk_acquire_facts",
    apk_path: path.basename(apkPath), apk_sha256: apkSha, byte_length: bytes ? bytes.length : null,
    tools: {
      unzip: { available: unzipAvail },
      aapt2: { available: aapt2Avail, ...(aapt2Run ? { run: { exit_code: aapt2Run.exit_code, timed_out: aapt2Run.timed_out } } : {}) },
      apksigner: { available: apksignerAvail, stub, ...(apksignerRun ? { run: { exit_code: apksignerRun.exit_code, timed_out: apksignerRun.timed_out } } : {}) },
    },
    package_name: packageName,
    zip_entries: entries.slice(0, 2000), zip_entry_count: entries.length,
    dex_entries: dexEntries, so_entries: soEntries,
    signature: {
      schemes, verified,
      signer_cert_fingerprints: certFps.map((c) => ({ sha256: c.sha256, ...(c.reported_fingerprint ? { reported_fingerprint: c.reported_fingerprint } : {}) })),
      raw_available: false,
    },
    packer_indicators: packer, evidence,
    conclusion: stub
      ? "已算 APK SHA-256 并列出 zip 条目与加固指示项事实；apksigner 不可用，签名方案仅给 META-INF 旁证，证书指纹缺省。"
      : "已算 APK SHA-256（Scope 主键），列出 zip 条目、签名方案与证书指纹、加固指示项，均为事实，不含判定。",
    limitations: [
      "packer_indicators 只陈述“命中了哪些特征文件名”的事实，不等于判定壳厂商或声称已脱壳。",
      "强加固（强 VMP / 串加密 / Dart AOT）静态读不动时应由上层标 blocked + 低置信画像；运行时脱壳归动态段，本期不做。",
      "证书只留 SHA-256 指纹，不存整证书；签名真伪与可伪造性属动态复现。",
    ],
  };
}
