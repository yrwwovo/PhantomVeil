import { realpathSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { runAcquireUnpack } from "../../../capabilities/apk/acquire-unpack.ts";
import { sha256Hex } from "../../../capabilities/apk/evidence.ts";
import { runApkAcquireUnpack, type ApkAcquireUnpackResult } from "../../workflows/apk/acquire-unpack.ts";
import { runApkDecompileManifest, type ApkDecompileManifestResult } from "../../workflows/apk/decompile-manifest.ts";
import { runApkDexSmaliAudit, type ApkDexSmaliAuditResult } from "../../workflows/apk/dex-smali-audit.ts";
import { runApkSoStaticAudit, type ApkSoStaticAuditResult } from "../../workflows/apk/so-static-audit.ts";
import { resolveSessionSoPath, type ApkScope } from "../../workflows/apk/scope.ts";

/**
 * ApkTaskService —— Hermes MCP 白名单 apk 工具背后的服务方法（PhantomVeil 侧）。
 *
 * 构造时不带路径，四个工具仍可注册。会话开始时由 bindSession 注入
 * 工作目录内的 APK，而不是从工具参数收任意机器路径。
 * 只做静态只读分析：四段流水线各一个方法，内部调对应 workflow，返回结构化事实。
 * 不产生 CWE 判定；cwe/locator/confidence 的推理归 Agent，回写组装归 apk-writeback。
 * 动态 verifier（apk.exported_component_poc / apk.signature_bypass）本期只预留命名，不实现。
 */

/** §8 决策 10 预留的 APK 动态 verifier 命名空间（本期只登记，不实现）。 */
export const RESERVED_APK_VERIFIER_KINDS = [
  "apk.exported_component_poc", // CWE-862/306：将来 adb 显式 intent 调起未鉴权组件拿回执
  "apk.signature_bypass",       // CWE-347：重签名/篡改 APK 通过校验
  "apk.unidbg_repro",           // so 取串/算法闭环
  "apk.frida_runtime",          // 运行时 hook
] as const;

export interface ApkServiceResponse<T> {
  ok: boolean;
  code: string;
  reason: string;
  result?: T;
}

/** 会话注入。路径必须落在 workRoot 内；不从 MCP 工具参数接收。 */
export interface ApkBindRequest {
  apkPath: string;
  workRoot: string;
  package_name?: string | null;
  signing_cert_sha256?: string | null;
  apk_sha256?: string | null;
}

function notBound(): ApkServiceResponse<never> {
  return { ok: false, code: "NOT_BOUND", reason: "APK 会话尚未绑定；路径只从会话工作目录注入" };
}

function normSha(value: string): string {
  return value.replace(/[^a-fA-F0-9]/g, "").toLowerCase();
}

export class ApkTaskService {
  private apkPath: string | null = null;
  private scope: ApkScope | undefined;
  private workRoot: string | undefined;

  /** 未绑定。不接收占位路径。 */
  constructor() {}

  private unbound(): ApkServiceResponse<never> | null {
    if (!this.apkPath || !this.workRoot || !this.scope?.apk_sha256) return notBound();
    return null;
  }

  /**
   * 绑定当前会话的 APK。先做路径门（绝对路径、.apk、无 ..、realpath 落在 workRoot 内的普通文件），
   * 通过后才读文件并用既有 sha256Hex 计算主键。失败不改已有绑定状态；首次失败保持未绑定。
   */
  async bindSession(input: ApkBindRequest): Promise<ApkServiceResponse<{ apk_sha256: string; apk_path: string; work_root: string; package_name?: string; signing_cert_sha256?: string }>> {
    const gate = gateApkPath(input.apkPath, input.workRoot);
    if (!gate.ok) return gate;
    let bytes: Buffer;
    try {
      bytes = await readFile(gate.resolved);
    } catch {
      return { ok: false, code: "APK_NOT_FOUND", reason: "APK 路径通过约束后仍无法读取" };
    }
    const actual = sha256Hex(bytes);
    const supplied = typeof input.apk_sha256 === "string" ? normSha(input.apk_sha256) : "";
    if (supplied && (supplied.length !== 64 || supplied !== actual)) {
      return { ok: false, code: "APK_SHA256_MISMATCH", reason: "提供的 apk_sha256 与文件内容不一致，会话保持未绑定" };
    }
    const certSupplied = typeof input.signing_cert_sha256 === "string";
    const packageSupplied = typeof input.package_name === "string";
    const suppliedCert = certSupplied ? normSha(input.signing_cert_sha256 as string) : "";
    let matchedCert: string | undefined;
    let matchedPackage: string | undefined;
    if (certSupplied || packageSupplied) {
      const facts = await runAcquireUnpack(gate.resolved);
      if (certSupplied) {
        const fingerprints = facts.signature.signer_cert_fingerprints
          .map((item) => normSha(item.sha256))
          .filter((item) => item.length === 64);
        if (fingerprints.length === 0) {
          return { ok: false, code: "NOT_BOUND", reason: "signing_cert_sha256 已提供，但证书指纹提取结果为空，会话保持未绑定" };
        }
        if (!fingerprints.includes(suppliedCert)) {
          return { ok: false, code: "NOT_BOUND", reason: "signing_cert_sha256 与提取到的证书指纹不一致，会话保持未绑定" };
        }
        matchedCert = suppliedCert;
      }
      if (packageSupplied) {
        const observed = typeof facts.package_name === "string" ? facts.package_name.trim() : "";
        if (!observed) {
          return { ok: false, code: "NOT_BOUND", reason: "package_name 已提供，但 aapt 包名提取结果为空，会话保持未绑定" };
        }
        if (observed !== input.package_name) {
          return { ok: false, code: "NOT_BOUND", reason: "package_name 与 aapt 提取的包名不一致，会话保持未绑定" };
        }
        matchedPackage = observed;
      }
    }
    const scope: ApkScope = { apk_sha256: actual };
    if (matchedPackage !== undefined) scope.package_name = matchedPackage;
    if (matchedCert !== undefined) scope.signing_cert_sha256 = matchedCert;
    this.apkPath = gate.resolved;
    this.workRoot = gate.workRoot;
    this.scope = scope;
    return {
      ok: true, code: "APK_BOUND", reason: "APK 已绑定到当前会话工作目录",
      result: {
        apk_sha256: actual, apk_path: gate.resolved, work_root: gate.workRoot,
        ...(matchedPackage !== undefined ? { package_name: matchedPackage } : {}),
        ...(matchedCert !== undefined ? { signing_cert_sha256: matchedCert } : {}),
      },
    };
  }

  /** ① 获取与脱壳：算 SHA-256、列条目、取签名/证书、加固指示项。 */
  async acquireUnpack(): Promise<ApkServiceResponse<ApkAcquireUnpackResult>> {
    const bad = this.unbound(); if (bad) return bad;
    const result = await runApkAcquireUnpack(this.apkPath as string, { ...(this.scope ? { scope: this.scope } : {}) });
    return { ok: result.ok, code: result.code, reason: result.reason, result };
  }

  /** ② 反编译与清单分析：枚举组件/权限/全局开关事实 + 候选定位。 */
  async decompileManifest(): Promise<ApkServiceResponse<ApkDecompileManifestResult>> {
    const bad = this.unbound(); if (bad) return bad;
    const result = await runApkDecompileManifest(this.apkPath as string, { ...(this.scope ? { scope: this.scope } : {}) });
    return { ok: result.ok, code: result.code, reason: result.reason, result };
  }

  /** ③ dex/smali 审计：清点调用点并与 exported 组件关联（可传入组件清单做关联）。 */
  async dexSmaliAudit(input: { components?: Array<{ name: string; type?: string | null }> } = {}): Promise<ApkServiceResponse<ApkDexSmaliAuditResult>> {
    const bad = this.unbound(); if (bad) return bad;
    const result = await runApkDexSmaliAudit(this.apkPath as string, {
      ...(this.scope ? { scope: this.scope } : {}),
      ...(input.components ? { components: input.components } : {}),
    });
    return { ok: result.ok, code: result.code, reason: result.reason, result };
  }

  /** ④ so 静态分析：只打开本会话 workRoot/lib/<abi>/*.so。未绑定不打开任何文件。 */
  async soStaticAudit(input: { soPath: string }): Promise<ApkServiceResponse<ApkSoStaticAuditResult>> {
    const bad = this.unbound(); if (bad) return bad;
    const session = { workRoot: this.workRoot as string, apk_sha256: this.scope?.apk_sha256 as string };
    const gate = resolveSessionSoPath(input?.soPath, session);
    if (!gate.ok) {
      return { ok: false, code: gate.code, reason: gate.reason };
    }
    const result = await runApkSoStaticAudit(gate.resolved, {
      ...(this.scope ? { scope: this.scope } : {}),
      ...(this.workRoot ? { workRoot: this.workRoot } : {}),
    });
    return { ok: result.ok, code: result.code, reason: result.reason, result };
  }
}

type ApkGate =
  | { ok: true; resolved: string; workRoot: string }
  | ApkServiceResponse<never>;

function gateApkPath(apkPath: string, workRoot: string): ApkGate {
  if (typeof apkPath !== "string" || !path.isAbsolute(apkPath)) {
    return { ok: false, code: "APK_PATH_RELATIVE", reason: "APK 路径必须是绝对路径" };
  }
  if (!apkPath.endsWith(".apk")) {
    return { ok: false, code: "APK_PATH_NOT_APK", reason: "APK 路径必须以 .apk 结尾" };
  }
  if (apkPath.split(/[\\/]/).includes("..")) {
    return { ok: false, code: "APK_PATH_ESCAPE", reason: "APK 路径含 ..，拒绝离开会话工作目录" };
  }
  if (typeof workRoot !== "string" || !path.isAbsolute(workRoot) || workRoot.split(/[\\/]/).includes("..")) {
    return { ok: false, code: "APK_WORK_ROOT_INVALID", reason: "会话工作目录必须是不含 .. 的绝对路径" };
  }
  let rootReal: string;
  try {
    rootReal = realpathSync(workRoot);
  } catch {
    return { ok: false, code: "APK_WORK_ROOT_INVALID", reason: "会话工作目录不存在或无法解析" };
  }
  let fileReal: string;
  try {
    fileReal = realpathSync(apkPath);
  } catch {
    return { ok: false, code: "APK_NOT_FOUND", reason: "APK 路径不存在或无法解析" };
  }
  const rel = path.relative(rootReal, fileReal);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
    return { ok: false, code: "APK_OUTSIDE_SESSION", reason: "APK 的真实路径不在当前会话工作目录内" };
  }
  try {
    if (!statSync(fileReal).isFile()) {
      return { ok: false, code: "APK_NOT_REGULAR", reason: "APK 路径必须是普通文件" };
    }
  } catch {
    return { ok: false, code: "APK_NOT_FOUND", reason: "APK 路径无法读取文件信息" };
  }
  return { ok: true, resolved: fileReal, workRoot: rootReal };
}
