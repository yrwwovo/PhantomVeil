import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { runTool, toolAvailable, type ToolRunResult } from "./run-tool.ts";
import { makeSnippetEvidence, sha256Hex, type EvidenceEntry } from "./evidence.ts";

/**
 * ② 反编译与清单分析 · decompile_manifest（STAGE ②，真实运行）。
 *
 * 只输出结构化“事实”：组件清单（exported / permission / protectionLevel / intent-filter）、
 * 全局开关（debuggable / allowBackup / minSdk / targetSdk）、声明权限矩阵。
 * 不打任何 CWE 标签、不做 if-else 判定——判定交给 Agent。
 */

export type ComponentType = "activity" | "service" | "receiver" | "provider";

export interface IntentFilter {
  actions: string[];
  categories: string[];
  data_schemes: string[];
}

export interface ManifestComponent {
  type: ComponentType;
  name: string;
  /** android:exported 的显式取值；未声明为 null（由 Agent 结合 intent-filter 自行推断默认导出）。 */
  exported_attr: boolean | null;
  /** 是否带 intent-filter（隐式导出的事实依据，仅陈述事实）。 */
  has_intent_filter: boolean;
  /** android:permission（组件级权限守卫），未声明为 null。 */
  permission: string | null;
  /** provider 专属，未声明为 null。 */
  read_permission: string | null;
  write_permission: string | null;
  grant_uri_permissions: boolean | null;
  /** provider authorities。 */
  authorities: string | null;
  enabled_attr: boolean | null;
  intent_filters: IntentFilter[];
}

export interface DeclaredPermission {
  name: string;
  protection_level: string | null;
}

export interface ManifestFacts {
  package_name: string | null;
  version_name: string | null;
  version_code: string | null;
  min_sdk: string | null;
  target_sdk: string | null;
  compile_sdk: string | null;
  debuggable: boolean | null;
  allow_backup: boolean | null;
  uses_permissions: string[];
  declared_permissions: DeclaredPermission[];
  components: ManifestComponent[];
}

export interface DecompileManifestResult {
  schema_version: 1;
  classification: "apk_manifest_facts";
  tool: { name: string; available: boolean; run?: Pick<ToolRunResult, "exit_code" | "timed_out" | "duration_ms">; stub: boolean };
  apk_sha256: string | null;
  manifest_sha256: string | null;
  facts: ManifestFacts;
  summary: {
    components: number;
    exported_true: number;
    with_intent_filter: number;
    components_without_permission: number;
    uses_permissions: number;
    declared_permissions: number;
  };
  evidence: EvidenceEntry[];
  conclusion: string;
  limitations: string[];
}

interface Tag {
  name: string;
  attrs: Record<string, string>;
  selfClosing: boolean;
  closing: boolean;
}

const ANDROID = "android:";

function attrBool(value: string | undefined): boolean | null {
  if (value === undefined) return null;
  return value === "true";
}

/** 极简 XML 标签扫描器：apktool 解出的 AndroidManifest.xml 为规范 XML，足够用。 */
function scanTags(xml: string): Tag[] {
  const tags: Tag[] = [];
  const re = /<(\/?)([A-Za-z0-9_.:-]+)((?:\s+[^<>]*?)?)(\/?)>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    const closing = m[1] === "/";
    const name = m[2];
    const rawAttrs = m[3] ?? "";
    const selfClosing = m[4] === "/";
    const attrs: Record<string, string> = {};
    const attrRe = /([A-Za-z0-9_.:-]+)\s*=\s*"([^"]*)"/g;
    let a: RegExpExecArray | null;
    while ((a = attrRe.exec(rawAttrs)) !== null) attrs[a[1]] = a[2];
    tags.push({ name, attrs, selfClosing, closing });
  }
  return tags;
}

/** 纯解析：把 AndroidManifest.xml 文本转成结构化事实（无判定）。 */
export function parseManifestFacts(xml: string): ManifestFacts {
  const tags = scanTags(xml);
  const facts: ManifestFacts = {
    package_name: null, version_name: null, version_code: null,
    min_sdk: null, target_sdk: null, compile_sdk: null,
    debuggable: null, allow_backup: null,
    uses_permissions: [], declared_permissions: [], components: [],
  };
  const componentTypes = new Set<ComponentType>(["activity", "service", "receiver", "provider"]);
  let current: ManifestComponent | null = null;
  let currentFilter: IntentFilter | null = null;

  for (const tag of tags) {
    const base = tag.name.replace(/^.*:/, ""); // activity-alias -> activity-alias
    if (tag.name === "manifest" && !tag.closing) {
      facts.package_name = tag.attrs["package"] ?? facts.package_name;
      facts.version_name = tag.attrs[`${ANDROID}versionName`] ?? facts.version_name;
      facts.version_code = tag.attrs[`${ANDROID}versionCode`] ?? facts.version_code;
      facts.compile_sdk = tag.attrs[`${ANDROID}compileSdkVersion`] ?? facts.compile_sdk;
    } else if (tag.name === "uses-sdk" && !tag.closing) {
      facts.min_sdk = tag.attrs[`${ANDROID}minSdkVersion`] ?? facts.min_sdk;
      facts.target_sdk = tag.attrs[`${ANDROID}targetSdkVersion`] ?? facts.target_sdk;
    } else if (tag.name === "uses-permission" || tag.name === "uses-permission-sdk-23") {
      const n = tag.attrs[`${ANDROID}name`];
      if (n) facts.uses_permissions.push(n);
    } else if (tag.name === "permission" && !tag.closing) {
      const n = tag.attrs[`${ANDROID}name`];
      if (n) facts.declared_permissions.push({ name: n, protection_level: tag.attrs[`${ANDROID}protectionLevel`] ?? null });
    } else if (tag.name === "application" && !tag.closing) {
      facts.debuggable = attrBool(tag.attrs[`${ANDROID}debuggable`]);
      facts.allow_backup = attrBool(tag.attrs[`${ANDROID}allowBackup`]);
    } else if (componentTypes.has(base as ComponentType) && !tag.closing) {
      current = {
        type: base as ComponentType,
        name: tag.attrs[`${ANDROID}name`] ?? "",
        exported_attr: attrBool(tag.attrs[`${ANDROID}exported`]),
        has_intent_filter: false,
        permission: tag.attrs[`${ANDROID}permission`] ?? null,
        read_permission: tag.attrs[`${ANDROID}readPermission`] ?? null,
        write_permission: tag.attrs[`${ANDROID}writePermission`] ?? null,
        grant_uri_permissions: attrBool(tag.attrs[`${ANDROID}grantUriPermissions`]),
        authorities: tag.attrs[`${ANDROID}authorities`] ?? null,
        enabled_attr: attrBool(tag.attrs[`${ANDROID}enabled`]),
        intent_filters: [],
      };
      facts.components.push(current);
      if (tag.selfClosing) current = null;
    } else if (componentTypes.has(base as ComponentType) && tag.closing) {
      current = null;
    } else if (tag.name === "intent-filter" && !tag.closing && current) {
      currentFilter = { actions: [], categories: [], data_schemes: [] };
      current.has_intent_filter = true;
      current.intent_filters.push(currentFilter);
      if (tag.selfClosing) currentFilter = null;
    } else if (tag.name === "intent-filter" && tag.closing) {
      currentFilter = null;
    } else if (tag.name === "action" && currentFilter) {
      const n = tag.attrs[`${ANDROID}name`];
      if (n) currentFilter.actions.push(n);
    } else if (tag.name === "category" && currentFilter) {
      const n = tag.attrs[`${ANDROID}name`];
      if (n) currentFilter.categories.push(n);
    } else if (tag.name === "data" && currentFilter) {
      const s = tag.attrs[`${ANDROID}scheme`];
      if (s) currentFilter.data_schemes.push(s);
    }
  }
  return facts;
}

function summarize(facts: ManifestFacts): DecompileManifestResult["summary"] {
  const exportedTrue = facts.components.filter((c) => c.exported_attr === true).length;
  const withFilter = facts.components.filter((c) => c.has_intent_filter).length;
  const noPerm = facts.components.filter((c) => c.permission === null && c.read_permission === null && c.write_permission === null).length;
  return {
    components: facts.components.length,
    exported_true: exportedTrue,
    with_intent_filter: withFilter,
    components_without_permission: noPerm,
    uses_permissions: facts.uses_permissions.length,
    declared_permissions: facts.declared_permissions.length,
  };
}

/** aapt2 dump badging 的标量事实（apktool 会把 sdk/version 挪进 apktool.yml，这里补齐）。 */
export function parseBadging(output: string): Partial<Pick<ManifestFacts,
  "package_name" | "version_name" | "version_code" | "min_sdk" | "target_sdk" | "compile_sdk" | "debuggable">> {
  const pkg = /^package:\s+(.*)$/m.exec(output)?.[1] ?? "";
  const field = (src: string, key: string): string | null => new RegExp(`${key}='([^']*)'`).exec(src)?.[1] ?? null;
  return {
    package_name: field(pkg, "name"),
    version_code: field(pkg, "versionCode"),
    version_name: field(pkg, "versionName"),
    compile_sdk: field(pkg, "compileSdkVersion"),
    min_sdk: /^(?:min)?[sS]dkVersion:'([^']*)'/m.exec(output)?.[1] ?? null,
    target_sdk: /^targetSdkVersion:'([^']*)'/m.exec(output)?.[1] ?? null,
    debuggable: /^application-debuggable/m.test(output) ? true : null,
  };
}

const LIMITATIONS = [
  "本结果只陈列 manifest 中观察到的组件与属性事实，不代表存在漏洞，也不输出 CWE 判定。",
  "exported 默认值（带 intent-filter 时默认导出）由上层 Agent 结合 targetSdk 自行推断，这里只给出显式属性。",
  "是否真正缺少鉴权需结合 ③ dex/smali 入口走读，本阶段不涉及代码逻辑。",
];

export interface DecompileManifestOptions {
  /** 覆盖 apktool 可执行名/路径。 */
  apktoolBin?: string;
  /** 覆盖 aapt2 可执行名/路径（用于 dump badging 补齐 sdk/version 标量事实）。 */
  aapt2Bin?: string;
  /** 回退：直接给一份已解出的 AndroidManifest.xml 文本（跳过工具执行）。 */
  manifestXml?: string;
  workDir?: string;
  timeoutMs?: number;
}

/**
 * 真实运行：apktool 解包取 AndroidManifest.xml 并解析成事实。
 * apktool 不可用则退化为 stub（仍返回结构，可编译），由上层记录“已安装 vs 桩”。
 */
export async function runDecompileManifest(
  apkPath: string,
  opts: DecompileManifestOptions = {},
): Promise<DecompileManifestResult> {
  const apkBytes = await readFile(apkPath).catch(() => null);
  const apkSha = apkBytes ? sha256Hex(apkBytes) : null;

  let manifestXml = opts.manifestXml ?? null;
  let toolRun: ToolRunResult | undefined;
  let available = false;
  let stub = false;
  const apktool = opts.apktoolBin ?? "apktool";

  if (manifestXml === null) {
    available = await toolAvailable(apktool);
    if (available) {
      const base = opts.workDir ?? (await mkdtemp(path.join(tmpdir(), "apk-manifest-")));
      const outDir = path.join(base, "out");
      toolRun = await runTool(apktool, ["d", "-f", "-s", "-o", outDir, apkPath], { timeoutMs: opts.timeoutMs ?? 180_000 });
      manifestXml = await readFile(path.join(outDir, "AndroidManifest.xml"), "utf8").catch(() => null);
      if (!opts.workDir) await rm(base, { recursive: true, force: true }).catch(() => {});
    }
    if (manifestXml === null) stub = true;
  }

  if (manifestXml === null) {
    return {
      schema_version: 1, classification: "apk_manifest_facts",
      tool: { name: apktool, available, stub: true, ...(toolRun ? { run: { exit_code: toolRun.exit_code, timed_out: toolRun.timed_out, duration_ms: toolRun.duration_ms } } : {}) },
      apk_sha256: apkSha, manifest_sha256: null,
      facts: { package_name: null, version_name: null, version_code: null, min_sdk: null, target_sdk: null, compile_sdk: null, debuggable: null, allow_backup: null, uses_permissions: [], declared_permissions: [], components: [] },
      summary: { components: 0, exported_true: 0, with_intent_filter: 0, components_without_permission: 0, uses_permissions: 0, declared_permissions: 0 },
      evidence: [],
      conclusion: "未能取得 AndroidManifest.xml（apktool 不可用或解包失败）；已按桩返回空事实集，不做任何判定。",
      limitations: LIMITATIONS,
    };
  }

  const facts = parseManifestFacts(manifestXml);
  // 补齐：apktool 解出的 manifest 不含 sdk/version，用 aapt2 dump badging 填空（只填 null 字段）。
  const aapt2 = opts.aapt2Bin ?? "aapt2";
  let badgingUsed = false;
  if (apkBytes && (await toolAvailable(aapt2))) {
    const badging = await runTool(aapt2, ["dump", "badging", apkPath], { timeoutMs: 60_000 });
    if (badging.ok) {
      const b = parseBadging(badging.stdout);
      for (const key of Object.keys(b) as Array<keyof typeof b>) {
        const v = b[key];
        if (v !== null && v !== undefined && (facts as unknown as Record<string, unknown>)[key] === null) {
          (facts as unknown as Record<string, unknown>)[key] = v;
          badgingUsed = true;
        }
      }
    }
  }
  const manifestSha = sha256Hex(Buffer.from(manifestXml, "utf8"));
  const evidence: EvidenceEntry[] = [];
  // 规范化 manifest 整体入证据（大文件会在工具内自动退化为 hash_only）。
  evidence.push(makeSnippetEvidence({
    stage: "decompile_manifest", locator: "manifest#normalized", raw: manifestXml, sourceFileSha256: apkSha,
  }));
  // 每个组件一条定位证据（只记事实片段）。
  for (const c of facts.components) {
    const snippet = JSON.stringify({
      type: c.type, name: c.name, exported_attr: c.exported_attr, has_intent_filter: c.has_intent_filter,
      permission: c.permission, read_permission: c.read_permission, write_permission: c.write_permission,
      grant_uri_permissions: c.grant_uri_permissions, authorities: c.authorities,
    });
    evidence.push(makeSnippetEvidence({
      stage: "decompile_manifest", locator: `manifest#${c.type}:${c.name}`, raw: snippet, sourceFileSha256: apkSha,
    }));
  }

  return {
    schema_version: 1, classification: "apk_manifest_facts",
    tool: { name: apktool, available, stub, ...(toolRun ? { run: { exit_code: toolRun.exit_code, timed_out: toolRun.timed_out, duration_ms: toolRun.duration_ms } } : {}) },
    apk_sha256: apkSha, manifest_sha256: manifestSha,
    facts, summary: summarize(facts), evidence,
    conclusion: `已枚举 manifest 组件与全局开关等事实（含 exported/permission/intent-filter）${badgingUsed ? "，sdk/version 标量由 aapt2 dump badging 补齐" : ""}，不含任何漏洞判定。`,
    limitations: LIMITATIONS,
  };
}
