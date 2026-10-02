import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import path from "node:path";

import { validatePolicy, type HttpGetPolicy } from "../../capabilities/web/restricted-http-get.ts";
import { checkUrlScope, validateScopeConfig, type ScopeConfig } from "./scope-guard.ts";
import type { AuthorizationRegistry } from "./authorization-registry.ts";

export interface TargetSetupInput {
  url: string;
  include_subdomains?: boolean;
  denied_hosts?: string[];
  denied_paths?: string[];
}

export interface TargetSetupDependencies {
  approve?: (details: { target: string; include_subdomains: boolean;
    allowed_path: string; denied_hosts: string[]; denied_paths: string[];
    replaces_existing_config: boolean }) => Promise<void>;
  resolveIps?: (host: string) => Promise<string[]>;
  now?: () => Date;
}

type SetupResult =
  | { ok: true; code: "TARGET_READY"; reason: string; target: string;
      authorization_reference: string; expires_at: string; backup_directory?: string }
  | { ok: false; code: "INVALID_INPUT" | "APPROVAL_REQUIRED" | "APPROVAL_DENIED" |
      "DNS_ERROR" | "CONFIG_ERROR"; reason: string };

const CONFIG_NAMES = ["scope.local.json", "http.local.json", "authorization.local.json"] as const;

async function defaultResolveIps(host: string): Promise<string[]> {
  if (isIP(host)) return [host];
  const addresses = await lookup(host, { all: true, verbatim: true });
  return [...new Set(addresses.map(item => item.address))];
}

async function readExisting(file: string): Promise<Buffer | undefined> {
  try {
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error("目标配置不是普通文件");
    return await readFile(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

/** 中文对话入口背后的确定性目标登记；仅在用户确认后解析 DNS、更新本地配置。 */
export async function runTargetSetup(
  projectRoot: string,
  input: TargetSetupInput,
  dependencies: TargetSetupDependencies = {},
): Promise<SetupResult> {
  let target: URL;
  try {
    if (!input || typeof input.url !== "string" ||
        (input.include_subdomains !== undefined && typeof input.include_subdomains !== "boolean") ||
        (input.denied_hosts !== undefined && !Array.isArray(input.denied_hosts)) ||
        (input.denied_paths !== undefined && !Array.isArray(input.denied_paths))) throw new Error();
    target = new URL(input.url);
    if (!["http:", "https:"].includes(target.protocol) || target.username || target.password ||
        target.search || target.hash) throw new Error();
  } catch {
    return { ok: false, code: "INVALID_INPUT", reason: "请提供不含账号、查询参数或片段的完整 HTTP(S) 目标 URL" };
  }

  const scheme = target.protocol.slice(0, -1);
  const port = target.port ? Number(target.port) : scheme === "https" ? 443 : 80;
  const host = target.hostname.replace(/^\[|\]$/gu, "").replace(/\.$/u, "").toLowerCase();
  const allowedPath = target.pathname;
  const scope: ScopeConfig = {
    allowed_schemes: [scheme],
    allowed_hosts: input.include_subdomains ? [] : [host],
    ...(input.include_subdomains ? { allowed_domains: [host] } : {}),
    denied_hosts: input.denied_hosts ?? [],
    allowed_ports: [port],
    allowed_paths: [allowedPath],
    denied_paths: input.denied_paths ?? [],
  };
  const valid = validateScopeConfig(scope);
  if (!valid.valid) return { ok: false, code: "INVALID_INPUT", reason: valid.reason };
  const decision = checkUrlScope(target.href, scope);
  if (!decision.allowed || !decision.target) {
    return { ok: false, code: "INVALID_INPUT", reason: decision.reason };
  }

  const configDir = path.join(path.resolve(projectRoot), "configs");
  const existing = new Map<string, Buffer>();
  try {
    try {
      const directory = await lstat(configDir);
      if (!directory.isDirectory() || directory.isSymbolicLink()) throw new Error("配置目录不是普通目录");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    for (const name of CONFIG_NAMES) {
      const content = await readExisting(path.join(configDir, name));
      if (content) existing.set(name, content);
    }
  } catch {
    return { ok: false, code: "CONFIG_ERROR", reason: "无法读取现有目标配置；未做更改" };
  }

  if (!dependencies.approve) {
    return { ok: false, code: "APPROVAL_REQUIRED", reason: "缺少目标登记确认；未解析 DNS，也未修改配置" };
  }
  try {
    await dependencies.approve({
      target: decision.target.url,
      include_subdomains: input.include_subdomains === true,
      allowed_path: decision.target.path,
      denied_hosts: [...scope.denied_hosts!],
      denied_paths: [...scope.denied_paths],
      replaces_existing_config: existing.size > 0,
    });
  } catch {
    return { ok: false, code: "APPROVAL_DENIED", reason: "用户未确认目标范围；未解析 DNS，也未修改配置" };
  }

  let ips: string[];
  try {
    ips = await (dependencies.resolveIps ?? defaultResolveIps)(host);
    if (!Array.isArray(ips) || ips.length === 0 || ips.some(ip => typeof ip !== "string" || !isIP(ip))) throw new Error();
    ips = [...new Set(ips)];
  } catch {
    return { ok: false, code: "DNS_ERROR", reason: "目标主机无法解析为有效 IP；未修改配置" };
  }

  const httpPolicy: HttpGetPolicy = {
    allowed_resolved_ips: ips,
    timeout_ms: 3000,
    max_response_bytes: 65536,
    max_redirects: 3,
  };
  if (validatePolicy(httpPolicy)) {
    return { ok: false, code: "CONFIG_ERROR", reason: "生成的 HTTP 策略无效；未修改配置" };
  }
  const now = dependencies.now?.() ?? new Date();
  const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const reference = `TASK-${randomUUID().slice(0, 8).toUpperCase()}`;
  const registry: AuthorizationRegistry = {
    schema_version: 1,
    grants: [{ reference, enabled: true, expires_at: expiresAt,
      actions: ["hypothesis_create", "parameter_reflection_check", "xss_encoding_probe"],
      scope }],
  };

  let backupDirectory: string | undefined;
  try {
    await mkdir(configDir, { recursive: true });
    if (existing.size > 0) {
      backupDirectory = path.join(configDir, ".local-backups", `${now.toISOString().replace(/[:.]/gu, "-")}-${randomUUID().slice(0, 8)}`);
      await mkdir(backupDirectory, { recursive: true, mode: 0o700 });
      for (const [name, content] of existing) {
        await writeFile(path.join(backupDirectory, name), content, { flag: "wx", mode: 0o600 });
      }
    }
    const values = [scope, httpPolicy, registry];
    for (let i = 0; i < CONFIG_NAMES.length; i++) {
      await writeFile(path.join(configDir, CONFIG_NAMES[i]), `${JSON.stringify(values[i], null, 2)}\n`, { mode: 0o600 });
    }
  } catch {
    // 保存了可恢复备份时，不把部分写入误报成成功任务。
    return { ok: false, code: "CONFIG_ERROR", reason: "目标配置写入失败；请检查本地备份与配置文件，勿继续请求" };
  }

  return {
    ok: true, code: "TARGET_READY", reason: "目标范围已保存；尚未发送 HTTP 请求，现有检查工具仍会独立校验每次访问",
    target: decision.target.url, authorization_reference: reference, expires_at: expiresAt,
    ...(backupDirectory ? { backup_directory: backupDirectory } : {}),
  };
}
