import path from "node:path";
import { isIP } from "node:net";

const SUPPORTED_SCHEMES = new Set(["http", "https"]);
const DEFAULT_PORTS: Readonly<Record<string, number>> = {
  http: 80,
  https: 443,
};

export interface ScopeConfig {
  allowed_schemes: string[];
  allowed_hosts: string[];
  /** 精确主机及其所有子域名；不接受 IP、localhost 或通配符。 */
  allowed_domains?: string[];
  /** 精确排除的主机，优先于允许规则。 */
  denied_hosts?: string[];
  allowed_ports: number[];
  allowed_paths: string[];
  denied_paths: string[];
}

export type ScopeDecisionCode =
  | "ALLOWED"
  | "INVALID_URL"
  | "INVALID_CONFIG"
  | "SCHEME_NOT_ALLOWED"
  | "HOST_NOT_ALLOWED"
  | "HOST_DENIED"
  | "PORT_NOT_ALLOWED"
  | "PATH_DENIED"
  | "PATH_NOT_ALLOWED";

export interface NormalizedTarget {
  url: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
}

export interface ScopeDecision {
  allowed: boolean;
  code: ScopeDecisionCode;
  reason: string;
  target?: NormalizedTarget;
}

interface NormalizedConfig {
  allowedSchemes: Set<string>;
  allowedHosts: Set<string>;
  allowedDomains: Set<string>;
  deniedHosts: Set<string>;
  allowedPorts: Set<number>;
  allowedPaths: string[];
  deniedPaths: string[];
}

interface ConfigResult {
  config?: NormalizedConfig;
  error?: string;
}

function deny(
  code: Exclude<ScopeDecisionCode, "ALLOWED">,
  reason: string,
  target?: NormalizedTarget,
): ScopeDecision {
  return { allowed: false, code, reason, ...(target ? { target } : {}) };
}

function normalizeScheme(value: string): string {
  return value.trim().toLowerCase().replace(/:$/, "");
}

function normalizeHost(value: string): string | undefined {
  const candidate = value.trim();
  if (!candidate || candidate.includes("://") || /[\/@?#]/u.test(candidate)) {
    return undefined;
  }

  try {
    const authority =
      candidate.includes(":") && !candidate.startsWith("[")
        ? `[${candidate}]`
        : candidate;
    const parsed = new URL(`http://${authority}`);

    if (parsed.username || parsed.password || parsed.port || parsed.pathname !== "/") {
      return undefined;
    }

    return parsed.hostname
      .replace(/^\[|\]$/gu, "")
      .replace(/\.$/u, "")
      .toLowerCase();
  } catch {
    return undefined;
  }
}

function normalizePath(value: string): string | undefined {
  if (!value.startsWith("/") || value.includes("?") || value.includes("#")) {
    return undefined;
  }

  try {
    const decoded = decodeURIComponent(value).replaceAll("\\", "/");
    if (decoded.includes("\0")) {
      return undefined;
    }

    const normalized = path.posix.normalize(decoded);
    return normalized.length > 1 ? normalized.replace(/\/$/u, "") : normalized;
  } catch {
    return undefined;
  }
}

function normalizeDomain(value: string): string | undefined {
  const host = normalizeHost(value);
  if (!host || isIP(host) || !host.includes(".") || host.includes("*")) {
    return undefined;
  }
  return host;
}

function hostIsWithinDomain(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

function pathIsWithin(candidate: string, scopePath: string): boolean {
  return (
    scopePath === "/" ||
    candidate === scopePath ||
    candidate.startsWith(`${scopePath}/`)
  );
}

function normalizeConfig(config: ScopeConfig): ConfigResult {
  if (!config || typeof config !== "object") {
    return { error: "授权配置不存在" };
  }

  const requiredArrays: Array<[keyof ScopeConfig, unknown]> = [
    ["allowed_schemes", config.allowed_schemes],
    ["allowed_hosts", config.allowed_hosts],
    ["allowed_ports", config.allowed_ports],
    ["allowed_paths", config.allowed_paths],
    ["denied_paths", config.denied_paths],
  ];

  const nonArray = requiredArrays.find(([, value]) => !Array.isArray(value));
  if (nonArray) {
    return { error: `配置项 ${nonArray[0]} 必须是数组` };
  }

  if (
    (config.allowed_domains !== undefined && !Array.isArray(config.allowed_domains)) ||
    (config.denied_hosts !== undefined && !Array.isArray(config.denied_hosts))
  ) {
    return { error: "allowed_domains 和 denied_hosts 必须是数组" };
  }

  if (
    config.allowed_schemes.some((value) => typeof value !== "string") ||
    config.allowed_hosts.some((value) => typeof value !== "string") ||
    (config.allowed_domains ?? []).some((value) => typeof value !== "string") ||
    (config.denied_hosts ?? []).some((value) => typeof value !== "string") ||
    config.allowed_paths.some((value) => typeof value !== "string") ||
    config.denied_paths.some((value) => typeof value !== "string")
  ) {
    return { error: "协议、主机和路径配置项必须使用字符串" };
  }

  const schemes = config.allowed_schemes.map(normalizeScheme);
  if (schemes.some((scheme) => !SUPPORTED_SCHEMES.has(scheme))) {
    return { error: "allowed_schemes 目前只支持 http 和 https" };
  }

  const hosts = config.allowed_hosts.map(normalizeHost);
  if (hosts.some((host) => host === undefined)) {
    return { error: "allowed_hosts 包含无效主机；请只填写主机名或 IP" };
  }

  const domains = (config.allowed_domains ?? []).map(normalizeDomain);
  if (domains.some((domain) => domain === undefined)) {
    return { error: "allowed_domains 只能填写完整域名，不支持 IP、localhost 或 *. 通配符" };
  }

  const deniedHosts = (config.denied_hosts ?? []).map(normalizeHost);
  if (deniedHosts.some((host) => host === undefined)) {
    return { error: "denied_hosts 包含无效主机；请只填写精确主机名或 IP" };
  }

  if (
    config.allowed_ports.some(
      (port) => !Number.isInteger(port) || port < 1 || port > 65_535,
    )
  ) {
    return { error: "allowed_ports 必须包含 1 到 65535 之间的整数" };
  }

  const allowedPaths = config.allowed_paths.map(normalizePath);
  const deniedPaths = config.denied_paths.map(normalizePath);
  if ([...allowedPaths, ...deniedPaths].some((item) => item === undefined)) {
    return { error: "路径必须以 / 开头，且不能包含查询参数或片段" };
  }

  return {
    config: {
      allowedSchemes: new Set(schemes),
      allowedHosts: new Set(hosts as string[]),
      allowedDomains: new Set(domains as string[]),
      deniedHosts: new Set(deniedHosts as string[]),
      allowedPorts: new Set(config.allowed_ports),
      allowedPaths: allowedPaths as string[],
      deniedPaths: deniedPaths as string[],
    },
  };
}

/** 仅校验授权配置结构；不做 URL 判断或网络访问。 */
export function validateScopeConfig(config: ScopeConfig): {
  valid: boolean;
  reason: string;
} {
  const result = normalizeConfig(config);
  return result.config
    ? { valid: true, reason: "授权配置结构有效" }
    : { valid: false, reason: result.error ?? "授权配置无效" };
}

/**
 * 离线判断目标 URL 是否位于显式授权范围内。
 * 本函数不会执行 DNS 解析，也不会发送任何网络请求。
 */
export function checkUrlScope(
  targetUrl: string,
  scopeConfig: ScopeConfig,
): ScopeDecision {
  const configResult = normalizeConfig(scopeConfig);
  if (!configResult.config) {
    return deny("INVALID_CONFIG", configResult.error ?? "授权配置无效");
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return deny("INVALID_URL", "目标 URL 格式无效，必须提供完整的绝对地址");
  }

  if (parsed.username || parsed.password) {
    return deny("INVALID_URL", "目标 URL 不能包含用户名或密码");
  }

  const scheme = normalizeScheme(parsed.protocol);
  const host = parsed.hostname
    .replace(/^\[|\]$/gu, "")
    .replace(/\.$/u, "")
    .toLowerCase();
  const effectivePort = parsed.port
    ? Number(parsed.port)
    : DEFAULT_PORTS[scheme];
  const normalizedPath = normalizePath(parsed.pathname);

  if (!effectivePort || !normalizedPath) {
    return deny("INVALID_URL", "目标 URL 包含无效端口或路径");
  }

  const target: NormalizedTarget = {
    url: parsed.href,
    scheme,
    host,
    port: effectivePort,
    path: normalizedPath,
  };
  const config = configResult.config;

  if (config.allowedSchemes.size === 0 || !config.allowedSchemes.has(scheme)) {
    return deny("SCHEME_NOT_ALLOWED", `协议 ${scheme} 未被授权`, target);
  }

  if (config.deniedHosts.has(host)) {
    return deny("HOST_DENIED", `主机 ${host} 命中禁止规则`, target);
  }

  const hostAllowed = config.allowedHosts.has(host) ||
    [...config.allowedDomains].some((domain) => hostIsWithinDomain(host, domain));
  if (!hostAllowed) {
    return deny("HOST_NOT_ALLOWED", `主机 ${host} 未被授权`, target);
  }

  if (config.allowedPorts.size === 0 || !config.allowedPorts.has(effectivePort)) {
    return deny("PORT_NOT_ALLOWED", `端口 ${effectivePort} 未被授权`, target);
  }

  const deniedPath = config.deniedPaths.find((item) =>
    pathIsWithin(normalizedPath, item),
  );
  if (deniedPath) {
    return deny(
      "PATH_DENIED",
      `路径 ${normalizedPath} 命中禁止规则 ${deniedPath}`,
      target,
    );
  }

  const allowedPath = config.allowedPaths.find((item) =>
    pathIsWithin(normalizedPath, item),
  );
  if (config.allowedPaths.length === 0 || !allowedPath) {
    return deny("PATH_NOT_ALLOWED", `路径 ${normalizedPath} 未被授权`, target);
  }

  return {
    allowed: true,
    code: "ALLOWED",
    reason: "目标 URL 位于显式授权范围内",
    target,
  };
}
