import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";

import {
  checkUrlScope,
  type ScopeConfig,
  type ScopeDecision,
} from "../../src/scope/scope-guard.ts";

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const OMITTED_RESPONSE_HEADERS = new Set([
  "set-cookie",
  "www-authenticate",
  "proxy-authenticate",
]);

export interface HttpGetPolicy {
  allowed_resolved_ips: string[];
  timeout_ms: number;
  max_response_bytes: number;
  max_redirects: number;
}

export type HttpGetCode =
  | "HTTP_RESPONSE"
  | "INVALID_POLICY"
  | "SCOPE_DENIED"
  | "DNS_ERROR"
  | "IP_NOT_ALLOWED"
  | "INVALID_REDIRECT"
  | "TOO_MANY_REDIRECTS"
  | "TIMEOUT"
  | "RESPONSE_TOO_LARGE"
  | "NETWORK_ERROR"
  | "REQUEST_BLOCKED";

export interface HttpRequestControl {
  // 由可信工作流提供，在每一跳的 DNS/连接前执行，不能由模型传入。
  before_request?: (url: string) => Promise<string | undefined>;
}

export interface RedirectRecord {
  from: string;
  to: string;
  status: number;
}

export interface HttpResponseObservation {
  url: string;
  status: number;
  headers: Record<string, string | string[]>;
  body: string;
  body_bytes: number;
  resolved_ip: string;
}

export interface HttpGetResult {
  ok: boolean;
  code: HttpGetCode;
  reason: string;
  response?: HttpResponseObservation;
  redirects: RedirectRecord[];
  scope_decision?: ScopeDecision;
}

interface PinnedAddress {
  address: string;
  family: 4 | 6;
}

interface RawResponse {
  status: number;
  headers: Record<string, string | string[]>;
  body: string;
  bodyBytes: number;
  location?: string;
}

class RequestFailure extends Error {
  readonly code: Exclude<
    HttpGetCode,
    | "HTTP_RESPONSE"
    | "INVALID_POLICY"
    | "SCOPE_DENIED"
    | "DNS_ERROR"
    | "IP_NOT_ALLOWED"
    | "INVALID_REDIRECT"
    | "TOO_MANY_REDIRECTS"
    | "REQUEST_BLOCKED"
  >;

  constructor(
    code: Exclude<
      HttpGetCode,
      | "HTTP_RESPONSE"
      | "INVALID_POLICY"
      | "SCOPE_DENIED"
      | "DNS_ERROR"
      | "IP_NOT_ALLOWED"
      | "INVALID_REDIRECT"
      | "TOO_MANY_REDIRECTS"
      | "REQUEST_BLOCKED"
    >,
    message: string,
  ) {
    super(message);
    this.code = code;
  }
}

function normalizeIp(value: string): string | undefined {
  const candidate = value.trim();
  const family = isIP(candidate);
  if (family === 4) {
    return candidate
      .split(".")
      .map((part) => String(Number(part)))
      .join(".");
  }

  if (family === 6) {
    try {
      return new URL(`http://[${candidate}]/`).hostname.slice(1, -1);
    } catch {
      return undefined;
    }
  }

  return undefined;
}

export function validatePolicy(policy: HttpGetPolicy): string | undefined {
  if (!policy || typeof policy !== "object") {
    return "HTTP 策略不存在";
  }
  if (!Array.isArray(policy.allowed_resolved_ips)) {
    return "allowed_resolved_ips 必须是数组";
  }
  if (
    policy.allowed_resolved_ips.length === 0 ||
    policy.allowed_resolved_ips.some(
      (value) => typeof value !== "string" || !normalizeIp(value),
    )
  ) {
    return "allowed_resolved_ips 必须包含至少一个有效 IP 地址";
  }
  if (!Number.isInteger(policy.timeout_ms) || policy.timeout_ms < 1) {
    return "timeout_ms 必须是正整数";
  }
  if (
    !Number.isInteger(policy.max_response_bytes) ||
    policy.max_response_bytes < 1
  ) {
    return "max_response_bytes 必须是正整数";
  }
  if (!Number.isInteger(policy.max_redirects) || policy.max_redirects < 0) {
    return "max_redirects 必须是非负整数";
  }
  return undefined;
}

async function choosePinnedAddress(
  host: string,
  allowedIps: Set<string>,
): Promise<
  | { address: PinnedAddress }
  | { code: "DNS_ERROR" | "IP_NOT_ALLOWED"; reason: string }
> {
  let candidates: PinnedAddress[];
  const literalFamily = isIP(host);

  if (literalFamily === 4 || literalFamily === 6) {
    candidates = [
      {
        address: normalizeIp(host) ?? host,
        family: literalFamily,
      },
    ];
  } else {
    try {
      const records = await lookup(host, { all: true, verbatim: true });
      candidates = records
        .map((record) => ({
          address: normalizeIp(record.address) ?? record.address,
          family: record.family,
        }))
        .filter(
          (record): record is PinnedAddress =>
            record.family === 4 || record.family === 6,
        );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { code: "DNS_ERROR", reason: `域名解析失败：${message}` };
    }
  }

  const allowed = candidates.find((item) => allowedIps.has(item.address));
  if (!allowed) {
    const resolved = candidates.map((item) => item.address).join(", ") || "无结果";
    return {
      code: "IP_NOT_ALLOWED",
      reason: `主机解析结果不在授权 IP 范围内：${resolved}`,
    };
  }

  return { address: allowed };
}

function safeHeaders(
  headers: http.IncomingHttpHeaders,
): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || OMITTED_RESPONSE_HEADERS.has(name.toLowerCase())) {
      continue;
    }
    result[name] = value;
  }
  return result;
}

function requestOnce(
  target: URL,
  pinnedAddress: PinnedAddress,
  policy: HttpGetPolicy,
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const transport = target.protocol === "https:" ? https : http;
    let settled = false;

    const finishReject = (error: Error): void => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };

    const request = transport.request(
      target,
      {
        method: "GET",
        headers: {
          accept: "text/html,application/json,text/plain;q=0.9,*/*;q=0.1",
          "accept-encoding": "identity",
          "user-agent": "security-agent-lab/0.1 restricted-http-get",
        },
        lookup: (_hostname, _options, callback) => {
          callback(null, pinnedAddress.address, pinnedAddress.family);
        },
        // 已经选定并固定一个授权 IP；禁用 Node 的多地址自动选择，
        // 避免它要求 lookup 回调返回地址数组并绕开单地址连接语义。
        autoSelectFamily: false,
      },
      (response) => {
        const status = response.statusCode ?? 0;
        const location = response.headers.location;
        const headers = safeHeaders(response.headers);

        if (REDIRECT_STATUSES.has(status) && location) {
          response.destroy();
          settled = true;
          resolve({ status, headers, body: "", bodyBytes: 0, location });
          return;
        }

        const chunks: Buffer[] = [];
        let totalBytes = 0;

        response.on("data", (chunk: Buffer | string) => {
          const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          totalBytes += buffer.length;
          if (totalBytes > policy.max_response_bytes) {
            response.destroy(
              new RequestFailure(
                "RESPONSE_TOO_LARGE",
                `响应超过 ${policy.max_response_bytes} 字节限制`,
              ),
            );
            return;
          }
          chunks.push(buffer);
        });

        response.on("end", () => {
          if (settled) {
            return;
          }
          settled = true;
          resolve({
            status,
            headers,
            body: Buffer.concat(chunks).toString("utf8"),
            bodyBytes: totalBytes,
          });
        });

        response.on("error", finishReject);
      },
    );

    request.setTimeout(policy.timeout_ms, () => {
      request.destroy(
        new RequestFailure("TIMEOUT", `请求超过 ${policy.timeout_ms} 毫秒限制`),
      );
    });
    // 限制整个请求耗时，防止持续发送少量数据绕过 socket 空闲超时。
    const deadline = setTimeout(() => request.destroy(
      new RequestFailure("TIMEOUT", `请求超过 ${policy.timeout_ms} 毫秒限制`),
    ), policy.timeout_ms);
    request.once("close", () => clearTimeout(deadline));
    request.on("error", finishReject);
    request.end();
  });
}

/**
 * 对显式授权目标执行一次受限 GET。每次重定向都会重新进行范围与 IP 检查。
 * 本阶段只返回观察结果，不保存证据，也不判断任何漏洞。
 */
export async function restrictedHttpGet(
  targetUrl: string,
  scopeConfig: ScopeConfig,
  policy: HttpGetPolicy,
  control: HttpRequestControl = {},
): Promise<HttpGetResult> {
  const policyError = validatePolicy(policy);
  if (policyError) {
    return {
      ok: false,
      code: "INVALID_POLICY",
      reason: policyError,
      redirects: [],
    };
  }

  const allowedIps = new Set(
    policy.allowed_resolved_ips.map((value) => normalizeIp(value) as string),
  );
  const redirects: RedirectRecord[] = [];
  let currentUrl = targetUrl;

  for (let redirectCount = 0; ; redirectCount += 1) {
    const scopeDecision = checkUrlScope(currentUrl, scopeConfig);
    if (!scopeDecision.allowed || !scopeDecision.target) {
      return {
        ok: false,
        code: "SCOPE_DENIED",
        reason: `Scope Guard 拒绝请求：${scopeDecision.reason}`,
        redirects,
        scope_decision: scopeDecision,
      };
    }

    const blocked = await control.before_request?.(scopeDecision.target.url);
    if (blocked) return { ok: false, code: "REQUEST_BLOCKED", reason: blocked, redirects };

    const pinnedResult = await choosePinnedAddress(
      scopeDecision.target.host,
      allowedIps,
    );
    if (!("address" in pinnedResult)) {
      return {
        ok: false,
        code: pinnedResult.code,
        reason: pinnedResult.reason,
        redirects,
      };
    }

    let response: RawResponse;
    try {
      response = await requestOnce(
        new URL(scopeDecision.target.url),
        pinnedResult.address,
        policy,
      );
    } catch (error) {
      if (error instanceof RequestFailure) {
        return {
          ok: false,
          code: error.code,
          reason: error.message,
          redirects,
        };
      }
      const message = error instanceof Error ? error.message : String(error);
      return {
        ok: false,
        code: "NETWORK_ERROR",
        reason: `网络请求失败：${message}`,
        redirects,
      };
    }

    if (response.location && REDIRECT_STATUSES.has(response.status)) {
      if (redirectCount >= policy.max_redirects) {
        return {
          ok: false,
          code: "TOO_MANY_REDIRECTS",
          reason: `重定向次数超过 ${policy.max_redirects} 次限制`,
          redirects,
        };
      }

      let nextUrl: string;
      try {
        nextUrl = new URL(response.location, currentUrl).href;
      } catch {
        return {
          ok: false,
          code: "INVALID_REDIRECT",
          reason: "服务器返回了无效的重定向地址",
          redirects,
        };
      }

      redirects.push({
        from: currentUrl,
        to: nextUrl,
        status: response.status,
      });
      currentUrl = nextUrl;
      continue;
    }

    return {
      ok: true,
      code: "HTTP_RESPONSE",
      reason: "已在授权范围内完成一次受限 HTTP GET",
      redirects,
      response: {
        url: currentUrl,
        status: response.status,
        headers: response.headers,
        body: response.body,
        body_bytes: response.bodyBytes,
        resolved_ip: pinnedResult.address.address,
      },
    };
  }
}
