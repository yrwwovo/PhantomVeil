import {
  checkUrlScope,
  validateScopeConfig,
  type ScopeConfig,
} from "./scope-guard.ts";

const REFERENCE_FORMAT = /^[A-Z0-9][A-Z0-9._-]{5,63}$/u;
export type AuthorizationAction = "hypothesis_create" | "parameter_reflection_check" | "xss_encoding_probe" | "xss_execution_verify" | "redirect_probe" | "web_observe";
const ACTIONS = new Set<AuthorizationAction>([
  "hypothesis_create", "parameter_reflection_check", "xss_encoding_probe", "xss_execution_verify", "redirect_probe", "web_observe",
]);

export interface AuthorizationGrant {
  reference: string;
  enabled: boolean;
  expires_at: string;
  actions: string[];
  scope: ScopeConfig;
}

export interface AuthorizationRegistry {
  schema_version: 1;
  grants: AuthorizationGrant[];
}

export type AuthorizationDecision =
  | { authorized: true; code: "AUTHORIZED"; reason: string }
  | {
      authorized: false;
      code:
        | "INVALID_REGISTRY"
        | "INVALID_REFERENCE"
        | "REFERENCE_NOT_FOUND"
        | "GRANT_DISABLED"
        | "GRANT_EXPIRED"
        | "ACTION_NOT_ALLOWED"
        | "TARGET_NOT_ALLOWED";
      reason: string;
    };

function deny(
  code: Exclude<AuthorizationDecision, { authorized: true }>["code"],
  reason: string,
): AuthorizationDecision {
  return { authorized: false, code, reason };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isUtcTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && date.toISOString() === value;
}

/**
 * 本地授权登记独立于项目总 Scope。引用是授权记录 ID，不是秘密或模型的自述。
 * 本函数完全离线，不执行 DNS 或 HTTP。
 */
export function checkHypothesisCreateAuthorization(
  targetUrl: string,
  reference: string,
  registry: unknown,
  now = new Date(),
): AuthorizationDecision {
  return checkActionAuthorization(targetUrl, reference, "hypothesis_create", registry, now);
}

/** 校验某个明确动作；调用方不能用任意字符串扩展动作集合。 */
export function checkActionAuthorization(
  targetUrl: string,
  reference: string,
  action: AuthorizationAction,
  registry: unknown,
  now = new Date(),
): AuthorizationDecision {
  if (!isRecord(registry) || registry.schema_version !== 1 ||
      !Array.isArray(registry.grants)) {
    return deny("INVALID_REGISTRY", "本地授权登记格式无效");
  }

  const seen = new Set<string>();
  for (const grant of registry.grants) {
    if (!isRecord(grant) || typeof grant.reference !== "string" ||
        !REFERENCE_FORMAT.test(grant.reference) ||
        seen.has(grant.reference) ||
        typeof grant.enabled !== "boolean" ||
        !isUtcTimestamp(grant.expires_at) ||
        !Array.isArray(grant.actions) ||
        grant.actions.some((item) => typeof item !== "string" || !ACTIONS.has(item as AuthorizationAction)) ||
        !isRecord(grant.scope) ||
        !validateScopeConfig(grant.scope as unknown as ScopeConfig).valid) {
      return deny("INVALID_REGISTRY", "本地授权登记包含无效或重复的授权记录");
    }
    seen.add(grant.reference);
  }

  if (typeof reference !== "string" || !REFERENCE_FORMAT.test(reference)) {
    return deny("INVALID_REFERENCE", "缺少或使用了无效的授权引用");
  }
  const grant = registry.grants.find((item) => item.reference === reference) as
    | AuthorizationGrant
    | undefined;
  if (!grant) return deny("REFERENCE_NOT_FOUND", "本地授权登记中没有该授权引用");
  if (!grant.enabled) return deny("GRANT_DISABLED", "该授权引用未启用");
  if (now.getTime() >= new Date(grant.expires_at).getTime()) {
    return deny("GRANT_EXPIRED", "该授权引用已过期");
  }
  if (!grant.actions.includes(action)) {
    const label = action === "hypothesis_create" ? "创建假设"
      : action === "parameter_reflection_check" ? "执行 GET 参数反射检查"
        : action === "xss_encoding_probe" ? "执行 XSS 特殊字符编码观察"
          : action === "redirect_probe" ? "执行重定向参数观察" : "执行只读页面观察";
    return deny("ACTION_NOT_ALLOWED", `该授权引用不允许${label}`);
  }
  const scoped = checkUrlScope(targetUrl, grant.scope);
  if (!scoped.allowed) {
    return deny("TARGET_NOT_ALLOWED", "目标 URL 不在该授权引用对应的范围内");
  }
  return {
    authorized: true,
    code: "AUTHORIZED",
    reason: "本地授权引用、操作及目标范围均已校验",
  };
}
