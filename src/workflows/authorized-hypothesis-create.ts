import { readFile } from "node:fs/promises";
import path from "node:path";

import {
  createHypothesis,
  type CreateHypothesisInput,
} from "../hypotheses/hypothesis-manager.ts";
import { HypothesisStore } from "../hypotheses/hypothesis-store.ts";
import {
  checkHypothesisCreateAuthorization,
  type AuthorizationRegistry,
} from "../scope/authorization-registry.ts";
import { checkUrlScope, type ScopeConfig } from "../scope/scope-guard.ts";

export interface AuthorizedHypothesisCreateInput extends CreateHypothesisInput {
  authorization_reference: string;
}

export type AuthorizedHypothesisCreateResult =
  | {
      ok: true;
      code: "HYPOTHESIS_RECORDED";
      reason: string;
      hypothesis_id: string;
      authorization_reference: string;
      status: "suspected";
      target_url: string;
      file_path: string;
    }
  | {
      ok: false;
      code:
        | "CONFIG_ERROR"
        | "INVALID_INPUT"
        | "SCOPE_DENIED"
        | "AUTHORIZATION_DENIED"
        | "STORE_ERROR";
      reason: string;
    };

/**
 * 只创建待验证假设：不发网络请求，不读取网页，不允许模型指定状态或授权配置。
 * 授权引用必须命中独立的本地授权登记，并与目标和操作相匹配。
 */
export async function runAuthorizedHypothesisCreate(
  projectRoot: string,
  input: AuthorizedHypothesisCreateInput,
  artifactNamespace: "opencode" | "hermes" = "opencode",
): Promise<AuthorizedHypothesisCreateResult> {
  const root = path.resolve(projectRoot);
  if (
    !input ||
    typeof input.target_url !== "string" ||
    typeof input.title !== "string" ||
    typeof input.description !== "string" ||
    typeof input.reason !== "string" ||
    typeof input.authorization_reference !== "string" ||
    input.title.trim().length > 160 ||
    input.description.trim().length > 2000 ||
    input.reason.trim().length > 500
  ) {
    return {
      ok: false,
      code: "INVALID_INPUT",
      reason: "参数必须是字符串，且标题、描述和原因不能超过长度限制",
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(input.target_url);
  } catch {
    return {
      ok: false,
      code: "INVALID_INPUT",
      reason: "目标必须是完整的绝对 URL",
    };
  }
  if (parsed.search || parsed.hash) {
    return {
      ok: false,
      code: "INVALID_INPUT",
      reason: "当前假设只接受不含查询参数或片段的 URL，避免把秘密写入本地记录",
    };
  }

  let scopeConfig: ScopeConfig;
  let authorizationRegistry: AuthorizationRegistry;
  try {
    const [scopeJson, authorizationJson] = await Promise.all([
      readFile(path.join(root, "configs", "scope.local.json"), "utf8"),
      readFile(path.join(root, "configs", "authorization.local.json"), "utf8"),
    ]);
    scopeConfig = JSON.parse(scopeJson) as ScopeConfig;
    authorizationRegistry = JSON.parse(authorizationJson) as AuthorizationRegistry;
  } catch {
    return {
      ok: false,
      code: "CONFIG_ERROR",
      reason: "无法读取项目范围配置或本地授权登记；默认拒绝创建假设",
    };
  }

  const decision = checkUrlScope(input.target_url, scopeConfig);
  if (!decision.allowed || !decision.target) {
    return {
      ok: false,
      code: "SCOPE_DENIED",
      reason: decision.reason,
    };
  }

  const authorization = checkHypothesisCreateAuthorization(
    decision.target.url,
    input.authorization_reference,
    authorizationRegistry,
  );
  if (!authorization.authorized) {
    return {
      ok: false,
      code: "AUTHORIZATION_DENIED",
      reason: authorization.reason,
    };
  }

  const created = createHypothesis({
    ...input,
    target_url: decision.target.url,
  });
  if (!created.ok) {
    return {
      ok: false,
      code: "INVALID_INPUT",
      reason: created.reason,
    };
  }

  const saved = await new HypothesisStore(path.join(root, "hypotheses", artifactNamespace))
    .create(created.hypothesis);
  if (!saved.ok) {
    return {
      ok: false,
      code: "STORE_ERROR",
      reason: saved.reason,
    };
  }

  return {
    ok: true,
    code: "HYPOTHESIS_RECORDED",
    reason: "已记录待验证假设；尚未执行漏洞验证",
    hypothesis_id: saved.hypothesis.hypothesis_id,
    authorization_reference: input.authorization_reference,
    status: "suspected",
    target_url: saved.hypothesis.target_url,
    file_path: saved.file_path,
  };
}
