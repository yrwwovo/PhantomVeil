import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { checkActionAuthorization, type AuthorizationRegistry } from "../src/scope/authorization-registry.ts";
import { checkUrlScope, type ScopeConfig } from "../src/scope/scope-guard.ts";
import { runTargetSetup } from "../src/scope/target-setup.ts";

async function rootFor(context: { after: (fn: () => Promise<void>) => void }) {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-target-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test("中文任务入口确认后生成可用范围、IP 策略和授权引用", async context => {
  const root = await rootFor(context);
  const approvals: unknown[] = [];
  const result = await runTargetSetup(root, {
    url: "http://127.0.0.1:5000/app",
    denied_paths: ["/app/delete"],
  }, {
    approve: async details => { approvals.push(details); },
    resolveIps: async () => ["127.0.0.1"],
    now: () => new Date("2026-09-29T00:00:00.000Z"),
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(approvals.length, 1);
  assert.equal(result.expires_at, "2026-10-06T00:00:00.000Z");
  const configDir = path.join(root, "configs");
  const scope = JSON.parse(await readFile(path.join(configDir, "scope.local.json"), "utf8")) as ScopeConfig;
  const http = JSON.parse(await readFile(path.join(configDir, "http.local.json"), "utf8"));
  const registry = JSON.parse(await readFile(path.join(configDir, "authorization.local.json"), "utf8")) as AuthorizationRegistry;
  assert.equal(checkUrlScope("http://127.0.0.1:5000/app/page", scope).code, "ALLOWED");
  assert.equal(checkUrlScope("http://127.0.0.1:5000/other", scope).code, "PATH_NOT_ALLOWED");
  assert.equal(checkUrlScope("http://127.0.0.1:5000/app/delete", scope).code, "PATH_DENIED");
  assert.deepEqual(http.allowed_resolved_ips, ["127.0.0.1"]);
  assert.equal(checkActionAuthorization("http://127.0.0.1:5000/app", result.authorization_reference,
    "parameter_reflection_check", registry, new Date("2026-09-29T01:00:00.000Z")).code, "AUTHORIZED");
  assert.equal(checkActionAuthorization("http://127.0.0.1:5000/app", result.authorization_reference,
    "redirect_probe", registry, new Date("2026-09-29T01:00:00.000Z")).code, "AUTHORIZED");
  assert.equal(checkActionAuthorization("http://127.0.0.1:5000/app", result.authorization_reference,
    "web_observe", registry, new Date("2026-09-29T01:00:00.000Z")).code, "AUTHORIZED");
});

test("拒绝或缺少确认时不解析 DNS、不创建配置", async context => {
  const root = await rootFor(context);
  let resolved = 0;
  const resolveIps = async () => { resolved++; return ["127.0.0.1"]; };
  const missing = await runTargetSetup(root, { url: "http://127.0.0.1:5000/" }, { resolveIps });
  const denied = await runTargetSetup(root, { url: "http://127.0.0.1:5000/" }, {
    resolveIps, approve: async () => { throw new Error("denied"); },
  });
  assert.equal(missing.code, "APPROVAL_REQUIRED");
  assert.equal(denied.code, "APPROVAL_DENIED");
  assert.equal(resolved, 0);
  await assert.rejects(readFile(path.join(root, "configs", "scope.local.json")));
});

test("切换目标前备份用户原配置，子域名匹配按域名段检查", async context => {
  const root = await rootFor(context);
  const configDir = path.join(root, "configs");
  await mkdir(configDir);
  const original = "{\"user\":\"old-config\"}\n";
  await writeFile(path.join(configDir, "scope.local.json"), original);
  const result = await runTargetSetup(root, {
    url: "https://example.test/", include_subdomains: true,
    denied_hosts: ["admin.example.test"],
  }, { approve: async details => { assert.equal(details.replaces_existing_config, true); },
    resolveIps: async () => ["192.0.2.10"] });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.ok(result.backup_directory);
  assert.equal(await readFile(path.join(result.backup_directory, "scope.local.json"), "utf8"), original);
  const scope = JSON.parse(await readFile(path.join(configDir, "scope.local.json"), "utf8")) as ScopeConfig;
  assert.equal(checkUrlScope("https://oa.example.test/", scope).code, "ALLOWED");
  assert.equal(checkUrlScope("https://admin.example.test/", scope).code, "HOST_DENIED");
  assert.equal(checkUrlScope("https://example.test.evil.test/", scope).code, "HOST_NOT_ALLOWED");
});

test("异常目标和 DNS 失败不会替换已有配置", async context => {
  const root = await rootFor(context);
  const configDir = path.join(root, "configs");
  await mkdir(configDir);
  await writeFile(path.join(configDir, "scope.local.json"), "old");
  const invalid = await runTargetSetup(root, { url: "https://user:pass@example.test/" }, {
    approve: async () => {}, resolveIps: async () => ["192.0.2.10"],
  });
  const dnsFail = await runTargetSetup(root, { url: "https://example.test/" }, {
    approve: async () => {}, resolveIps: async () => { throw new Error("DNS failed"); },
  });
  assert.equal(invalid.code, "INVALID_INPUT");
  assert.equal(dnsFail.code, "DNS_ERROR");
  assert.equal(await readFile(path.join(configDir, "scope.local.json"), "utf8"), "old");
});

test("OpenCode 入口声明一次确认且不直接运行扫描", async () => {
  const projectRoot = path.resolve(import.meta.dirname, "..");
  const tool = await readFile(path.join(projectRoot, ".opencode/tools/authorized_target_setup.ts"), "utf8");
  const agent = await readFile(path.join(projectRoot, ".opencode/agents/web-security-agent.md"), "utf8");
  assert.match(tool, /permission: "target_setup"/u);
  assert.match(tool, /runTargetSetup/u);
  assert.doesNotMatch(tool, /runWebCheck|runWebCrawl|runAuthorizedReflectedXssAssessment/u);
  assert.match(agent, /authorized_target_setup: allow/u);
  assert.match(agent, /target_setup: ask/u);
  const toolModule = await import("../.opencode/tools/authorized_target_setup.ts");
  assert.deepEqual(Object.keys(toolModule.default.args).sort(),
    ["url", "include_subdomains", "denied_hosts", "denied_paths"].sort());
});
