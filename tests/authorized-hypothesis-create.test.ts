import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import hypothesisTool from "../.opencode/tools/authorized_hypothesis_create.ts";
import { runAuthorizedHypothesisCreate } from "../src/adapters/opencode/authorized-hypothesis-create.ts";
import { HypothesisStore } from "../src/hypotheses/hypothesis-store.ts";

const AUTHORIZATION_REFERENCE = "LOCAL-LAB-TEST";

async function temporaryProject(context: TestContext): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-hypothesis-tool-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function writeScope(root: string, port: number): Promise<void> {
  await mkdir(path.join(root, "configs"), { recursive: true });
  await writeFile(
    path.join(root, "configs", "scope.local.json"),
    JSON.stringify({
      allowed_schemes: ["http"],
      allowed_hosts: ["127.0.0.1"],
      allowed_ports: [port],
      allowed_paths: ["/lab"],
      denied_paths: ["/lab/admin"],
    }),
    "utf8",
  );
}

async function writeAuthorization(
  root: string,
  port: number,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  await mkdir(path.join(root, "configs"), { recursive: true });
  await writeFile(
    path.join(root, "configs", "authorization.local.json"),
    JSON.stringify({
      schema_version: 1,
      grants: [{
        reference: AUTHORIZATION_REFERENCE,
        enabled: true,
        expires_at: "2099-12-31T23:59:59.000Z",
        actions: ["hypothesis_create"],
        scope: {
          allowed_schemes: ["http"],
          allowed_hosts: ["127.0.0.1"],
          allowed_ports: [port],
          allowed_paths: ["/lab"],
          denied_paths: ["/lab/admin"],
        },
        ...overrides,
      }],
    }),
    "utf8",
  );
}

function input(target_url: string, authorization_reference = AUTHORIZATION_REFERENCE) {
  return {
    authorization_reference,
    target_url,
    title: "待验证：响应头配置可能需要检查",
    description: "这是一个待验证想法，并非漏洞结论。",
    reason: "人工提出，尚无验证结果",
  };
}

test("授权 URL 只创建 suspected 假设，不发送网络请求", async (context) => {
  const root = await temporaryProject(context);
  let requestCount = 0;
  const server = createServer((_request, response) => {
    requestCount += 1;
    response.end("not expected");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  context.after(() => new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  }));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("没有测试端口");
  await writeScope(root, address.port);
  await writeAuthorization(root, address.port);

  const result = await runAuthorizedHypothesisCreate(
    root,
    input(`http://127.0.0.1:${address.port}/lab/page`),
  );
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.code, "HYPOTHESIS_RECORDED");
  assert.equal(result.status, "suspected");
  assert.equal(result.authorization_reference, AUTHORIZATION_REFERENCE);
  assert.equal(requestCount, 0);

  const reopened = await new HypothesisStore(path.join(root, "hypotheses", "opencode"))
    .load(result.hypothesis_id);
  assert.equal(reopened.ok, true);
  if (!reopened.ok) return;
  assert.equal(reopened.hypothesis.status, "suspected");
  assert.equal(reopened.hypothesis.authorization_reference, AUTHORIZATION_REFERENCE);
  assert.deepEqual(reopened.hypothesis.evidence, []);
  assert.deepEqual(reopened.hypothesis.reproduction_steps, []);
  assert.equal(reopened.hypothesis.history.length, 1);
});

test("缺少授权配置时默认拒绝，且不创建记录", async (context) => {
  const root = await temporaryProject(context);
  const result = await runAuthorizedHypothesisCreate(
    root,
    input("http://127.0.0.1:5000/lab"),
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "CONFIG_ERROR");
  await assert.rejects(readdir(path.join(root, "hypotheses")), { code: "ENOENT" });
});

test("端口、伪装主机和禁止路径都不能创建假设", async (context) => {
  const root = await temporaryProject(context);
  await writeScope(root, 5000);
  await writeAuthorization(root, 5000);
  const targets = [
    "http://127.0.0.1:5001/lab",
    "http://127.0.0.1.evil.example:5000/lab",
    "http://127.0.0.1:5000/lab/admin",
  ];
  for (const target of targets) {
    const result = await runAuthorizedHypothesisCreate(root, input(target));
    assert.equal(result.ok, false);
    assert.equal(result.code, "SCOPE_DENIED");
  }
  await assert.rejects(readdir(path.join(root, "hypotheses")), { code: "ENOENT" });
});

test("含查询秘密、异常 URL 和空白标题被拒绝", async (context) => {
  const root = await temporaryProject(context);
  await writeScope(root, 5000);
  await writeAuthorization(root, 5000);
  for (const proposed of [
    input("http://127.0.0.1:5000/lab?token=secret"),
    input("not-a-url"),
    { ...input("http://127.0.0.1:5000/lab"), title: " " },
  ]) {
    const result = await runAuthorizedHypothesisCreate(root, proposed);
    assert.equal(result.ok, false);
    assert.equal(result.code, "INVALID_INPUT");
  }
  await assert.rejects(readdir(path.join(root, "hypotheses")), { code: "ENOENT" });
});

test("OpenCode 工具仅暴露创建所需参数，没有状态参数", async () => {
  assert.deepEqual(
    Object.keys(hypothesisTool.args).sort(),
    ["authorization_reference", "description", "reason", "target_url", "title"],
  );
  const output = await hypothesisTool.execute(
    input("http://127.0.0.1:5000/lab?token=secret"),
    {} as never,
  );
  assert.equal(typeof output, "string");
  const result = JSON.parse(output as string) as { code: string };
  assert.equal(result.code, "INVALID_INPUT");
});

test("受限 Agent 要求创建工具逐次审批且不能直接读授权登记", async () => {
  const agent = await readFile(
    new URL("../.opencode/agents/web-security-agent.md", import.meta.url),
    "utf8",
  );
  assert.match(agent, /authorized_hypothesis_create: ask/u);
  assert.match(agent, /read: deny/u);
  assert.match(agent, /grep: deny/u);
  assert.match(agent, /glob: deny/u);
});

test("即使调用方额外传入 confirmed，也只能保存 suspected", async (context) => {
  const root = await temporaryProject(context);
  await writeScope(root, 5000);
  await writeAuthorization(root, 5000);
  const supplied = {
    ...input("http://127.0.0.1:5000/lab"),
    status: "confirmed",
  };
  const result = await runAuthorizedHypothesisCreate(root, supplied);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.status, "suspected");
  const loaded = await new HypothesisStore(path.join(root, "hypotheses", "opencode"))
    .load(result.hypothesis_id);
  assert.equal(loaded.ok, true);
  if (loaded.ok) assert.equal(loaded.hypothesis.status, "suspected");
});

test("缺少独立授权登记时，已有 URL Scope 也不能创建假设", async (context) => {
  const root = await temporaryProject(context);
  await writeScope(root, 5000);
  const result = await runAuthorizedHypothesisCreate(
    root,
    input("http://127.0.0.1:5000/lab"),
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "CONFIG_ERROR");
  await assert.rejects(readdir(path.join(root, "hypotheses")), { code: "ENOENT" });
});

test("缺失或编造的授权引用都被拒绝，不产生假设文件", async (context) => {
  const root = await temporaryProject(context);
  await writeScope(root, 5000);
  await writeAuthorization(root, 5000);
  for (const reference of ["", "LOCAL-LAB-INVENTED"]) {
    const result = await runAuthorizedHypothesisCreate(
      root,
      input("http://127.0.0.1:5000/lab", reference),
    );
    assert.equal(result.ok, false);
    assert.equal(result.code, "AUTHORIZATION_DENIED");
  }
  await assert.rejects(readdir(path.join(root, "hypotheses")), { code: "ENOENT" });
});

test("禁用、过期和未授权操作的引用都不能写入", async (context) => {
  const root = await temporaryProject(context);
  await writeScope(root, 5000);
  for (const override of [
    { enabled: false },
    { expires_at: "2020-01-01T00:00:00.000Z" },
    { actions: [] },
  ]) {
    await writeAuthorization(root, 5000, override);
    const result = await runAuthorizedHypothesisCreate(
      root,
      input("http://127.0.0.1:5000/lab"),
    );
    assert.equal(result.ok, false);
    assert.equal(result.code, "AUTHORIZATION_DENIED");
  }
  await assert.rejects(readdir(path.join(root, "hypotheses")), { code: "ENOENT" });
});

test("授权引用的范围不匹配时，即使总体 Scope 放行也拒绝", async (context) => {
  const root = await temporaryProject(context);
  await writeScope(root, 5000);
  await writeAuthorization(root, 5001);
  const result = await runAuthorizedHypothesisCreate(
    root,
    input("http://127.0.0.1:5000/lab"),
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "AUTHORIZATION_DENIED");
  await assert.rejects(readdir(path.join(root, "hypotheses")), { code: "ENOENT" });
});
