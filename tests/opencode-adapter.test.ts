import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import authorizedWebObserveTool from "../.opencode/tools/authorized_web_observe.ts";
import { runAuthorizedWebObservation } from "../src/adapters/opencode/authorized-web-observe.ts";

function temporaryProjectRoot(): string {
  return path.join(
    tmpdir(),
    `security-agent-opencode-${process.pid}-${Date.now()}-${Math.random()}`,
  );
}

test("OpenCode 适配层完成授权 GET 证据和报告链路", async (context) => {
  const projectRoot = temporaryProjectRoot();
  context.after(() => rm(projectRoot, { recursive: true, force: true }));
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("page content must not return to the model");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  context.after(
    () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  );
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("测试服务器没有可用端口");
  }

  await mkdir(path.join(projectRoot, "configs"), { recursive: true });
  await writeFile(
    path.join(projectRoot, "configs", "scope.local.json"),
    JSON.stringify({
      allowed_schemes: ["http"],
      allowed_hosts: ["127.0.0.1"],
      allowed_ports: [address.port],
      allowed_paths: ["/observe"],
      denied_paths: [],
    }),
    "utf8",
  );
  await writeFile(
    path.join(projectRoot, "configs", "http.local.json"),
    JSON.stringify({
      allowed_resolved_ips: ["127.0.0.1"],
      timeout_ms: 1000,
      max_response_bytes: 4096,
      max_redirects: 0,
    }),
    "utf8",
  );

  const result = await runAuthorizedWebObservation(
    projectRoot,
    `http://127.0.0.1:${address.port}/observe`,
  );

  assert.equal(result.ok, true);
  if (!result.ok) {
    return;
  }
  assert.equal(result.code, "OBSERVATION_RECORDED");
  assert.equal(result.http_status, 200);
  assert.match(result.evidence_id, /^EV-/u);
  assert.match(result.report_id, /^RPT-/u);

  const report = await readFile(result.report_file, "utf8");
  assert.match(report, new RegExp(result.evidence_id, "u"));
  assert.doesNotMatch(JSON.stringify(result), /page content must not return/u);
});

test("OpenCode 适配层不能绕过项目授权配置", async (context) => {
  const projectRoot = temporaryProjectRoot();
  context.after(() => rm(projectRoot, { recursive: true, force: true }));
  await mkdir(path.join(projectRoot, "configs"), { recursive: true });
  await writeFile(
    path.join(projectRoot, "configs", "scope.local.json"),
    JSON.stringify({
      allowed_schemes: [],
      allowed_hosts: [],
      allowed_ports: [],
      allowed_paths: [],
      denied_paths: [],
    }),
    "utf8",
  );
  await writeFile(
    path.join(projectRoot, "configs", "http.local.json"),
    JSON.stringify({
      allowed_resolved_ips: ["127.0.0.1"],
      timeout_ms: 1000,
      max_response_bytes: 4096,
      max_redirects: 0,
    }),
    "utf8",
  );

  const result = await runAuthorizedWebObservation(
    projectRoot,
    "http://127.0.0.1:8080/",
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "HTTP_REJECTED");
});

test("OpenCode 工具从自身位置读取项目配置，不依赖会话目录", async () => {
  const output = await authorizedWebObserveTool.execute(
    { url: "http://example.com/" },
    {
      sessionID: "test-session",
      messageID: "test-message",
      agent: "web-security-agent",
      directory: "D:\\",
      worktree: "D:\\",
      abort: new AbortController().signal,
      metadata() {},
      async ask() {},
    },
  );

  assert.equal(typeof output, "string");
  const result = JSON.parse(output as string) as {
    code: string;
    reason: string;
  };
  assert.equal(result.code, "HTTP_REJECTED");
  assert.doesNotMatch(result.reason, /无法读取项目授权配置/u);
});
