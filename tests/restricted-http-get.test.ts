import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import test from "node:test";

import {
  restrictedHttpGet,
  type HttpGetPolicy,
} from "../capabilities/web/restricted-http-get.ts";
import type { ScopeConfig } from "../src/scope/scope-guard.ts";

const basePolicy: HttpGetPolicy = {
  allowed_resolved_ips: ["127.0.0.1"],
  timeout_ms: 1000,
  max_response_bytes: 1024,
  max_redirects: 2,
};

async function startServer(
  handler: Parameters<typeof createServer>[0],
): Promise<{ server: Server; port: number }> {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("测试服务器没有可用端口");
  }
  return { server, port: address.port };
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function scopeFor(port: number, deniedPaths: string[] = []): ScopeConfig {
  return {
    allowed_schemes: ["http"],
    allowed_hosts: ["127.0.0.1"],
    allowed_ports: [port],
    allowed_paths: ["/"],
    denied_paths: deniedPaths,
  };
}

test("对授权的本地目标执行一次 GET", async (context) => {
  const { server, port } = await startServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("hello scope");
  });
  context.after(() => closeServer(server));

  const result = await restrictedHttpGet(
    `http://127.0.0.1:${port}/hello`,
    scopeFor(port),
    basePolicy,
  );

  assert.equal(result.ok, true);
  assert.equal(result.code, "HTTP_RESPONSE");
  assert.equal(result.response?.status, 200);
  assert.equal(result.response?.body, "hello scope");
  assert.equal(result.response?.resolved_ip, "127.0.0.1");
});

test("Scope Guard 拒绝后不连接服务器", async (context) => {
  let requests = 0;
  const { server, port } = await startServer((_request, response) => {
    requests += 1;
    response.end("unexpected");
  });
  context.after(() => closeServer(server));

  const result = await restrictedHttpGet(
    `http://127.0.0.1:${port}/forbidden`,
    { ...scopeFor(port), allowed_paths: ["/allowed"] },
    basePolicy,
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "SCOPE_DENIED");
  assert.equal(requests, 0);
});

test("拒绝未列入策略的实际连接 IP", async (context) => {
  let requests = 0;
  const { server, port } = await startServer((_request, response) => {
    requests += 1;
    response.end("unexpected");
  });
  context.after(() => closeServer(server));

  const result = await restrictedHttpGet(
    `http://127.0.0.1:${port}/`,
    scopeFor(port),
    { ...basePolicy, allowed_resolved_ips: ["192.0.2.10"] },
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "IP_NOT_ALLOWED");
  assert.equal(requests, 0);
});

test("重定向目标重新经过 Scope Guard", async (context) => {
  let deniedPathRequests = 0;
  const { server, port } = await startServer((request, response) => {
    if (request.url === "/start") {
      response.writeHead(302, { location: "/admin/delete" });
      response.end();
      return;
    }
    deniedPathRequests += 1;
    response.end("should not be reached");
  });
  context.after(() => closeServer(server));

  const result = await restrictedHttpGet(
    `http://127.0.0.1:${port}/start`,
    scopeFor(port, ["/admin/delete"]),
    basePolicy,
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "SCOPE_DENIED");
  assert.equal(result.redirects.length, 1);
  assert.equal(deniedPathRequests, 0);
});

test("响应超过大小限制时停止", async (context) => {
  const { server, port } = await startServer((_request, response) => {
    response.end("0123456789");
  });
  context.after(() => closeServer(server));

  const result = await restrictedHttpGet(
    `http://127.0.0.1:${port}/large`,
    scopeFor(port),
    { ...basePolicy, max_response_bytes: 5 },
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "RESPONSE_TOO_LARGE");
});

test("请求超过时间限制时停止", async (context) => {
  const { server, port } = await startServer((_request, response) => {
    setTimeout(() => response.end("late"), 150);
  });
  context.after(() => closeServer(server));

  const result = await restrictedHttpGet(
    `http://127.0.0.1:${port}/slow`,
    scopeFor(port),
    { ...basePolicy, timeout_ms: 30 },
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "TIMEOUT");
});
