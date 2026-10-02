import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { restrictedHttpGet, validatePolicy } from "../../capabilities/web/restricted-http-get.ts";
import { validateScopeConfig } from "../../src/scope/scope-guard.ts";

// 只供 Docker 内部网络的本地对照实验使用；不监听宿主机端口。
const scope = {
  allowed_schemes: ["http"], allowed_hosts: ["fixture"], allowed_ports: [8000],
  allowed_paths: ["/"], denied_paths: ["/forbidden", "/metrics"],
};
const policy = {
  allowed_resolved_ips: ["172.30.90.10"], timeout_ms: 5000,
  max_response_bytes: 262144, max_redirects: 3,
};
const maxRequests = Number(process.env.GATE_MAX_REQUESTS ?? "4");
if (!validateScopeConfig(scope).valid || validatePolicy(policy) || !Number.isInteger(maxRequests) ||
    maxRequests < 1 || maxRequests > 20) {
  throw new Error("门禁配置无效");
}

let networkAttempts = 0;
let clientRequests = 0;
const log = event => console.log(JSON.stringify(event));
const digest = value => createHash("sha256").update(value).digest("hex").slice(0, 16);

function reply(res, status, code, body = "") {
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "x-pveil-gate-code": code,
    "x-pveil-network-attempts": String(networkAttempts),
    "cache-control": "no-store",
  });
  res.end(body);
}

const server = createServer(async (req, res) => {
  const id = ++clientRequests;
  const urlHash = digest(req.url ?? "");
  if (req.method !== "GET" || req.headers["content-length"] || req.headers["transfer-encoding"]) {
    reply(res, 405, "METHOD_DENIED");
    log({ id, url_hash: urlHash, code: "METHOD_DENIED", network_attempts: networkAttempts });
    return;
  }
  let target;
  try {
    target = new URL(req.url);
    if (target.protocol !== "http:") throw new Error();
  } catch {
    reply(res, 400, "INVALID_TARGET");
    log({ id, url_hash: urlHash, code: "INVALID_TARGET", network_attempts: networkAttempts });
    return;
  }

  let result;
  try {
    result = await restrictedHttpGet(target.href, scope, policy, {
      before_request: async () => {
        if (networkAttempts >= maxRequests) return "任务请求预算已用尽";
        networkAttempts++;
        return undefined;
      },
    });
  } catch {
    reply(res, 502, "GATE_ERROR");
    log({ id, url_hash: urlHash, code: "GATE_ERROR", network_attempts: networkAttempts });
    return;
  }
  const status = result.ok && result.response ? result.response.status
    : result.code === "REQUEST_BLOCKED" ? 429 : 403;
  const body = result.ok && result.response ? result.response.body : "";
  const contentType = result.ok && result.response ? result.response.headers["content-type"] : undefined;
  res.writeHead(status, {
    "content-type": typeof contentType === "string" ? contentType : "text/plain; charset=utf-8",
    "x-pveil-gate-code": result.code,
    "x-pveil-network-attempts": String(networkAttempts),
    "cache-control": "no-store",
  });
  res.end(body);
  log({ id, url_hash: urlHash, code: result.code, status,
    redirect_count: result.redirects.length, network_attempts: networkAttempts });
});

server.on("connect", (req, socket) => {
  const id = ++clientRequests;
  socket.end("HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
  log({ id, url_hash: digest(req.url ?? ""), code: "CONNECT_DENIED",
    network_attempts: networkAttempts });
});

server.on("upgrade", (req, socket) => {
  const id = ++clientRequests;
  socket.end("HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
  log({ id, url_hash: digest(req.url ?? ""), code: "UPGRADE_DENIED",
    network_attempts: networkAttempts });
});

server.listen(8787, "0.0.0.0", () => log({ code: "READY", max_requests: maxRequests }));
