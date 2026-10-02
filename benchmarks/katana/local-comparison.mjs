import { createHash } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import { connect as netConnect } from "node:net";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { runWebCrawl } from "../../src/workflows/web-crawl.ts";

const katanaPath = process.argv[2];
if (!katanaPath) {
  console.error("用法：node benchmarks/katana/local-comparison.mjs <katana.exe 绝对路径>");
  process.exit(2);
}

const requestLimit = 20;
const entries = [];
let phase = "baseline";
let mainPort;
let outsidePort;
let proxyPort;
let proxyAttempts = 0;
let proxyConnects = 0;
let blockedProxyAttempts = 0;
const blockedProxyTargets = [];
let directCandidateRequests = 0;
let candidateAttempts = 0;
const tunnelPorts = new Set();
const servers = [];
const tempRoot = await mkdtemp(path.join(os.tmpdir(), "pveil-katana-bench-"));

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      servers.push(server);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise(resolve => server.close(resolve));
}

function runProcess(file, args, timeoutMs = 45000) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, NO_PROXY: "" } });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", code => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timed_out: child.killed });
    });
  });
}

try {
  const outside = createServer((req, res) => {
    entries.push({ phase, host: "outside", path: req.url, status: 200 });
    res.writeHead(200, { "content-type": "text/html" });
    res.end("outside");
  });
  outsidePort = await listen(outside);

  const fixture = createServer((req, res) => {
    if (phase === "candidate") {
      candidateAttempts++;
      if (!tunnelPorts.has(req.socket.remotePort) && req.headers["x-pveil-benchmark-proxy"] !== "1") {
        directCandidateRequests++;
        res.writeHead(403).end("proxy required");
        return;
      }
      if (candidateAttempts > requestLimit) {
        res.writeHead(429).end("benchmark request limit");
        return;
      }
    }
    const pathname = new URL(req.url, "http://127.0.0.1").pathname;
    const status = pathname === "/redirect" ? 302 : pathname === "/missing" ? 404 : 200;
    entries.push({ phase, host: "fixture", path: req.url, status });
    if (pathname === "/redirect") {
      res.writeHead(302, { location: "/final" });
      res.end();
    } else if (pathname === "/") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(`<a href="/html">html</a><a href="/redirect">redirect</a>
        <a href="/search?q=seed">search</a><a href="/missing">missing</a>
        <a href="/logout">logout</a>
        <a href="http://127.0.0.1:${outsidePort}/outside">outside</a>
        <script src="/app.js"></script>`);
    } else if (pathname === "/html") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end('<a href="/deep">deep</a>');
    } else if (pathname === "/app.js") {
      res.writeHead(200, { "content-type": "application/javascript" });
      res.end('fetch("/api?item=1");');
    } else if (status === 404) {
      res.writeHead(404, { "content-type": "text/html" });
      res.end("missing");
    } else {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(`<p>${pathname}</p>`);
    }
  });
  mainPort = await listen(fixture);
  const origin = `http://127.0.0.1:${mainPort}`;

  const proxy = createServer((req, res) => {
    proxyAttempts++;
    let target;
    try { target = new URL(req.url); } catch { res.writeHead(400).end(); return; }
    if (proxyAttempts > requestLimit || target.origin !== origin || req.method !== "GET") {
      blockedProxyAttempts++;
      blockedProxyTargets.push({ url: target.href, method: req.method });
      res.writeHead(403).end("benchmark boundary");
      return;
    }
    const upstream = httpRequest(target, {
      method: "GET", headers: { "x-pveil-benchmark-proxy": "1" }, timeout: 5000,
    }, upstreamResponse => {
      res.writeHead(upstreamResponse.statusCode, upstreamResponse.headers);
      upstreamResponse.pipe(res);
    });
    upstream.on("error", () => res.writeHead(502).end());
    upstream.end();
  });
  proxy.on("connect", (req, clientSocket, head) => {
    proxyConnects++;
    if (req.url !== `127.0.0.1:${mainPort}`) {
      blockedProxyAttempts++;
      blockedProxyTargets.push({ url: req.url, method: "CONNECT" });
      clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    const upstream = netConnect(mainPort, "127.0.0.1", () => {
      tunnelPorts.add(upstream.localPort);
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    });
    upstream.on("error", () => clientSocket.destroy());
    clientSocket.on("error", () => upstream.destroy());
    clientSocket.on("close", () => upstream.destroy());
    upstream.on("close", () => tunnelPorts.delete(upstream.localPort));
  });
  proxyPort = await listen(proxy);

  await mkdir(path.join(tempRoot, "configs"));
  await writeFile(path.join(tempRoot, "configs/scope.local.json"), JSON.stringify({
    allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [mainPort],
    allowed_paths: ["/"], denied_paths: ["/logout"],
  }));
  await writeFile(path.join(tempRoot, "configs/http.local.json"), JSON.stringify({
    allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 5000,
    max_response_bytes: 262144, max_redirects: 5,
  }));
  await writeFile(path.join(tempRoot, "configs/crawl.local.json"), JSON.stringify({
    max_pages: 10, max_depth: 2, max_requests: requestLimit, delay_ms: 300,
  }));

  const baselineStart = performance.now();
  const baseline = await runWebCrawl(tempRoot, `${origin}/`);
  const baselineMs = Math.round(performance.now() - baselineStart);
  if (!baseline.ok) throw new Error(`baseline failed: ${baseline.code}`);

  phase = "candidate";
  const escapedOrigin = origin.replaceAll(".", "\\.");
  const candidateStart = performance.now();
  const candidate = await runProcess(katanaPath, [
    "-u", `${origin}/`, "-d", "2", "-s", "breadth-first",
    "-cs", `^${escapedOrigin}/`, "-cos", `^${escapedOrigin}/logout(?:[/?#]|$)`,
    "-c", "1", "-p", "1", "-rl", "3", "-mdp", "20",
    "-timeout", "5", "-retry", "0", "-mrs", "262144", "-ct", "10s",
    "-jc", "-proxy", `http://127.0.0.1:${proxyPort}`,
    "-duc", "-debug", "-nc",
  ], 20000);
  const candidateMs = Math.round(performance.now() - candidateStart);

  const requestSummary = name => {
    const requests = entries.filter(item => item.phase === name && item.host === "fixture");
    const reachable = [...new Set(requests.filter(item => item.status === 200).map(item => item.path))].sort();
    return { count: requests.length, reachable, errors: requests.filter(item => item.status >= 400).map(item => item.path) };
  };
  const baselineSummary = requestSummary("baseline");
  const candidateSummary = requestSummary("candidate");
  const outputUrls = [...new Set(candidate.stdout.split(/\r?\n/u)
    .filter(line => line.startsWith("http://")))].sort();
  const additional = candidateSummary.reachable.filter(url => !baselineSummary.reachable.includes(url));
  const report = {
    fixture: "local static HTML, redirect, query link, external JavaScript, cross-port link",
    katana_version: "v1.7.0",
    katana_binary_sha256: createHash("sha256").update(await readFile(katanaPath)).digest("hex"),
    common_request_limit: requestLimit,
    baseline: { elapsed_ms: baselineMs, workflow_requests: baseline.requests,
      observed_query_endpoints: baseline.input_map.query_endpoints.map(item => ({
        endpoint: item.endpoint, parameters: item.parameter_names,
      })), ...baselineSummary },
    candidate: { elapsed_ms: candidateMs, proxy_http_attempts: proxyAttempts,
      proxy_connects: proxyConnects, blocked_proxy_attempts: blockedProxyAttempts,
      blocked_proxy_targets: blockedProxyTargets,
      total_origin_attempts: candidateAttempts,
      direct_requests_rejected: directCandidateRequests, process_exit: candidate.code,
      timed_out: candidate.timed_out, output_urls: outputUrls, ...candidateSummary },
    additional_reachable_paths: additional,
    outside_origin_requests: entries.filter(item => item.host === "outside").length,
    candidate_stderr: candidate.stderr.trim(),
  };
  console.log(JSON.stringify(report, null, 2));
  if (candidateAttempts > requestLimit || directCandidateRequests || blockedProxyAttempts ||
      report.outside_origin_requests || candidate.code !== 0) {
    process.exitCode = 2;
  }
} finally {
  await Promise.all(servers.reverse().map(close));
  await rm(tempRoot, { recursive: true, force: true });
}
