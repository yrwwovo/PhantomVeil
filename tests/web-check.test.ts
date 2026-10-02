import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import tool from "../.opencode/tools/authorized_web_check.ts";
import { runWebCheck } from "../src/workflows/web-check.ts";
import { generateHeaderCheckReport } from "../src/reporting/header-check-report.ts";
import { verifyEvidenceFile } from "../src/evidence/evidence-store.ts";

async function fixture(t: TestContext) {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-web-check-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const requests: string[] = [];
  const server = createServer((request, response) => {
    requests.push(request.url!);
    if (request.url === "/redirect") {
      response.writeHead(302, { location: "/denied" });
      response.end();
    } else {
      response.writeHead(request.url === "/missing" ? 404 : 200, {
        "content-type": "text/html", "x-test-private": "RAW_HEADER_SECRET",
      });
      response.end("<html>RAW_BODY_SECRET<script>alert(1)</script></html>");
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("没有测试端口");
  await mkdir(path.join(root, "configs"));
  await writeFile(path.join(root, "configs", "scope.local.json"), JSON.stringify({
    allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [address.port],
    allowed_paths: ["/"], denied_paths: ["/denied"],
  }));
  await writeFile(path.join(root, "configs", "http.local.json"), JSON.stringify({
    allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 1000, max_response_bytes: 4096, max_redirects: 2,
  }));
  return { root, requests, url: `http://127.0.0.1:${address.port}/` };
}

test("一键检查只访问一次并生成一份证据和含实际检查结果的中文报告", async t => {
  const { root, requests, url } = await fixture(t);
  const result = await runWebCheck(root, `${url}?password=QUERY_SECRET`);
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(result.code, "WEB_CHECK_COMPLETED");
  assert.equal(requests.length, 1);
  assert.deepEqual(result.result.summary, { pass: 1, review: 3, not_applicable: 1 });
  const report = await readFile(result.trace.report_file, "utf8");
  assert.match(report, /需要复核｜内容安全策略/u);
  assert.ok(report.includes(result.trace.evidence_id));
  assert.match(report, /不是已确认漏洞/u);
  assert.equal((await verifyEvidenceFile(result.trace.evidence_file)).ok, true);
  assert.doesNotMatch(JSON.stringify(result) + report, /RAW_BODY_SECRET|RAW_HEADER_SECRET|QUERY_SECRET/u);
  assert.doesNotMatch(result.user_summary, /EV-|HYP-|RPT-/u);
  assert.equal((await readdir(path.join(root, "evidence", "opencode"))).length, 1);
  assert.equal((await readdir(path.join(root, "reports", "opencode"))).length, 1);
  await assert.rejects(readdir(path.join(root, "hypotheses")), { code: "ENOENT" });
});

test("范围拒绝和配置缺失不连接目标也不生成成功报告", async t => {
  const { root, requests, url } = await fixture(t);
  const denied = await runWebCheck(root, `${url}denied`);
  assert.equal(denied.code, "HTTP_REJECTED");
  assert.equal((denied as { cause?: string }).cause, "SCOPE_DENIED");
  const missing = await runWebCheck(path.join(root, "absent"), url);
  assert.equal(missing.code, "CONFIG_ERROR");
  assert.equal(requests.length, 0);
  await assert.rejects(readdir(path.join(root, "reports")), { code: "ENOENT" });
});

test("一键入口不能通过重定向访问被禁止路径", async t => {
  const { root, requests, url } = await fixture(t);
  const result = await runWebCheck(root, `${url}redirect`);
  assert.equal(result.code, "HTTP_REJECTED");
  assert.deepEqual(requests, ["/redirect"]);
  await assert.rejects(readdir(path.join(root, "evidence")), { code: "ENOENT" });
});

test("报告写入失败保留已保存证据并返回未完成，不重复请求", async t => {
  const { root, requests, url } = await fixture(t);
  await writeFile(path.join(root, "reports"), "block report directory");
  const result = await runWebCheck(root, url);
  assert.equal(result.code, "REPORT_ERROR");
  assert.equal(result.ok, false);
  assert.ok("trace" in result && result.trace);
  assert.equal((await verifyEvidenceFile(result.trace.evidence_file)).ok, true);
  assert.equal(requests.length, 1);
});

test("证据保存失败时停止检查，不产生报告", async t => {
  const { root, url } = await fixture(t);
  await writeFile(path.join(root, "evidence"), "block evidence directory");
  const result = await runWebCheck(root, url);
  assert.equal(result.code, "EVIDENCE_ERROR");
  await assert.rejects(readdir(path.join(root, "reports")), { code: "ENOENT" });
});

test("生成报告前复核证据，修改后的文件不能生成检查报告", async t => {
  const { root, url } = await fixture(t);
  const result = await runWebCheck(root, url);
  assert.ok(result.ok);
  const record = JSON.parse(await readFile(result.trace.evidence_file, "utf8"));
  record.observation.response.headers["content-security-policy"] = "default-src 'self'";
  await writeFile(result.trace.evidence_file, JSON.stringify(record));
  const rejected = await generateHeaderCheckReport(result.trace.evidence_file, path.join(root, "other-reports"));
  assert.equal(rejected.code, "EVIDENCE_INVALID");
  await assert.rejects(readdir(path.join(root, "other-reports")), { code: "ENOENT" });
});

test("404 仍能分析响应头，但中文摘要明确说明不是正常业务页面", async t => {
  const { root, url } = await fixture(t);
  const result = await runWebCheck(root, `${url}missing`);
  assert.ok(result.ok);
  assert.equal(result.result.http_status, 404);
  assert.match(result.user_summary, /错误状态响应/u);
});

test("工具仅需 URL；命令行无参数时打印用法，不启动检查", async () => {
  assert.deepEqual(Object.keys(tool.args), ["url"]);
  const output = await tool.execute({ url: "" }, { directory: "D:/" } as never);
  assert.equal(JSON.parse(output as string).code, "INVALID_INPUT");
  const script = fileURLToPath(new URL("../scripts/web-check.ts", import.meta.url));
  const result = spawnSync(process.execPath, [script], { encoding: "utf8", cwd: tmpdir() });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /用法：npm run scan/u);
});
