import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { performance } from "node:perf_hooks";
import { extractPageLinks } from "../capabilities/web/crawl-links.ts";
import { runWebCrawl } from "../src/workflows/web-crawl.ts";
import tool from "../.opencode/tools/authorized_web_crawl.ts";
import { verifyEvidenceFile } from "../src/evidence/evidence-store.ts";

async function fixture(t: TestContext, handler: (url: string, res: ServerResponse) => void,
  limits: Record<string, number> = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-crawl-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const hits: { url: string; at: number }[] = [];
  const server = createServer((req, res) => { hits.push({ url: req.url!, at: performance.now() }); handler(req.url!, res); });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("没有测试端口");
  const url = `http://127.0.0.1:${address.port}/`;
  await mkdir(path.join(root, "configs"));
  await writeFile(path.join(root, "configs/scope.local.json"), JSON.stringify({
    allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1", "localhost"],
    allowed_ports: [address.port], allowed_paths: ["/"], denied_paths: ["/denied"],
  }));
  await writeFile(path.join(root, "configs/http.local.json"), JSON.stringify({
    allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 1000, max_response_bytes: 4096, max_redirects: 3,
  }));
  await writeFile(path.join(root, "configs/crawl.local.json"), JSON.stringify({
    max_pages: 10, max_depth: 2, max_requests: 20, delay_ms: 100, ...limits,
  }));
  return { root, url, hits };
}

function html(res: ServerResponse, body: string) { res.writeHead(200, { "content-type": "text/html" }); res.end(body); }

test("HTML 解析器处理实体、base、大小写；不会误读脚本、注释、模板和下载链接", () => {
  const result = extractPageLinks(`<base href='/app/'><BASE href='/ignored/'>
    <A HREF='p&#97;ge'>x</A><!-- <a href='/fake'> -->
    <script>"<a href='/script'>"</script><template><a href='/template'></template>
    <a download href='/download'>file</a><form action='/submit'></form>`, "http://example.test/");
  assert.equal(result.base_url, "http://example.test/app/");
  assert.deepEqual(result.links, ["page"]);
});

test("链接文字只保留短标签，不带脚本或控制字符", () => {
  const parsed = extractPageLinks(`<a href='/one'>进入 <b>检索</b><script>ignore me</script></a>
    <a href='/two' aria-label='帮助\u0001中心'></a><a href='/three'>${"x".repeat(200)}</a>`,
    "http://example.test/");
  assert.deepEqual(parsed.choices.map(choice => choice.label), ["进入 检索", "帮助 中心", "x".repeat(80)]);
});

test("发现相对链接并去重；查询、禁止路径、跨源和表单不会被访问", async t => {
  const f = await fixture(t, (url, res) => html(res, url === "/" ? `
    <a href='/a#one'>a</a><a href='/a#two'>a2</a><a href='/a?token=SECRET'>q</a>
    <a href='/denied'>no</a><a href='https://evil.example/'>out</a>
    <form action='/submit'><input></form><script>fetch('/script')</script>` : "<a href='/'>home</a>"));
  const result = await runWebCrawl(f.root, f.url);
  assert.ok(result.ok, JSON.stringify(result));
  assert.ok("pages" in result);
  assert.deepEqual(f.hits.map(h => h.url), ["/", "/a"]);
  assert.equal(result.checked, 2);
  assert.doesNotMatch(JSON.stringify(result), /SECRET|fetch\(/u);
  for (const p of result.pages) assert.ok((await verifyEvidenceFile(p.evidence_file!)).ok);
  assert.ok("report_file" in result);
  assert.match(await readFile(result.report_file, "utf8"), /不代表已覆盖全站/u);
  assert.equal(f.hits[1].at - f.hits[0].at >= 80, true);
  await assert.rejects(readdir(path.join(f.root, "hypotheses")), { code: "ENOENT" });
});

test("多页静态表单和查询参数会汇总，但不会提交或保留参数值", async t => {
  const f = await fixture(t, (url, res) => html(res, url === "/" ? `
    <form action='/login?flow=SECRET_FLOW' method='post'>
      <input name='username' value='SECRET_USER'><input name='password' type='password'>
    </form>
    <a href='/next'>next</a><a href='/search?q=SECRET_QUERY&lang=zh'>search</a>` : `
    <form action='/login' method='post'><input name='otp'></form>
    <form action='https://outside.example/upload' method='post'><input name='file' type='file'></form>
    <a href='/search?page=2&q=OTHER_SECRET'>search</a>`));
  const result = await runWebCrawl(f.root, f.url);
  assert.ok(result.ok, JSON.stringify(result));
  assert.deepEqual(f.hits.map(hit => hit.url), ["/", "/next"]);
  assert.deepEqual(result.input_map.summary, {
    pages_with_inputs: 2,
    forms_observed: 3,
    controls_observed: 4,
    unique_form_actions: 2,
    unique_query_endpoints: 1,
  });
  const login = result.input_map.forms.find(form => form.endpoint?.endsWith("/login"));
  assert.deepEqual(login?.parameter_names, ["flow", "username", "password", "otp"]);
  assert.equal(result.input_map.forms.find(form => form.endpoint?.includes("outside.example"))?.same_origin, false);
  assert.deepEqual(result.input_map.query_endpoints[0].parameter_names, ["q", "lang", "page"]);
  assert.doesNotMatch(JSON.stringify(result), /SECRET_FLOW|SECRET_USER|SECRET_QUERY|OTHER_SECRET/u);
  assert.match(await readFile(result.report_file, "utf8"), /静态表单与参数入口/u);
});

test("页面与深度限制分别生效，深度 0 只观察起始页面", async t => {
  const f = await fixture(t, (_url, res) => html(res, "<a href='/a'>a</a><a href='/b'>b</a>"), { max_pages: 1 });
  const result = await runWebCrawl(f.root, f.url);
  assert.ok("stop_reason" in result);
  assert.equal(result.stop_reason, "page_limit");
  assert.equal(f.hits.length, 1);
  await writeFile(path.join(f.root, "configs/crawl.local.json"), JSON.stringify({max_pages:10,max_depth:0,max_requests:20,delay_ms:100}));
  const shallow = await runWebCrawl(f.root, f.url);
  assert.ok("skipped" in shallow);
  assert.equal(shallow.skipped.depth_limit, 2);
  assert.equal(f.hits.length, 2);
});

test("每个重定向消耗预算且限速，预算用尽不发送下一跳", async t => {
  const f = await fixture(t, (url, res) => {
    res.writeHead(302, { location: url === "/" ? "/next" : "/final" }); res.end();
  }, { max_requests: 2 });
  const result = await runWebCrawl(f.root, f.url);
  assert.ok("stop_reason" in result);
  assert.equal(result.stop_reason, "request_limit");
  assert.equal(result.requests, 2);
  assert.deepEqual(f.hits.map(h => h.url), ["/", "/next"]);
  assert.ok(f.hits[1].at - f.hits[0].at >= 80);
});

test("即使全局 Scope 允许另一个主机，同源限制仍阻止跨源重定向", async t => {
  let location = "";
  const f = await fixture(t, (_url, res) => { res.writeHead(302, { location }); res.end(); });
  location = f.url.replace("127.0.0.1", "localhost");
  const result = await runWebCrawl(f.root, f.url);
  assert.ok("pages" in result);
  assert.equal(result.pages[0].code, "origin_or_query_blocked");
  assert.equal(f.hits.length, 1);
});

test("禁止路径与带查询参数的重定向不会发出后续请求", async t => {
  let location = "/denied";
  const f = await fixture(t, (_url, res) => { res.writeHead(302, { location }); res.end(); });
  const denied = await runWebCrawl(f.root, f.url);
  assert.ok("pages" in denied);
  assert.equal(denied.pages[0].code, "SCOPE_DENIED");
  location = "/search?q=SECRET";
  const query = await runWebCrawl(f.root, f.url);
  assert.ok("pages" in query);
  assert.equal(query.pages[0].code, "origin_or_query_blocked");
  assert.doesNotMatch(JSON.stringify(query), /SECRET/u);
  assert.equal(f.hits.length, 2);
});

test("跨源 base、非 HTML 和 404 中的链接不扩展爬取", async t => {
  let mode = 0;
  const f = await fixture(t, (_url, res) => {
    res.writeHead(mode === 2 ? 404 : 200, { "content-type": mode === 1 ? "application/json" : "text/html" });
    res.end(mode === 0 ? "<base href='https://evil.example/'><a href='out'>out</a>" : "<a href='/extra'>extra</a>");
  });
  for (mode = 0; mode < 3; mode++) await runWebCrawl(f.root, f.url);
  assert.deepEqual(f.hits.map(h => h.url), ["/", "/", "/"]);
});

test("错误配置、入口查询参数和未授权起点在连接前拒绝", async t => {
  const f = await fixture(t, (_url, res) => html(res, "hello"));
  assert.equal((await runWebCrawl(f.root, `${f.url}?secret=1`)).code, "INVALID_INPUT");
  assert.equal((await runWebCrawl(f.root, `${f.url}denied`)).code, "SCOPE_DENIED");
  await writeFile(path.join(f.root, "configs/crawl.local.json"), JSON.stringify({max_pages:999,max_depth:2,max_requests:20,delay_ms:0}));
  assert.equal((await runWebCrawl(f.root, f.url)).code, "CONFIG_ERROR");
  assert.equal(f.hits.length, 0);
});

test("重定向循环不会重复访问已请求 URL", async t => {
  const f = await fixture(t, (url, res) => { res.writeHead(302, {location: url === "/" ? "/loop" : "/"}); res.end(); });
  const result = await runWebCrawl(f.root, f.url);
  assert.ok("pages" in result);
  assert.equal(result.pages[0].code, "duplicate");
  assert.deepEqual(f.hits.map(h=>h.url), ["/", "/loop"]);
});

test("持续输出小块响应也会被请求总超时终止", async t => {
  const f = await fixture(t, (_url, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    const timer = setInterval(() => res.write("x"), 20);
    res.once("close", () => clearInterval(timer));
  });
  await writeFile(path.join(f.root, "configs/http.local.json"), JSON.stringify({allowed_resolved_ips:["127.0.0.1"],timeout_ms:120,max_response_bytes:4096,max_redirects:0}));
  const result = await runWebCrawl(f.root, f.url);
  assert.ok("pages" in result);
  assert.equal(result.pages[0].code, "TIMEOUT");
});

test("OpenCode 爬虫只接收 URL，不允许模型增大预算", async () => {
  assert.deepEqual(Object.keys(tool.args), ["url"]);
  const output = await tool.execute({url:"not a url"}, {} as never);
  assert.equal(JSON.parse(output as string).code, "INVALID_INPUT");
});

test("响应体超限会留下失败记录；证据保存失败会停止后续爬取", async t => {
  const f = await fixture(t, (_url, res) => html(res, "<a href='/next'>next</a>" + "x".repeat(5000)));
  const large = await runWebCrawl(f.root, f.url);
  assert.ok("pages" in large);
  assert.equal(large.pages[0].code, "RESPONSE_TOO_LARGE");
  assert.equal(f.hits.length, 1);
  await writeFile(path.join(f.root, "configs/http.local.json"), JSON.stringify({allowed_resolved_ips:["127.0.0.1"],timeout_ms:1000,max_response_bytes:10000,max_redirects:0}));
  await writeFile(path.join(f.root, "evidence"), "block directory");
  const blocked = await runWebCrawl(f.root, f.url);
  assert.ok("stop_reason" in blocked);
  assert.equal(blocked.stop_reason, "storage_error");
  assert.equal(blocked.ok, false);
  assert.equal(f.hits.length, 2);
});

test("发现队列和每页提取链接都有上限，重复重定向目标不再读取", async t => {
  const extracted = extractPageLinks(Array.from({length:250}, (_, i) => `<a href='/p${i}'>x</a>`).join(""), "http://example.test/");
  assert.equal(extracted.links.length, 200);
  assert.equal(extracted.truncated, true);
  const f = await fixture(t, (url, res) => {
    if (url === "/") html(res, "<a href='/go'>go</a><a href='/final'>final</a>");
    else if (url === "/go") { res.writeHead(302, {location:"/final"}); res.end(); }
    else html(res, "done");
  });
  const result = await runWebCrawl(f.root, f.url);
  assert.ok(result.ok);
  assert.deepEqual(f.hits.map(h => h.url), ["/", "/go", "/final"]);
});
