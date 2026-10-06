import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { chooseOpenCodeCandidate, PHANTOMVEIL_AGENT, runPveil } from "../src/cli/pveil.ts";

const PROJECT_ROOT = path.resolve(import.meta.dirname, "..");

function writer() {
  let text = "";
  return {
    stream: { write(value: string) { text += value; return true; } },
    read: () => text,
  };
}

test("Windows 命令定位优先选择可执行扩展名而不是无扩展名 npm shim", () => {
  assert.equal(chooseOpenCodeCandidate([
    "C:/old/opencode",
    "C:/old/opencode.cmd",
    "D:/new/opencode.exe",
  ]), "D:/new/opencode.exe");
  assert.equal(chooseOpenCodeCandidate([
    "C:/old/opencode",
    "C:/old/opencode.cmd",
  ]), "C:/old/opencode.cmd");
});

test("TUI 首页加载可替换的 PhantomVeil 品牌组件", async () => {
  const config = JSON.parse(await readFile(
    path.join(PROJECT_ROOT, ".opencode", "phantomveil-tui.json"),
    "utf8",
  )) as { plugin?: string[]; theme?: string };
  const pluginPath = config.plugin?.[0];
  assert.equal(pluginPath, "./tui-plugins/phantomveil-brand.tsx");
  assert.equal(config.theme, "phantomveil");

  const theme = await readFile(
    path.join(PROJECT_ROOT, ".opencode", "themes", "phantomveil.json"),
    "utf8",
  );
  assert.match(theme, /#C4A7E7/u);
  assert.doesNotMatch(theme, /#(?:8FD3C7|88C0D0|8FBCBB)/iu);

  const plugin = await readFile(
    path.join(PROJECT_ROOT, ".opencode", "tui-plugins", "phantomveil-brand.tsx"),
    "utf8",
  );
  assert.match(plugin, /home_logo/u);
  assert.match(plugin, /PhantomVeil/u);
  assert.match(plugin, /setTerminalTitle\(WINDOW_TITLE\)/u);
  assert.match(plugin, /const WINDOW_TITLE = "PhantomVeil"/u);
  assert.match(plugin, /context\.theme\.current\.primary/u);
  assert.doesNotMatch(plugin, /fetch\s*\(|node:(?:http|https|net|child_process)/u);
});

test("pveil 无参数时以受限 Agent 启动 OpenCode TUI", async () => {
  const stdout = writer();
  const stderr = writer();
  let invocation: { command: string; args: string[]; cwd: string; env: NodeJS.ProcessEnv } | undefined;
  const status = await runPveil("D:/example/project", [], {
    stdout: stdout.stream,
    stderr: stderr.stream,
    env: { TEST_ONLY: "1" },
    locateOpenCode: () => "C:/tools/opencode.exe",
    launchOpenCode: (command, args, options) => {
      invocation = { command, args, cwd: options.cwd, env: options.env };
      return { status: 0 };
    },
  });

  assert.equal(status, 0);
  assert.match(stdout.read(), /Phant0mV3il/u);
  assert.equal(stderr.read(), "");
  assert.equal(invocation?.command, "C:/tools/opencode.exe");
  assert.deepEqual(invocation?.args, ["D:\\example\\project", "--agent", PHANTOMVEIL_AGENT]);
  assert.equal(invocation?.cwd, "D:\\example\\project");
  assert.match(invocation?.env.OPENCODE_TUI_CONFIG ?? "", /phantomveil-tui\.json$/u);
  assert.equal(invocation?.args.includes("--auto"), false);
});

test("pveil 显式 Hermes 任务只转交隔离启动器，不调用 OpenCode", async () => {
  const stdout = writer();
  const stderr = writer();
  let hermes: { script: string; args: string[]; cwd: string } | undefined;
  let openCodeCalled = false;
  const status = await runPveil("D:/example/project", ["chat", "--runtime", "hermes",
    "--url", "http://127.0.0.1:5000/", "--authorization-reference", "LAB-REF",
    "--assessment"], {
    stdout: stdout.stream, stderr: stderr.stream,
    env: { DEEPSEEK_API_KEY: "fixture-only" },
    locateOpenCode: () => { openCodeCalled = true; return "C:/tools/opencode.exe"; },
    launchOpenCode: () => { openCodeCalled = true; return { status: 0 }; },
    launchHermesTask: (script, args, options) => {
      hermes = { script, args, cwd: options.cwd };
      return { status: 0 };
    },
  });
  assert.equal(status, 0);
  assert.equal(openCodeCalled, false);
  assert.equal(stderr.read(), "");
  assert.equal(hermes?.script, "D:\\example\\project\\scripts\\hermes-chat.mjs");
  assert.deepEqual(hermes?.args, ["--url", "http://127.0.0.1:5000/",
    "--authorization-reference", "LAB-REF", "--assessment"]);
  assert.equal(hermes?.cwd, "D:\\example\\project");
});

test("Hermes 入口在密钥缺失、无效目标或只读新目标叠加主动模式时拒绝", async () => {
  const stderr = writer();
  let launched = false;
  const common = { stdout: writer().stream, stderr: stderr.stream,
    launchHermesTask: () => { launched = true; return { status: 0 }; } };
  assert.equal(await runPveil(".", ["chat", "--runtime", "hermes",
    "--url", "http://127.0.0.1:5000/", "--authorization-reference", "LAB-REF"],
  { ...common, env: {} }), 2);
  assert.match(stderr.read(), /DEEPSEEK_API_KEY/u);
  assert.equal(await runPveil(".", ["chat", "--runtime", "hermes",
    "--url", "https://example.test/#fragment", "--authorization-reference", "LAB-REF"],
  { ...common, env: { DEEPSEEK_API_KEY: "fixture-only" } }), 2);
  assert.equal(await runPveil(".", ["chat", "--runtime", "hermes",
    "--url", "http://127.0.0.1:5000/", "--new-target", "--assessment"],
  { ...common, env: { DEEPSEEK_API_KEY: "fixture-only" } }), 2);
  assert.equal(launched, false);
});

test("pveil 显式 OpenCode 回退保持原受限 TUI 配置", async () => {
  let args: string[] = [];
  const status = await runPveil("D:/example/project", ["chat", "--runtime", "opencode"], {
    stdout: writer().stream, stderr: writer().stream,
    locateOpenCode: () => "C:/tools/opencode.exe",
    launchOpenCode: (_command, received, options) => {
      args = received;
      assert.match(options.env.OPENCODE_TUI_CONFIG ?? "", /phantomveil-tui\.json$/u);
      return { status: 0 };
    },
  });
  assert.equal(status, 0);
  assert.deepEqual(args, ["D:\\example\\project", "--agent", PHANTOMVEIL_AGENT]);
});

test("缺少 OpenCode CLI 时明确拒绝，不尝试替代网络或 Shell 能力", async () => {
  const stderr = writer();
  let launched = false;
  const status = await runPveil(".", [], {
    stderr: stderr.stream,
    stdout: writer().stream,
    locateOpenCode: () => undefined,
    launchOpenCode: () => { launched = true; return { status: 0 }; },
  });
  assert.equal(status, 2);
  assert.equal(launched, false);
  assert.match(stderr.read(), /未找到 OpenCode CLI/u);
  assert.match(stderr.read(), /1\.18\.29/u);
});

test("check 和 crawl 只转交给现有工作流", async () => {
  const stdout = writer();
  const calls: string[] = [];
  const common = {
    stdout: stdout.stream,
    stderr: writer().stream,
    runCheck: async (_root: string, url: string) => {
      calls.push(`check:${url}`);
      return { ok: true as const, code: "WEB_CHECK_COMPLETED", user_summary: "单页完成", result: {} as never,
        trace: { evidence_id: "EV-test", evidence_file: "evidence.json", report_id: "RPT-test", report_file: "report.md" } };
    },
    runCrawl: async (_root: string, url: string) => {
      calls.push(`crawl:${url}`);
      return { ok: true as const, code: "CRAWL_COMPLETED", user_summary: "爬取完成", report_file: "crawl.md" } as never;
    },
  };

  assert.equal(await runPveil(".", ["check", "http://127.0.0.1/"], common), 0);
  assert.equal(await runPveil(".", ["crawl", "http://127.0.0.1/"], common), 0);
  assert.deepEqual(calls, ["check:http://127.0.0.1/", "crawl:http://127.0.0.1/"]);
  assert.match(stdout.read(), /单页完成[\s\S]*report\.md[\s\S]*爬取完成[\s\S]*crawl\.md/u);
});

test("未知参数和缺失 URL 在执行工作流前被拒绝", async () => {
  let called = false;
  const dependencies = {
    stdout: writer().stream,
    stderr: writer().stream,
    runCheck: async () => { called = true; return {} as never; },
    runCrawl: async () => { called = true; return {} as never; },
  };
  assert.equal(await runPveil(".", ["unknown"], dependencies), 2);
  assert.equal(await runPveil(".", ["check"], dependencies), 2);
  assert.equal(called, false);
});
