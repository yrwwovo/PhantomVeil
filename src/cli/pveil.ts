import { spawnSync } from "node:child_process";
import path from "node:path";

import { runWebCheck } from "../workflows/web-check.ts";
import { runWebCrawl } from "../workflows/web-crawl.ts";

export const PHANTOMVEIL_TITLE = "Phant0mV3il";
export const PHANTOMVEIL_PRODUCT_NAME = "PhantomVeil";
export const PHANTOMVEIL_AGENT = "Phant0mV3il";

type TextWriter = Pick<NodeJS.WriteStream, "write">;

interface LaunchResult {
  status: number | null;
  error?: Error;
}

export interface PveilDependencies {
  env?: NodeJS.ProcessEnv;
  stdout?: TextWriter;
  stderr?: TextWriter;
  locateOpenCode?: (env: NodeJS.ProcessEnv) => string | undefined;
  launchOpenCode?: (
    command: string,
    args: string[],
    options: { cwd: string; env: NodeJS.ProcessEnv },
  ) => LaunchResult;
  launchHermesTask?: (
    script: string,
    args: string[],
    options: { cwd: string; env: NodeJS.ProcessEnv },
  ) => LaunchResult;
  runCheck?: typeof runWebCheck;
  runCrawl?: typeof runWebCrawl;
}

export function chooseOpenCodeCandidate(candidates: string[]): string | undefined {
  for (const extension of [".exe", ".cmd", ".bat"]) {
    const candidate = candidates.find(value => value.toLowerCase().endsWith(extension));
    if (candidate) return candidate;
  }
  return candidates[0];
}

const HELP = `${PHANTOMVEIL_TITLE} - 授权 Web 安全 Agent

用法：
  pveil                  进入 OpenCode 终端对话界面
  pveil chat             进入 OpenCode 终端对话界面
  pveil chat --runtime opencode
                         显式进入 OpenCode（回退入口）
  pveil chat --runtime hermes --url <URL> --authorization-reference <REF> [--crawl|--reflection|--redirect|--encoding|--assessment]
                         进入本次授权的 Hermes PhantomVeil 任务
  pveil chat --runtime hermes --url <URL> --new-target
                         登记一个只读目标并进入 Hermes
  pveil check <URL>      执行一次受限单页检查（无需 LLM）
  pveil crawl <URL>      执行受限同源爬取（无需 LLM）
  pveil --help           显示帮助

安全边界：所有目标访问继续经过 Scope Guard；本入口不会扩大授权范围。
`;

const BANNER = `
  ╭────────────────────────────────────────╮
  │              ${PHANTOMVEIL_TITLE}              │
  │       Authorized Security Agent        │
  ╰────────────────────────────────────────╯
`;

function writeLine(writer: TextWriter, value: string): void {
  writer.write(value.endsWith("\n") ? value : `${value}\n`);
}

/** 查找已安装的 OpenCode CLI；OPENCODE_BIN 可显式指定独立可执行文件。 */
export function locateOpenCode(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const explicit = env.OPENCODE_BIN?.trim();
  if (explicit) return explicit;

  const locator = process.platform === "win32" ? "where.exe" : "which";
  const located = spawnSync(locator, ["opencode"], {
    encoding: "utf8",
    windowsHide: true,
    env,
  });
  if (located.status !== 0 || !located.stdout) return undefined;
  const candidates = located.stdout.split(/\r?\n/u).map(value => value.trim()).filter(Boolean);
  return chooseOpenCodeCandidate(candidates);
}

/** 保持 stdio 直连，使 OpenCode 的全屏 TUI 可以正常接管当前终端。 */
export function launchOpenCode(
  command: string,
  args: string[],
  options: { cwd: string; env: NodeJS.ProcessEnv },
): LaunchResult {
  if (process.platform === "win32" && /\.(?:cmd|bat)$/iu.test(command)) {
    // npm 在 Windows 上生成 .cmd shim；用 call 让 cmd.exe 可靠地传递带空格路径。
    const result = spawnSync(options.env.ComSpec || "cmd.exe", ["/d", "/c", "call", command, ...args], {
      cwd: options.cwd,
      env: options.env,
      stdio: "inherit",
      windowsHide: false,
    });
    return { status: result.status, error: result.error };
  }

  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: "inherit",
    windowsHide: false,
  });
  return { status: result.status, error: result.error };
}

/** Hermes task launcher owns the isolated profile and all task-level checks. */
export function launchHermesTask(
  script: string,
  args: string[],
  options: { cwd: string; env: NodeJS.ProcessEnv },
): LaunchResult {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: options.cwd,
    env: options.env,
    stdio: "inherit",
    windowsHide: false,
  });
  return { status: result.status, error: result.error };
}

function parseHermesChatArgs(args: string[]): string[] | undefined {
  if (args.length < 3 || args[0] !== "--url") return undefined;
  const url = args[1];
  let target: URL;
  try { target = new URL(url); } catch { return undefined; }
  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password ||
      target.hash || target.href !== url) return undefined;
  const newTarget = args[2] === "--new-target";
  const expected = newTarget ? 3 : 4;
  if (!newTarget && (args[2] !== "--authorization-reference" || !args[3]?.trim())) return undefined;
  if (![expected, expected + 1].includes(args.length)) return undefined;
  const mode = args[expected];
  if (mode && !["--crawl", "--reflection", "--redirect", "--encoding", "--assessment"].includes(mode)) {
    return undefined;
  }
  if (newTarget && mode) return undefined;
  if ((mode || newTarget) && target.search) return undefined;
  return args;
}

async function runDeterministicCommand(
  command: "check" | "crawl",
  args: string[],
  projectRoot: string,
  dependencies: Required<Pick<PveilDependencies, "stdout" | "stderr" | "runCheck" | "runCrawl">>,
): Promise<number> {
  if (args.length !== 1) {
    writeLine(dependencies.stderr, `用法：pveil ${command} http://127.0.0.1:5000/`);
    return 2;
  }

  const result = command === "check"
    ? await dependencies.runCheck(projectRoot, args[0])
    : await dependencies.runCrawl(projectRoot, args[0]);
  writeLine(dependencies[result.ok ? "stdout" : "stderr"], "user_summary" in result ? result.user_summary : result.reason);
  if ("report_file" in result) writeLine(dependencies.stdout, `报告：${result.report_file}`);
  if ("trace" in result && result.trace && "report_file" in result.trace) {
    writeLine(dependencies.stdout, `报告：${result.trace.report_file}`);
  }
  return result.ok ? 0 : 2;
}

/** `pveil` 的最小入口：对话复用 OpenCode，检查命令复用现有确定性工作流。 */
export async function runPveil(
  projectRoot: string,
  args: string[],
  dependencies: PveilDependencies = {},
): Promise<number> {
  const root = path.resolve(projectRoot);
  const env = dependencies.env ?? process.env;
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  const locate = dependencies.locateOpenCode ?? locateOpenCode;
  const launch = dependencies.launchOpenCode ?? launchOpenCode;
  const launchHermes = dependencies.launchHermesTask ?? launchHermesTask;
  const runCheck = dependencies.runCheck ?? runWebCheck;
  const runCrawl = dependencies.runCrawl ?? runWebCrawl;

  if (args[0] === "--help" || args[0] === "-h" || args[0] === "help") {
    writeLine(stdout, HELP);
    return 0;
  }
  if (args[0] === "check" || args[0] === "crawl") {
    return runDeterministicCommand(args[0], args.slice(1), root, { stdout, stderr, runCheck, runCrawl });
  }
  if (args[0] === "chat" && args[1] === "--runtime" && args[2] === "hermes") {
    const taskArgs = parseHermesChatArgs(args.slice(3));
    if (!taskArgs) {
      writeLine(stderr, "Hermes 任务参数无效。使用 pveil --help 查看用法；新目标只能登记只读任务。");
      return 2;
    }
    if (!env.DEEPSEEK_API_KEY?.trim()) {
      writeLine(stderr, "当前终端缺少 DEEPSEEK_API_KEY；请仅在本机进程环境中设置，不要作为命令参数传入。");
      return 2;
    }
    const script = path.join(root, "scripts", "hermes-chat.mjs");
    const result = launchHermes(script, taskArgs, { cwd: root, env });
    if (result.error) {
      writeLine(stderr, `Hermes 任务启动失败：${result.error.message}`);
      return 2;
    }
    return result.status ?? 2;
  }
  const openCodeChat = args.length === 0 ||
    (args.length === 1 && args[0] === "chat") ||
    (args.length === 3 && args[0] === "chat" && args[1] === "--runtime" && args[2] === "opencode");
  if (!openCodeChat) {
    writeLine(stderr, `未知参数：${args.join(" ")}。使用 pveil --help 查看可用命令。`);
    return 2;
  }

  const openCode = locate(env);
  if (!openCode) {
    writeLine(stderr, "未找到 OpenCode CLI。请先安装与项目兼容的 OpenCode，或用 OPENCODE_BIN 指定可执行文件。");
    writeLine(stderr, "当前已验证的项目集成基线是 OpenCode 1.18.29。");
    return 2;
  }

  if ((stdout as NodeJS.WriteStream).isTTY) stdout.write(`\u001B]0;${PHANTOMVEIL_PRODUCT_NAME}\u0007`);
  writeLine(stdout, BANNER);
  const tuiConfig = path.join(root, ".opencode", "phantomveil-tui.json");
  const result = launch(openCode, [root, "--agent", PHANTOMVEIL_AGENT], {
    cwd: root,
    env: { ...env, OPENCODE_TUI_CONFIG: tuiConfig },
  });
  if (result.error) {
    writeLine(stderr, `OpenCode 启动失败：${result.error.message}`);
    return 2;
  }
  return result.status ?? 2;
}
