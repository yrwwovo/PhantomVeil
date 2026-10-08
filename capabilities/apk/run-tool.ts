import { spawn } from "node:child_process";

/**
 * 受限外部工具执行器（设计 §0 / §8 决策 5：固定子命令 + 参数白名单，不开通用 shell）。
 *
 * 所有调用都用 argv 数组形式 spawn（shell:false），不拼接字符串、不做 shell 解释；
 * 每个 capability 自行把子命令与参数写死，这里只负责执行、限时、限输出与捕获。
 * 本模块不产生任何判定，只回传 stdout/stderr/退出码等执行事实。
 */

export interface RunToolOptions {
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  env?: Record<string, string>;
}

export interface ToolRunResult {
  tool: string;
  argv: string[];
  ok: boolean;
  exit_code: number | null;
  signal: string | null;
  timed_out: boolean;
  stdout: string;
  stderr: string;
  spawn_error?: string;
  duration_ms: number;
}

const DEFAULT_TIMEOUT_MS = 180_000;
const DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024;

export function runTool(tool: string, args: string[], opts: RunToolOptions = {}): Promise<ToolRunResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxOutput = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT;
  const started = Date.now();
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(tool, args, {
        cwd: opts.cwd,
        env: opts.env ? { ...process.env, ...opts.env } : process.env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      resolve({
        tool, argv: args, ok: false, exit_code: null, signal: null, timed_out: false,
        stdout: "", stderr: "", spawn_error: error instanceof Error ? error.message : String(error),
        duration_ms: Date.now() - started,
      });
      return;
    }
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    let outBytes = 0;
    let errBytes = 0;
    let timedOut = false;
    const append = (chunks: Buffer[], total: number, chunk: Buffer): number => {
      if (total >= maxOutput) return total;
      const room = maxOutput - total;
      chunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
      return total + chunk.length;
    };
    child.stdout?.on("data", (c: Buffer) => { outBytes = append(outChunks, outBytes, c); });
    child.stderr?.on("data", (c: Buffer) => { errBytes = append(errChunks, errBytes, c); });
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutMs);
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({
        tool, argv: args, ok: false, exit_code: null, signal: null, timed_out: timedOut,
        stdout: Buffer.concat(outChunks).toString("utf8"), stderr: Buffer.concat(errChunks).toString("utf8"),
        spawn_error: error.message, duration_ms: Date.now() - started,
      });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        tool, argv: args, ok: code === 0 && !timedOut, exit_code: code, signal: signal ?? null,
        timed_out: timedOut,
        stdout: Buffer.concat(outChunks).toString("utf8"),
        stderr: Buffer.concat(errChunks).toString("utf8"),
        duration_ms: Date.now() - started,
      });
    });
  });
}

/** which 探测工具是否可用（用于“已安装 vs 桩”的降级判定）。 */
export async function toolAvailable(tool: string): Promise<boolean> {
  const res = await runTool("/usr/bin/env", ["bash", "-c", `command -v ${JSON.stringify(tool).slice(1, -1)} >/dev/null 2>&1`], { timeoutMs: 5000 });
  return res.ok;
}
