import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { access, lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

import { scoreHermesOpenCodePair } from "../../src/evaluation/hermes-pair-score.ts";

const SOURCE_ROOT = path.resolve(import.meta.dirname, "../..");
const RUNS_ROOT = path.resolve(process.env.PVEIL_HERMES_RUNS_DIR ?? path.join(
  process.env.LOCALAPPDATA ?? path.join(homedir(), ".local", "share"),
  "PhantomVeil", "hermes-eval-runs"));
const relativeRoot = path.relative(SOURCE_ROOT, RUNS_ROOT);
if (!relativeRoot || (!relativeRoot.startsWith("..") && !path.isAbsolute(relativeRoot))) {
  throw new Error("配对评测目录必须位于源码仓库外");
}
const model = process.argv[2];
const provider = process.argv[3];
const options = process.argv.slice(4);
const modelOption = options.find(item => item.startsWith("--opencode-model="));
const opencodeModel = modelOption?.slice("--opencode-model=".length) ?? `${provider}/${model}`;
if (typeof model !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._/-]{1,100}$/u.test(model) ||
    typeof provider !== "string" || !/^[a-zA-Z0-9-]{2,40}$/u.test(provider) ||
    provider === "local-fixture" || options.length > 1 || (options.length && !modelOption) ||
    opencodeModel !== `${provider}/${model}`) {
  throw new Error("用法：npm run hermes:pair -- MODEL PROVIDER [--opencode-model=PROVIDER/MODEL]；首轮只接受两端完全相同的提供方和模型 ID");
}
const sha256 = value => createHash("sha256").update(value).digest("hex");
const pairId = `pair-${new Date().toISOString().replace(/[:.]/gu, "-")}-${randomUUID().slice(0, 8)}`;
const pairDir = path.join(RUNS_ROOT, pairId);
await mkdir(pairDir, { recursive: true });
const pairFile = path.join(pairDir, "pair-result.json");
const save = async summary => {
  await writeFile(pairFile, JSON.stringify(summary, null, 2), { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ pair_id: pairId, status: summary.status,
    stage: summary.stage ?? null, error_code: summary.error_code ?? null,
    hermes_binary_source: summary.hermes_binary_source ?? null,
    ignored_invalid_hermes_override: summary.ignored_invalid_hermes_override ?? false,
    result_file: pairFile, runs: summary.runs ?? [] })}\n`);
};

let stage = "credential_preflight";
let hermesSelection = null;
try {
if (provider === "deepseek" && !process.env.DEEPSEEK_API_KEY) {
  await save({ pair_id: pairId, status: "blocked_model_credentials",
    reason: "隔离 Hermes 子进程缺少 DEEPSEEK_API_KEY；未启动模型或靶站",
    model, provider, opencode_model: opencodeModel, runs: [] });
  process.exitCode = 2;
} else {
  stage = "hermes_binary_check";
  const localAppData = process.env.LOCALAPPDATA;
  const candidates = [
    ["override", process.env.HERMES_BIN],
    ["shared_project_runtime", process.platform === "win32"
      ? path.join(path.dirname(SOURCE_ROOT), ".phantomveil-hermes-runtime", ".venv",
        "Scripts", "hermes.exe") : null],
    ["isolated", process.platform === "win32" && localAppData
      ? path.join(localAppData, "PhantomVeil", "hermes-runtime", "source",
        ".venv", "Scripts", "hermes.exe") : null],
    ["isolated_physical", process.platform === "win32" && localAppData
      ? path.join(localAppData, "Packages", "OpenAI.Codex_2p2nqsd0c76g0", "LocalCache",
        "Local", "PhantomVeil", "hermes-runtime", "source", ".venv", "Scripts",
        "hermes.exe") : null],
    ["official_windows", process.platform === "win32" && localAppData
      ? path.join(localAppData, "hermes", "bin", "hermes.exe") : null],
    ["path", process.platform === "win32" ? null : "hermes"],
  ];
  let ignoredInvalidOverride = false;
  for (const [source, candidate] of candidates) {
    if (!candidate) continue;
    if (path.isAbsolute(candidate)) {
      try { await access(candidate); } catch {
        if (source === "override") ignoredInvalidOverride = true;
        continue;
      }
    }
    hermesSelection = { source, bin: candidate };
    break;
  }
  if (!hermesSelection) {
    const missing = new Error("Hermes executable not found");
    missing.code = "ENOENT";
    throw missing;
  }
  const hermesBin = hermesSelection.bin;
  const childEnv = { ...process.env, HERMES_BIN: hermesBin };
  const runScript = path.join(import.meta.dirname, "run.mjs");

  async function runSide(runtime, port) {
    const args = [runScript, model, provider, `--runtime=${runtime}`, "--learning=off",
      `--opencode-model=${opencodeModel}`, ...(port ? [`--port=${port}`] : [])];
    const runtimeEnv = { ...childEnv };
    if (runtime === "opencode") delete runtimeEnv.DEEPSEEK_API_KEY;
    const child = spawn(process.execPath, args, { cwd: SOURCE_ROOT, env: runtimeEnv,
      windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderrBytes = 0;
    child.stdout.on("data", chunk => { stdout = (stdout + chunk.toString("utf8")).slice(-32768); });
    child.stderr.on("data", chunk => { stderrBytes += chunk.length; });
    let timedOut = false;
    const timeout = setTimeout(() => { timedOut = true; child.kill(); }, 180_000);
    const exitCode = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    }).finally(() => clearTimeout(timeout));
    const line = stdout.trim().split(/\r?\n/u).at(-1);
    let notice;
    try { notice = JSON.parse(line); } catch { notice = null; }
    if (!notice || !/^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-[0-9a-f]{8}$/u
      .test(notice.run_id) || timedOut) {
      return { runtime, launch_failure: true, exit_code: exitCode, timed_out: timedOut,
        stderr_bytes: stderrBytes, result_file: null, result: null };
    }
    const resultDir = path.join(RUNS_ROOT, notice.run_id);
    const resultFile = path.join(resultDir, "result.json");
    const [dirStat, fileStat] = await Promise.all([lstat(resultDir), lstat(resultFile)]);
    if (!dirStat.isDirectory() || dirStat.isSymbolicLink() ||
        !fileStat.isFile() || fileStat.isSymbolicLink()) {
      const invalidPath = new Error("子评测结果不在隔离运行目录");
      invalidPath.code = "RESULT_PATH_REJECTED";
      throw invalidPath;
    }
    const result = JSON.parse(await readFile(resultFile, "utf8"));
    if (result.run_id !== notice.run_id || result.runtime !== runtime) {
      const invalidIdentity = new Error("子评测结果身份不匹配");
      invalidIdentity.code = "RESULT_ID_MISMATCH";
      throw invalidIdentity;
    }
    return { runtime, launch_failure: false, exit_code: exitCode, timed_out: timedOut,
      stderr_bytes: stderrBytes, result_file: resultFile, result };
  }

  stage = "hermes_run";
  const hermes = await runSide("hermes", null);
  let opencode = null;
  if (hermes.result?.target_url) {
    const port = new URL(hermes.result.target_url).port;
    stage = "opencode_run";
    opencode = await runSide("opencode", port);
  }
  stage = "pair_scoring";
  const score = hermes.result && opencode?.result
    ? scoreHermesOpenCodePair(hermes.result, opencode.result) : null;
  const status = score?.status ?? "launch_failed";
  const runView = side => side && ({ runtime: side.runtime, result_file: side.result_file,
    run_id: side.result?.run_id ?? null, run_outcome: side.result?.run_outcome ?? null,
    score_passed: side.result?.score?.passed ?? null,
    target_url: side.result?.target_url ?? null,
    tool_calls: side.result?.tool_events?.map(tool => tool.name) ?? [],
    actual_requests: side.result?.fixture_requests?.length ?? null,
    request_budget: side.result?.request_budget ?? null,
    runtime_limits: side.result?.runtime_limits ?? null,
    token_usage: side.result?.token_usage ?? null,
    elapsed_ms: side.result?.elapsed_ms ?? null,
    child_exit_code: side.exit_code, launch_failure: side.launch_failure });
  await save({ pair_id: pairId, status, model, provider,
    hermes_binary_source: hermesSelection.source,
    ignored_invalid_hermes_override: ignoredInvalidOverride,
    opencode_model: opencodeModel, prompt_sha256: hermes.result?.prompt_text
      ? sha256(hermes.result.prompt_text) : null,
    pair_evaluator_sha256: sha256(await readFile(path.join(SOURCE_ROOT,
      "src", "evaluation", "hermes-pair-score.ts"))),
    pair_launcher_sha256: sha256(await readFile(import.meta.filename)),
    score, runs: [runView(hermes), runView(opencode)].filter(Boolean),
    note: "同一提供方和模型 ID 的路由已核对；未验证提供方后端权重版本" });
  process.exitCode = status === "paired_passed" ? 0 : 1;
}
} catch (error) {
  await save({ pair_id: pairId, status: "launch_failed", stage,
    error_name: error instanceof Error ? error.name : "UnknownError",
    error_code: typeof error?.code === "string" ? error.code : null,
    hermes_binary_source: hermesSelection?.source ?? null,
    model, provider, opencode_model: opencodeModel, runs: [] });
  process.exitCode = 1;
}
