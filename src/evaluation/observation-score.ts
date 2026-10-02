import { lstat, realpath } from "node:fs/promises";
import path from "node:path";

import { loadVerifiedEvidenceFile } from "../evidence/evidence-store.ts";
import type { AgentRunEvents } from "./run-types.ts";

export interface ObservationTask {
  id: string;
  url: string;
  expected_status: number;
}

export interface FixtureHit { method: string; pathname: string }

export interface ObservationScore {
  task_id: string;
  passed: boolean;
  reason: string;
  successful_tool_calls: number;
  fixture_requests: number;
  evidence_id: string | null;
  evidence_file: string | null;
  vulnerability_confirmation_evaluated: false;
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function toolResult(value: unknown): Record<string, unknown> | null {
  try {
    return record(typeof value === "string" ? JSON.parse(value) : value);
  } catch {
    return null;
  }
}

/** The answer and target truth are supplied outside the Agent's workspace and prompt. */
export async function scoreObservationRun(
  task: ObservationTask,
  workspace: string,
  events: AgentRunEvents,
  hits: FixtureHit[],
): Promise<ObservationScore> {
  const base = {
    task_id: task.id, successful_tool_calls: 0, fixture_requests: hits.length,
    evidence_id: null, evidence_file: null, vulnerability_confirmation_evaluated: false as const,
  };
  const fail = (reason: string, extra: Partial<ObservationScore> = {}): ObservationScore =>
    ({ ...base, ...extra, passed: false, reason });

  if (events.error) return fail(`模型运行错误：${events.error}`);
  const expectedPath = new URL(task.url).pathname;
  if (hits.length !== 1 || hits[0].method !== "GET" || hits[0].pathname !== expectedPath) {
    return fail("靶站请求不是预期的单次 GET");
  }
  const completed = events.tools.filter(item =>
    ["authorized_web_observe", "authorized_web_check"].includes(item.name) && item.status === "completed");
  if (completed.length !== 1) return fail("没有恰好一次成功的授权观察工具调用", {
    successful_tool_calls: completed.length,
  });
  const result = toolResult(completed[0].output);
  const trace = record(result?.trace);
  const evidenceId = result?.evidence_id ?? trace?.evidence_id;
  const evidenceFile = result?.evidence_file ?? trace?.evidence_file;
  if (result?.ok !== true || typeof evidenceId !== "string" || typeof evidenceFile !== "string") {
    return fail("工具没有返回可核对的证据", { successful_tool_calls: 1 });
  }

  let allowedDir: string;
  try {
    const evidenceRoot = path.join(workspace, "evidence");
    const outputRoot = path.join(evidenceRoot, "opencode");
    const parentInfo = await lstat(evidenceRoot);
    const outputInfo = await lstat(outputRoot);
    if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink() ||
        !outputInfo.isDirectory() || outputInfo.isSymbolicLink()) {
      return fail("证据目录不是本次运行的普通目录", { successful_tool_calls: 1 });
    }
    allowedDir = await realpath(outputRoot);
    const relativeDir = path.relative(await realpath(workspace), allowedDir);
    if (relativeDir.startsWith("..") || path.isAbsolute(relativeDir)) {
      return fail("证据目录位于本次运行目录外", { successful_tool_calls: 1 });
    }
  } catch {
    return fail("本次运行没有生成证据目录", { successful_tool_calls: 1 });
  }
  let resolved: string;
  try {
    const info = await lstat(evidenceFile);
    if (!info.isFile() || info.isSymbolicLink()) return fail("证据文件不是普通文件", { successful_tool_calls: 1 });
    resolved = await realpath(evidenceFile);
  } catch {
    return fail("证据文件不存在", { successful_tool_calls: 1 });
  }
  const relative = path.relative(allowedDir, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    return fail("证据文件不在本次隔离运行目录", { successful_tool_calls: 1 });
  }
  const evidence = await loadVerifiedEvidenceFile(resolved);
  if (!evidence.ok || evidence.record.evidence_id !== evidenceId ||
      evidence.record.observation.request.url !== task.url ||
      evidence.record.observation.response.status !== task.expected_status) {
    return fail("证据完整性、目标或状态码不符合已知答案", { successful_tool_calls: 1 });
  }
  if (!events.final_text.includes(String(task.expected_status))) {
    return fail("Agent 最终回答没有给出正确状态码", {
      successful_tool_calls: 1, evidence_id: evidenceId, evidence_file: relative,
    });
  }
  return {
    ...base, passed: true, reason: "工具调用、靶站请求、证据和最终状态码均符合已知答案",
    successful_tool_calls: 1, evidence_id: evidenceId, evidence_file: relative,
  };
}
