import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import path from "node:path";

import { loadVerifiedEvidenceFile } from "../evidence/evidence-store.ts";
import { auditObservationReport } from "./report-audit.ts";
import type { AgentRunEvents } from "./run-types.ts";

const EVIDENCE_ID = /^EV-\d{14}-[a-f0-9]{8}$/u;
const REPORT_ID = /^RPT-\d{14}-[a-f0-9]{8}$/u;

export interface ObservationTask {
  id: string;
  url: string;
  expected_status: number;
}

export interface FixtureHit {
  received_at: string;
  method: string;
  request_target: string;
  response_status: number;
  response_body_sha256: string;
}

export interface ObservationScore {
  task_id: string;
  passed: boolean;
  reason: string;
  successful_tool_calls: number;
  fixture_requests: number;
  evidence_id: string | null;
  evidence_file: string | null;
  evidence_sha256: string | null;
  report_id: string | null;
  report_file: string | null;
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
  artifactNamespace: "opencode" | "hermes" = "opencode",
): Promise<ObservationScore> {
  const base = {
    task_id: task.id, successful_tool_calls: 0, fixture_requests: hits.length,
    evidence_id: null, evidence_file: null, evidence_sha256: null,
    report_id: null, report_file: null, vulnerability_confirmation_evaluated: false as const,
  };
  const fail = (reason: string, extra: Partial<ObservationScore> = {}): ObservationScore =>
    ({ ...base, ...extra, passed: false, reason });

  if (events.error) return fail(`模型运行错误：${events.error}`);
  const expectedUrl = new URL(task.url);
  const expectedTarget = `${expectedUrl.pathname}${expectedUrl.search}`;
  if (hits.length !== 1 || hits[0].method !== "GET" ||
      hits[0].request_target !== expectedTarget) {
    return fail("靶站请求不是预期的单次 GET");
  }
  const completed = events.tools.filter(item =>
    ["authorized_web_observe", "authorized_web_check"].includes(item.name) && item.status === "completed");
  if (events.tools.length !== 1 || completed.length !== 1 ||
      record(completed[0].input)?.url !== task.url) return fail("没有恰好一次针对预期目标的授权观察工具调用", {
    successful_tool_calls: completed.length,
  });
  const result = toolResult(completed[0].output);
  const trace = record(result?.trace);
  const evidenceId = result?.evidence_id ?? trace?.evidence_id;
  const evidenceFile = result?.evidence_file ?? trace?.evidence_file;
  const reportId = result?.report_id ?? trace?.report_id;
  const reportFile = result?.report_file ?? trace?.report_file;
  if (result?.ok !== true || typeof evidenceId !== "string" || !EVIDENCE_ID.test(evidenceId) ||
      typeof evidenceFile !== "string" || typeof reportId !== "string" ||
      !REPORT_ID.test(reportId) || typeof reportFile !== "string") {
    return fail("工具没有返回可核对的证据", { successful_tool_calls: 1 });
  }

  let allowedDir: string;
  try {
    const evidenceRoot = path.join(workspace, "evidence");
    const outputRoot = path.join(evidenceRoot, artifactNamespace);
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
  if (relative !== `${evidenceId}.json`) {
    return fail("证据文件不在本次隔离运行目录", { successful_tool_calls: 1 });
  }
  const evidence = await loadVerifiedEvidenceFile(resolved);
  const actualBodyHash = evidence.ok
    ? createHash("sha256").update(evidence.record.observation.response.body, "utf8").digest("hex")
    : null;
  if (!evidence.ok || evidence.record.evidence_id !== evidenceId ||
      evidence.record.observation.request.url !== task.url ||
      evidence.record.observation.response.status !== task.expected_status ||
      evidence.record.observation.response.status !== hits[0].response_status ||
      evidence.record.observation.response.body_sha256 !== actualBodyHash ||
      actualBodyHash !== hits[0].response_body_sha256) {
    return fail("证据完整性、目标或状态码不符合已知答案", { successful_tool_calls: 1 });
  }
  let relativeReport: string;
  let reportText: string;
  try {
    const reportRoot = path.join(workspace, "reports");
    const outputRoot = path.join(reportRoot, artifactNamespace);
    const parentInfo = await lstat(reportRoot);
    const outputInfo = await lstat(outputRoot);
    const fileInfo = await lstat(reportFile);
    if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink() ||
        !outputInfo.isDirectory() || outputInfo.isSymbolicLink() ||
        !fileInfo.isFile() || fileInfo.isSymbolicLink()) throw new Error("invalid report path");
    const reportDir = await realpath(outputRoot);
    const resolvedReport = await realpath(reportFile);
    relativeReport = path.relative(reportDir, resolvedReport);
    if (relativeReport !== `${reportId}.md` ||
        path.relative(await realpath(workspace), reportDir).startsWith("..")) {
      throw new Error("report outside run");
    }
    reportText = await readFile(resolvedReport, "utf8");
  } catch {
    return fail("报告不存在或不在本次隔离运行目录", { successful_tool_calls: 1 });
  }
  if (!auditObservationReport(reportText, reportId, evidence.record, completed[0].name)) {
    return fail("报告内容与已验证证据不一致", { successful_tool_calls: 1 });
  }
  const statusToken = new RegExp(`(?<!\\d)${task.expected_status}(?!\\d)`, "u");
  if (!statusToken.test(events.final_text)) {
    return fail("Agent 最终回答没有给出正确状态码", {
      successful_tool_calls: 1, evidence_id: evidenceId, evidence_file: relative,
      evidence_sha256: evidence.record.integrity.payload_sha256,
      report_id: reportId, report_file: relativeReport,
    });
  }
  return {
    ...base, passed: true, reason: "工具调用、靶站请求、证据和最终状态码均符合已知答案",
    successful_tool_calls: 1, evidence_id: evidenceId, evidence_file: relative,
    evidence_sha256: evidence.record.integrity.payload_sha256,
    report_id: reportId, report_file: relativeReport,
  };
}
