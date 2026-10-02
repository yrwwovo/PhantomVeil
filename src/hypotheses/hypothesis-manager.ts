import { randomUUID } from "node:crypto";

import { loadVerifiedEvidenceFile } from "../evidence/evidence-store.ts";

export type HypothesisStatus =
  | "suspected"
  | "testing"
  | "confirmed"
  | "rejected"
  | "inconclusive";

export interface HypothesisEvidenceRef {
  evidence_id: string;
  file_path: string;
  payload_sha256: string;
}

export interface HypothesisCandidateIdentity {
  kind: "reflected_xss";
  endpoint: string;
  parameter_name: string;
  fingerprint: string;
}

export interface HypothesisHistoryEntry {
  from: HypothesisStatus | null;
  to: HypothesisStatus;
  changed_at: string;
  reason: string;
  event?: "status_change" | "evidence_attached";
}

export interface Hypothesis {
  schema_version: 1;
  hypothesis_id: string;
  authorization_reference?: string;
  candidate_identity?: HypothesisCandidateIdentity;
  title: string;
  description: string;
  target_url: string;
  status: HypothesisStatus;
  evidence: HypothesisEvidenceRef[];
  reproduction_steps: string[];
  created_at: string;
  updated_at: string;
  history: HypothesisHistoryEntry[];
}

export interface CreateHypothesisInput {
  title: string;
  description: string;
  target_url: string;
  reason: string;
  authorization_reference?: string;
  candidate_identity?: HypothesisCandidateIdentity;
}

export interface TransitionHypothesisInput {
  to: HypothesisStatus;
  reason: string;
  evidence_files?: string[];
  reproduction_steps?: string[];
}

export interface HypothesisManagerOptions {
  now?: () => Date;
  id_factory?: () => string;
}

export type HypothesisResult =
  | {
      ok: true;
      code: "HYPOTHESIS_CREATED" | "HYPOTHESIS_UPDATED";
      reason: string;
      hypothesis: Hypothesis;
    }
  | {
      ok: false;
      code:
        | "INVALID_INPUT"
        | "INVALID_TRANSITION"
        | "EVIDENCE_INVALID"
        | "CONFIRMATION_REQUIREMENTS_MISSING";
      reason: string;
    };

const ALLOWED_TRANSITIONS: Record<HypothesisStatus, HypothesisStatus[]> = {
  suspected: ["testing", "rejected", "inconclusive"],
  testing: ["confirmed", "rejected", "inconclusive"],
  inconclusive: ["testing", "rejected"],
  confirmed: [],
  rejected: [],
};

function nonEmpty(value: string): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

function normalizeLines(values: string[] | undefined): string[] {
  if (!values) {
    return [];
  }
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function validHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function validCandidateIdentity(value: HypothesisCandidateIdentity | undefined): boolean {
  if (!value) return true;
  if (value.kind !== "reflected_xss" || !nonEmpty(value.parameter_name) ||
      !/^[a-f0-9]{64}$/u.test(value.fingerprint)) return false;
  try {
    const endpoint = new URL(value.endpoint);
    return (endpoint.protocol === "http:" || endpoint.protocol === "https:") &&
      !endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash;
  } catch {
    return false;
  }
}

function timestampAndId(options: HypothesisManagerOptions): {
  now: string;
  hypothesisId: string;
} {
  const now = (options.now ?? (() => new Date()))().toISOString();
  const compactDate = now.replace(/[-:.TZ]/gu, "").slice(0, 14);
  const suffix = (options.id_factory ?? randomUUID)().slice(0, 8);
  return { now, hypothesisId: `HYP-${compactDate}-${suffix}` };
}

export function createHypothesis(
  input: CreateHypothesisInput,
  options: HypothesisManagerOptions = {},
): HypothesisResult {
  if (
    !nonEmpty(input.title) ||
    !nonEmpty(input.description) ||
    !nonEmpty(input.reason) ||
    !validHttpUrl(input.target_url) ||
    !validCandidateIdentity(input.candidate_identity)
  ) {
    return {
      ok: false,
      code: "INVALID_INPUT",
      reason: "标题、描述、创建原因和有效的 HTTP(S) 目标 URL 都不能为空",
    };
  }

  const { now, hypothesisId } = timestampAndId(options);
  return {
    ok: true,
    code: "HYPOTHESIS_CREATED",
    reason: "已创建待验证的漏洞假设；这不是漏洞结论",
    hypothesis: {
      schema_version: 1,
      hypothesis_id: hypothesisId,
      ...(input.authorization_reference
        ? { authorization_reference: input.authorization_reference }
        : {}),
      ...(input.candidate_identity
        ? { candidate_identity: structuredClone(input.candidate_identity) }
        : {}),
      title: input.title.trim(),
      description: input.description.trim(),
      target_url: new URL(input.target_url).href,
      status: "suspected",
      evidence: [],
      reproduction_steps: [],
      created_at: now,
      updated_at: now,
      history: [
        {
          from: null,
          to: "suspected",
          changed_at: now,
          reason: input.reason.trim(),
        },
      ],
    },
  };
}

async function loadEvidenceRefs(
  filePaths: string[],
): Promise<
  | { ok: true; refs: HypothesisEvidenceRef[] }
  | { ok: false; reason: string }
> {
  const refs: HypothesisEvidenceRef[] = [];
  for (const filePath of filePaths) {
    const loaded = await loadVerifiedEvidenceFile(filePath);
    if (!loaded.ok) {
      return {
        ok: false,
        reason: `证据文件未通过校验：${loaded.reason}`,
      };
    }
    refs.push({
      evidence_id: loaded.record.evidence_id,
      file_path: filePath,
      payload_sha256: loaded.record.integrity.payload_sha256,
    });
  }
  return { ok: true, refs };
}

export async function createHypothesisWithEvidence(
  input: CreateHypothesisInput,
  evidenceFiles: string[],
  options: HypothesisManagerOptions = {},
): Promise<HypothesisResult> {
  const created = createHypothesis(input, options);
  if (!created.ok) return created;
  const loaded = await loadEvidenceRefs(evidenceFiles);
  if (!loaded.ok) {
    return { ok: false, code: "EVIDENCE_INVALID", reason: loaded.reason };
  }
  return {
    ...created,
    hypothesis: { ...created.hypothesis, evidence: loaded.refs },
  };
}

export async function attachHypothesisEvidence(
  hypothesis: Hypothesis,
  evidenceFiles: string[],
  reason: string,
  options: Pick<HypothesisManagerOptions, "now"> = {},
): Promise<HypothesisResult> {
  if (!nonEmpty(reason) || evidenceFiles.length === 0) {
    return { ok: false, code: "INVALID_INPUT", reason: "关联证据必须提供文件和原因" };
  }
  const loaded = await loadEvidenceRefs(evidenceFiles);
  if (!loaded.ok) {
    return { ok: false, code: "EVIDENCE_INVALID", reason: loaded.reason };
  }
  const existingIds = new Set(hypothesis.evidence.map(ref => ref.evidence_id));
  const additions = loaded.refs.filter(ref => !existingIds.has(ref.evidence_id));
  if (additions.length === 0) {
    return { ok: false, code: "INVALID_INPUT", reason: "这些证据已经关联到该假设" };
  }
  const changedAt = (options.now ?? (() => new Date()))().toISOString();
  return {
    ok: true,
    code: "HYPOTHESIS_UPDATED",
    reason: "新证据已关联到原有漏洞假设，状态未自动改变",
    hypothesis: {
      ...hypothesis,
      evidence: [...hypothesis.evidence, ...additions],
      updated_at: changedAt,
      history: [...hypothesis.history, {
        from: hypothesis.status,
        to: hypothesis.status,
        changed_at: changedAt,
        reason: reason.trim(),
        event: "evidence_attached",
      }],
    },
  };
}

async function reverifyEvidence(
  refs: HypothesisEvidenceRef[],
): Promise<{ ok: true } | { ok: false; reason: string }> {
  for (const ref of refs) {
    const loaded = await loadVerifiedEvidenceFile(ref.file_path);
    if (
      !loaded.ok ||
      loaded.record.evidence_id !== ref.evidence_id ||
      loaded.record.integrity.payload_sha256 !== ref.payload_sha256
    ) {
      return {
        ok: false,
        reason: `确认前证据 ${ref.evidence_id} 未通过重新校验`,
      };
    }
  }
  return { ok: true };
}

export async function transitionHypothesis(
  hypothesis: Hypothesis,
  input: TransitionHypothesisInput,
  options: Pick<HypothesisManagerOptions, "now"> = {},
): Promise<HypothesisResult> {
  if (!nonEmpty(input.reason)) {
    return {
      ok: false,
      code: "INVALID_INPUT",
      reason: "每次状态变化都必须填写原因",
    };
  }
  if (!ALLOWED_TRANSITIONS[hypothesis.status].includes(input.to)) {
    return {
      ok: false,
      code: "INVALID_TRANSITION",
      reason: `不允许从 ${hypothesis.status} 变更为 ${input.to}`,
    };
  }

  const loaded = await loadEvidenceRefs(input.evidence_files ?? []);
  if (!loaded.ok) {
    return {
      ok: false,
      code: "EVIDENCE_INVALID",
      reason: loaded.reason,
    };
  }

  const evidenceById = new Map(
    [...hypothesis.evidence, ...loaded.refs].map((ref) => [ref.evidence_id, ref]),
  );
  const evidence = [...evidenceById.values()];
  const reproductionSteps = normalizeLines([
    ...hypothesis.reproduction_steps,
    ...(input.reproduction_steps ?? []),
  ]);

  if (input.to === "confirmed") {
    if (evidence.length === 0 || reproductionSteps.length === 0) {
      return {
        ok: false,
        code: "CONFIRMATION_REQUIREMENTS_MISSING",
        reason: "确认漏洞至少需要一份通过校验的证据和一条复现步骤",
      };
    }
    const verified = await reverifyEvidence(evidence);
    if (!verified.ok) {
      return {
        ok: false,
        code: "EVIDENCE_INVALID",
        reason: verified.reason,
      };
    }
  }

  const changedAt = (options.now ?? (() => new Date()))().toISOString();
  return {
    ok: true,
    code: "HYPOTHESIS_UPDATED",
    reason: `漏洞假设状态已变更为 ${input.to}`,
    hypothesis: {
      ...hypothesis,
      status: input.to,
      evidence,
      reproduction_steps: reproductionSteps,
      updated_at: changedAt,
      history: [
        ...hypothesis.history,
        {
          from: hypothesis.status,
          to: input.to,
          changed_at: changedAt,
          reason: input.reason.trim(),
        },
      ],
    },
  };
}
