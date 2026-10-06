import { createHash } from "node:crypto";
import { inventoryPageInputs } from "../../capabilities/web/input-inventory.ts";
import type { EvidenceRecord } from "../evidence/evidence-store.ts";

export interface GetParameterCandidate {
  candidate_id: string; evidence_id: string; endpoint: string; parameter_name: string;
  source_kind: "form" | "query_link"; form_index: number;
}

export function safeGetParameter(endpoint: string, name: string): boolean {
  return /^[\p{L}\p{N}_.-]{1,128}$/u.test(name) &&
    !/(?:pass|secret|token|auth|session|cookie|api.?key|file|csrf)/iu.test(name) &&
    !/(?:^|\/)(?:logout|delete|remove|reset|unsubscribe|purchase|transfer|admin)(?:\/|$)/iu.test(new URL(endpoint).pathname);
}

/** Reuses the existing value-stripping parser; no request or model-supplied endpoint. */
export function getParameterCandidates(record: EvidenceRecord): GetParameterCandidate[] {
  const response = record.observation.response;
  if (!String(response.headers["content-type"] ?? "").toLowerCase().includes("text/html")) return [];
  const inventory = inventoryPageInputs(response.body, record.observation.request.url);
  const candidates: GetParameterCandidate[] = [];
  const add = (endpoint: string, name: string, source_kind: "form" | "query_link", form_index: number) => {
    if (!safeGetParameter(endpoint, name)) return;
    const candidate_id = createHash("sha256").update(`${record.evidence_id}\n${endpoint}\n${name}`).digest("hex");
    if (!candidates.some(c => c.candidate_id === candidate_id)) candidates.push({ candidate_id,
      evidence_id: record.evidence_id, endpoint, parameter_name: name, source_kind, form_index });
  };
  for (const form of inventory.forms) {
    if (form.method !== "get" || !form.action_valid || !form.same_origin || !form.action ||
      form.action_query_parameters.length || form.controls.some(c => !c.disabled &&
        ["password", "hidden", "file"].includes(c.type))) continue;
    for (const name of form.parameter_names) add(form.action, name, "form", form.index);
  }
  for (const link of inventory.query_endpoints) {
    // Dropping other required values is ambiguous; first slice supports one query parameter.
    if (link.same_origin && link.parameter_names.length === 1) add(link.endpoint,
      link.parameter_names[0], "query_link", 0);
  }
  return candidates;
}
