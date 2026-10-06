import { readFile, realpath } from "node:fs/promises";
import path from "node:path";

import { extractPageLinks } from "../../capabilities/web/crawl-links.ts";
import { loadVerifiedEvidenceFile } from "../evidence/evidence-store.ts";
import { checkUrlScope, type ScopeConfig } from "../scope/scope-guard.ts";

const EVIDENCE_ID = /^EV-\d{14}-[a-f0-9]{8}$/u;

/** List only already-observed, query-free same-origin links; never sends a request. */
export async function runEvidenceLinkInventory(projectRoot: string, input: { evidence_id: string },
  artifactNamespace: "opencode" | "hermes" = "opencode") {
  if (!input || typeof input.evidence_id !== "string" || !EVIDENCE_ID.test(input.evidence_id)) {
    return { ok: false as const, code: "INVALID_ID", reason: "请提供完整 EV 编号" };
  }
  let filePath: string;
  let root: string;
  try {
    root = await realpath(projectRoot);
    const relative = path.join("evidence", artifactNamespace, `${input.evidence_id}.json`);
    filePath = await realpath(path.join(root, relative));
    if (path.relative(root, filePath) !== relative) {
      return { ok: false as const, code: "PATH_REJECTED", reason: "证据文件不在本项目固定目录" };
    }
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    return { ok: false as const, code: missing ? "NOT_FOUND" : "IO_ERROR",
      reason: missing ? "找不到来源证据" : "无法定位来源证据" };
  }
  const loaded = await loadVerifiedEvidenceFile(filePath);
  if (!loaded.ok) return loaded;
  if (loaded.record.evidence_id !== input.evidence_id) {
    return { ok: false as const, code: "INVALID_EVIDENCE_FILE", reason: "证据编号不匹配" };
  }
  const observation = loaded.record.observation;
  const contentType = Object.entries(observation.response.headers)
    .find(([name]) => name.toLowerCase() === "content-type")?.[1];
  const normalizedType = Array.isArray(contentType) ? contentType.join(";") : contentType;
  if (!normalizedType?.toLowerCase().includes("text/html")) {
    return { ok: false as const, code: "NOT_HTML", reason: "来源证据不是 HTML" };
  }
  let scope: ScopeConfig;
  try {
    scope = JSON.parse(await readFile(path.join(root, "configs", "scope.local.json"), "utf8"));
  } catch {
    return { ok: false as const, code: "CONFIG_ERROR", reason: "无法读取当前授权范围" };
  }
  const pageUrl = new URL(observation.request.url);
  const extracted = extractPageLinks(observation.response.body, pageUrl.href, 100);
  const links: string[] = [];
  const choices: Array<{ url: string; label: string }> = [];
  const seen = new Set<string>();
  let skipped = 0;
  for (const { href, label } of extracted.choices) {
    try {
      const candidate = new URL(href, extracted.base_url);
      candidate.hash = "";
      if (candidate.origin !== pageUrl.origin || candidate.username || candidate.password ||
          candidate.search || !checkUrlScope(candidate.href, scope).allowed) {
        skipped++;
        continue;
      }
      if (seen.has(candidate.href)) continue;
      seen.add(candidate.href);
      if (links.length < 30) {
        links.push(candidate.href);
        choices.push({ url: candidate.href, label });
      }
      else skipped++;
    } catch { skipped++; }
  }
  return { ok: true as const, code: "LINK_INVENTORY_COMPLETED",
    reason: "只读列出当前授权范围内的普通链接；尚未访问这些链接",
    result: { page_url: pageUrl.href, links, choices, skipped,
      truncated: extracted.truncated || seen.size > 30 } };
}
