import { realpath } from "node:fs/promises";
import path from "node:path";

import { inventoryPageInputs } from "../../../capabilities/web/input-inventory.ts";
import { loadVerifiedEvidenceFile } from "../../evidence/evidence-store.ts";

const EVIDENCE_ID = /^EV-\d{14}-[a-f0-9]{8}$/u;

/** 只分析本项目已有 HTML 证据；不联网、不写文件、不提交表单。 */
export async function runEvidenceInputInventory(
  projectRoot: string,
  input: { evidence_id: string },
) {
  if (!input || typeof input.evidence_id !== "string" || !EVIDENCE_ID.test(input.evidence_id)) {
    return { ok: false as const, code: "INVALID_ID", reason: "请提供完整的 EV 证据编号，不能使用文件路径" };
  }

  let filePath: string;
  try {
    const root = await realpath(projectRoot);
    const relativeFile = path.join("evidence", "opencode", `${input.evidence_id}.json`);
    filePath = await realpath(path.join(root, relativeFile));
    if (path.relative(root, filePath) !== relativeFile) {
      return { ok: false as const, code: "PATH_REJECTED", reason: "证据文件被重定向到其他位置，拒绝读取" };
    }
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    return {
      ok: false as const,
      code: missing ? "NOT_FOUND" : "IO_ERROR",
      reason: missing ? "项目中找不到该证据记录，请核对编号" : "无法定位项目证据文件",
    };
  }

  const loaded = await loadVerifiedEvidenceFile(filePath);
  if (!loaded.ok) return loaded;
  if (loaded.record.evidence_id !== input.evidence_id) {
    return { ok: false as const, code: "INVALID_EVIDENCE_FILE", reason: "证据编号与文件名不一致" };
  }
  const response = loaded.record.observation.response;
  const contentType = Object.entries(response.headers)
    .find(([name]) => name.toLowerCase() === "content-type")?.[1];
  const normalizedType = Array.isArray(contentType) ? contentType.join(";") : contentType;
  if (!normalizedType?.toLowerCase().includes("text/html")) {
    return { ok: false as const, code: "NOT_HTML", reason: "该证据不是 HTML 响应，无法提取页面输入入口" };
  }

  return {
    ok: true as const,
    code: "INPUT_INVENTORY_COMPLETED",
    reason: "已从完整性校验通过的 HTML 证据中完成只读输入入口清点",
    result: inventoryPageInputs(response.body, loaded.record.observation.request.url),
  };
}
