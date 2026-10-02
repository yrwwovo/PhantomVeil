import { realpath } from "node:fs/promises";
import path from "node:path";

import { checkHttpSecurityHeaders } from "../../../capabilities/web/security-header-check.ts";
import { loadVerifiedEvidenceFile } from "../../evidence/evidence-store.ts";

const EVIDENCE_ID = /^EV-\d{14}-[a-f0-9]{8}$/u;

/** 只分析本项目已有证据；不发送网络请求、不修改证据或假设。 */
export async function runEvidenceHeaderCheck(
  projectRoot: string,
  input: { evidence_id: string },
) {
  if (!input || typeof input.evidence_id !== "string" ||
      !EVIDENCE_ID.test(input.evidence_id)) {
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
  return {
    ok: true as const,
    code: "HEADER_CHECK_COMPLETED",
    reason: "已基于完整性校验通过的已有证据完成离线响应头检查",
    result: checkHttpSecurityHeaders(loaded.record),
  };
}
