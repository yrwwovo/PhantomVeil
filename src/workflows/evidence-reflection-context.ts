import { realpath } from "node:fs/promises";
import path from "node:path";

import { analyzeReflectionContext } from "../../capabilities/web/reflection-context.ts";
import { loadVerifiedEvidenceFile } from "../evidence/evidence-store.ts";

const EVIDENCE_ID = /^EV-\d{14}-[a-f0-9]{8}$/u;
const REFLECTION_MARKER = /^PV-REFLECT-[a-f0-9]{16}$/u;

/** 只分析已保存并通过完整性校验的反射响应证据；不联网、不执行 HTML。 */
export async function runEvidenceReflectionContext(projectRoot: string, input: { evidence_id: string },
  artifactNamespace: "opencode" | "hermes" = "opencode") {
  if (!input || typeof input.evidence_id !== "string" || !EVIDENCE_ID.test(input.evidence_id)) {
    return { ok: false as const, code: "INVALID_ID", reason: "请提供完整的 EV 证据编号，不能使用文件路径" };
  }
  let filePath: string;
  try {
    const root = await realpath(projectRoot);
    const relativeFile = path.join("evidence", artifactNamespace, `${input.evidence_id}.json`);
    filePath = await realpath(path.join(root, relativeFile));
    if (path.relative(root, filePath) !== relativeFile) {
      return { ok: false as const, code: "PATH_REJECTED", reason: "证据文件被重定向到其他位置，拒绝读取" };
    }
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    return { ok: false as const, code: missing ? "NOT_FOUND" : "IO_ERROR",
      reason: missing ? "项目中找不到该证据记录，请核对编号" : "无法定位项目证据文件" };
  }

  const loaded = await loadVerifiedEvidenceFile(filePath);
  if (!loaded.ok) return loaded;
  if (loaded.record.evidence_id !== input.evidence_id) {
    return { ok: false as const, code: "INVALID_EVIDENCE_FILE", reason: "证据编号与文件名不一致" };
  }
  const observation = loaded.record.observation;
  const contentType = Object.entries(observation.response.headers)
    .find(([name]) => name.toLowerCase() === "content-type")?.[1];
  const normalizedType = Array.isArray(contentType) ? contentType.join(";") : contentType;
  if (!normalizedType?.toLowerCase().includes("text/html")) {
    return { ok: false as const, code: "NOT_HTML", reason: "该证据不是 HTML 响应，无法分析反射位置" };
  }

  let markers: string[];
  try {
    markers = [...new Set([...new URL(observation.request.url).searchParams.values()]
      .filter(value => REFLECTION_MARKER.test(value)))];
  } catch {
    return { ok: false as const, code: "INVALID_EVIDENCE_URL", reason: "证据中的请求 URL 无效" };
  }
  if (markers.length === 0) {
    return { ok: false as const, code: "MARKER_NOT_FOUND", reason: "该 EV 不是可识别的无害参数反射检查证据" };
  }
  if (markers.length > 1) {
    return { ok: false as const, code: "AMBIGUOUS_MARKER", reason: "该 EV 包含多个反射标记，无法确定本次要分析的标记" };
  }

  return {
    ok: true as const, code: "REFLECTION_CONTEXT_COMPLETED",
    reason: "已对完整性校验通过的 HTML 证据完成离线反射位置分析",
    evidence_id: input.evidence_id,
    result: analyzeReflectionContext(observation.response.body, markers[0]),
  };
}
