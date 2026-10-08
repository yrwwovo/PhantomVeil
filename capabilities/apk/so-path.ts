import { realpathSync, statSync } from "node:fs";
import path from "node:path";

/**
 * 当前 APK 会话的 so 绑定。workRoot 与 apk_sha256 都来自已有的
 * ApkTaskService / Scope，这里不另建会话存储。
 */
export interface SoSessionBinding {
  workRoot: string;
  apk_sha256: string;
}

export type SoPathGate =
  | { ok: true; resolved: string }
  | { ok: false; code: string; reason: string };

function fail(code: string, reason: string): SoPathGate {
  return { ok: false, code, reason };
}

/**
 * 只接受该会话 workRoot/lib/<abi>/*.so 的普通文件。
 * 先拒绝相对路径、非 .so 和 `..`，再用 realpath 确认没有符号链接逃出会话树。
 */
export function resolveSessionSoPath(soPath: string, session: SoSessionBinding | undefined): SoPathGate {
  if (!session?.workRoot || !session.apk_sha256) {
    return fail("SO_SESSION_REQUIRED", "so 路径必须绑在当前 APK 会话的 workRoot 与 apk_sha256 上");
  }
  if (typeof soPath !== "string" || soPath.length === 0) {
    return fail("INVALID_SO_PATH", "so 路径为空");
  }
  if (!path.isAbsolute(soPath)) {
    return fail("SO_PATH_RELATIVE", "so 路径必须是绝对路径");
  }
  if (!soPath.endsWith(".so")) {
    return fail("SO_PATH_NOT_SO", "so 路径必须以 .so 结尾");
  }
  if (soPath.split(/[\\/]/).includes("..")) {
    return fail("SO_PATH_ESCAPE", "so 路径含 ..，拒绝离开会话解包树");
  }
  if (!path.isAbsolute(session.workRoot)) {
    return fail("SO_SESSION_REQUIRED", "会话 workRoot 必须是绝对路径");
  }
  let rootReal: string;
  try {
    rootReal = realpathSync(session.workRoot);
  } catch {
    return fail("SO_SESSION_REQUIRED", "会话 workRoot 不存在或无法解析");
  }
  let fileReal: string;
  try {
    fileReal = realpathSync(soPath);
  } catch {
    return fail("SO_PATH_NOT_FOUND", "so 路径不存在或无法解析");
  }
  const rel = path.relative(rootReal, fileReal);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
    return fail("SO_OUTSIDE_SESSION", "so 的真实路径不在当前 APK 会话的 workRoot 内");
  }
  const parts = rel.split(path.sep);
  const abi = parts[1] ?? "";
  const name = parts[2] ?? "";
  const abiOk = /^[A-Za-z0-9][A-Za-z0-9_.+-]*$/.test(abi);
  if (parts.length !== 3 || parts[0] !== "lib" || !abiOk || !name.endsWith(".so")) {
    return fail("SO_OUTSIDE_LIB_ABI", "so 必须位于该会话 workRoot/lib/<abi>/ 下");
  }
  try {
    if (!statSync(fileReal).isFile()) {
      return fail("SO_NOT_REGULAR", "so 路径必须是普通文件");
    }
  } catch {
    return fail("SO_PATH_NOT_FOUND", "so 路径无法读取文件信息");
  }
  return { ok: true, resolved: fileReal };
}
