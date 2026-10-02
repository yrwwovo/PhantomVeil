import { createHash, randomUUID } from "node:crypto";
import { mkdir, open, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import type { HttpRequestControl } from "../../capabilities/web/restricted-http-get.ts";

const DEFAULT_MAX_REQUESTS = 20;
const MAX_LOCK_ATTEMPTS = 20;
export const TASK_BUDGET_EXHAUSTED = "TASK_REQUEST_BUDGET_EXHAUSTED";
export const TASK_BUDGET_UNAVAILABLE = "TASK_REQUEST_BUDGET_UNAVAILABLE";

interface BudgetState {
  schema_version: 1;
  max_requests: number;
  used_requests: number;
  attempts: { at: string; target_sha256: string }[];
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function validState(value: unknown): value is BudgetState {
  if (!value || typeof value !== "object") return false;
  const state = value as BudgetState;
  return state.schema_version === 1 && Number.isInteger(state.max_requests) &&
    state.max_requests >= 1 && state.max_requests <= 100 &&
    Number.isInteger(state.used_requests) && state.used_requests >= 0 &&
    state.used_requests <= 100 && Array.isArray(state.attempts) &&
    state.attempts.length === state.used_requests && state.attempts.every(item =>
      typeof item?.at === "string" && /^[a-f0-9]{64}$/u.test(item.target_sha256));
}

async function configuredLimit(projectRoot: string): Promise<number> {
  let raw: string;
  try {
    raw = await readFile(path.join(projectRoot, "configs", "request-budget.local.json"), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return DEFAULT_MAX_REQUESTS;
    throw error;
  }
  const parsed: unknown = JSON.parse(raw);
  const value = parsed as { max_requests?: unknown } | null;
  if (!value || Number.isInteger(value.max_requests) !== true ||
      (value.max_requests as number) < 1 || (value.max_requests as number) > 100) {
    throw new Error("invalid request budget configuration");
  }
  return value.max_requests as number;
}

function statePath(projectRoot: string, sessionId: string, stateRoot?: string): string {
  const base = stateRoot ?? process.env.PVEIL_REQUEST_BUDGET_DIR ??
    path.join(process.env.LOCALAPPDATA ?? path.join(homedir(), ".local", "share"),
    "PhantomVeil", "request-budgets");
  return path.join(base, digest(path.resolve(projectRoot)), `${digest(sessionId)}.json`);
}

async function saveState(file: string, state: BudgetState): Promise<void> {
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(state)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporary, file);
  } finally {
    await rm(temporary, { force: true });
  }
}

/** Reserve one request attempt before connection. A failed attempt is not refunded. */
export async function reserveSessionRequest(
  projectRoot: string,
  sessionId: string,
  targetUrl: string,
  stateRoot?: string,
): Promise<{ allowed: boolean; code: string; used_requests?: number; max_requests?: number }> {
  if (typeof sessionId !== "string" || !sessionId.trim()) {
    return { allowed: false, code: TASK_BUDGET_UNAVAILABLE };
  }
  const file = statePath(projectRoot, sessionId, stateRoot);
  const lockFile = `${file}.lock`;
  let lock: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const limit = await configuredLimit(projectRoot);
    await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    for (let attempt = 0; attempt < MAX_LOCK_ATTEMPTS; attempt++) {
      try {
        lock = await open(lockFile, "wx", 0o600);
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        await delay(50);
      }
    }
    if (!lock) return { allowed: false, code: TASK_BUDGET_UNAVAILABLE };
    let state: BudgetState = { schema_version: 1, max_requests: limit, used_requests: 0, attempts: [] };
    try {
      const parsed: unknown = JSON.parse(await readFile(file, "utf8"));
      if (!validState(parsed)) throw new Error("invalid request budget state");
      state = parsed;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const previousLimit = state.max_requests;
    state.max_requests = Math.min(state.max_requests, limit);
    if (state.used_requests >= state.max_requests) {
      if (state.max_requests !== previousLimit) await saveState(file, state);
      return { allowed: false, code: TASK_BUDGET_EXHAUSTED,
        used_requests: state.used_requests, max_requests: state.max_requests };
    }
    state.used_requests++;
    state.attempts.push({ at: new Date().toISOString(), target_sha256: digest(targetUrl) });
    await saveState(file, state);
    return { allowed: true, code: "REQUEST_RESERVED",
      used_requests: state.used_requests, max_requests: state.max_requests };
  } catch {
    return { allowed: false, code: TASK_BUDGET_UNAVAILABLE };
  } finally {
    if (lock) {
      await lock.close();
      await rm(lockFile, { force: true });
    }
  }
}

export function sessionRequestControl(
  projectRoot: string,
  sessionId: string | undefined,
  stateRoot?: string,
): HttpRequestControl {
  return { before_request: async url => {
    const result = await reserveSessionRequest(projectRoot, sessionId ?? "", url, stateRoot);
    return result.allowed ? undefined : result.code;
  } };
}

export async function readSessionRequestBudget(
  projectRoot: string,
  sessionId: string,
  stateRoot?: string,
): Promise<BudgetState | null> {
  try {
    const parsed: unknown = JSON.parse(await readFile(statePath(projectRoot, sessionId, stateRoot), "utf8"));
    return validState(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** Isolated evaluation runs may see the same workspace through different Windows path aliases. */
export async function readIsolatedRunRequestBudget(
  stateRoot: string,
  sessionId: string,
): Promise<BudgetState | null> {
  try {
    const projectKeys = await readdir(stateRoot);
    const matches: BudgetState[] = [];
    for (const key of projectKeys) {
      if (!/^[a-f0-9]{64}$/u.test(key)) continue;
      try {
        const parsed: unknown = JSON.parse(await readFile(
          path.join(stateRoot, key, `${digest(sessionId)}.json`), "utf8"));
        if (validState(parsed)) matches.push(parsed);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    return matches.length === 1 ? matches[0] : null;
  } catch {
    return null;
  }
}
