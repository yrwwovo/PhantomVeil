import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * ReconLab v2 rubric table integration.
 *
 * A rubric row carries the tunable GATES for a vulnerability kind (minimum
 * confidence, which verification checks must be satisfied, which evidence kinds
 * are required, and the allowed reason_code vocabulary). The platform serves the
 * authoritative table at GET /api/rubrics; we mirror its seed in a committed
 * bundle (rubric-defaults.json) so verifications still work fully offline.
 *
 * IMPORTANT: a rubric only tunes the gates. A plugin's intrinsic DETECTION logic
 * (e.g. open-redirect needing an in-site control plus two distinct off-site
 * targets) stays inside the plugin and is never driven from here.
 */

/** Authoritative rubric row shape. The platform uses `rule_id` for `kind`. */
export interface Rubric {
  kind: string;
  title: string;
  category: string;
  enforce: boolean;
  min_confidence: number;
  confirm_checks: string[];
  confirm_evidence_kinds: string[];
  reject_reasons: string[];
  inconclusive_triggers: string[];
  note: string;
}

/** Where a resolved rubric came from, for reporting/telemetry. */
export type RubricSource = "live" | "cache" | "bundled";

export interface RubricProvider {
  /** Resolve a kind's row, or the `default` row. Never throws for unknown kind. */
  getRubric(kind: string): Promise<Rubric>;
  /** Where the most recently resolved rubric came from. */
  readonly source: RubricSource;
}

/**
 * Hard fallback used only if the bundled file is somehow missing a `default`
 * row. Mirrors the platform seed default (enforce:false, min_confidence:50,
 * confirm_checks:["reproduce"]).
 */
export const FALLBACK_DEFAULT: Rubric = {
  kind: "default",
  title: "default",
  category: "default",
  enforce: false,
  min_confidence: 50,
  confirm_checks: ["reproduce"],
  confirm_evidence_kinds: [],
  reject_reasons: [],
  inconclusive_triggers: [],
  note: "built-in fallback default row",
};

function str(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function strArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** Normalize one raw row (accepts `rule_id` or `kind`) into a Rubric. */
export function normalizeRubricRow(raw: unknown): Rubric | null {
  if (!raw || typeof raw !== "object") return null;
  const row = raw as Record<string, unknown>;
  const kind = str(row.kind) || str(row.rule_id);
  if (!kind) return null;
  return {
    kind,
    title: str(row.title),
    category: str(row.category),
    enforce: row.enforce === true,
    min_confidence: typeof row.min_confidence === "number" ? row.min_confidence : 0,
    confirm_checks: strArray(row.confirm_checks),
    confirm_evidence_kinds: strArray(row.confirm_evidence_kinds),
    reject_reasons: strArray(row.reject_reasons),
    inconclusive_triggers: strArray(row.inconclusive_triggers),
    note: str(row.note),
  };
}

/** Index an array (or { rubrics: [...] }) of raw rows by kind. */
export function indexRubricRows(raw: unknown): Map<string, Rubric> {
  const rows: unknown[] = Array.isArray(raw)
    ? raw
    : raw && typeof raw === "object" && Array.isArray((raw as { rubrics?: unknown }).rubrics)
      ? (raw as { rubrics: unknown[] }).rubrics
      : [];
  const index = new Map<string, Rubric>();
  for (const entry of rows) {
    const row = normalizeRubricRow(entry);
    if (row) index.set(row.kind, row);
  }
  return index;
}

function resolveFromIndex(index: Map<string, Rubric>, kind: string): Rubric {
  return index.get(kind) ?? index.get("default") ?? FALLBACK_DEFAULT;
}

function defaultBundlePath(): string {
  return fileURLToPath(new URL("./rubric-defaults.json", import.meta.url));
}

/** Offline provider backed by the committed rubric-defaults.json bundle. */
export class BundledRubricProvider implements RubricProvider {
  source: RubricSource = "bundled";
  private index: Map<string, Rubric> | null = null;
  private readonly filePath: string;

  constructor(filePath: string = defaultBundlePath()) {
    this.filePath = filePath;
  }

  private load(): Map<string, Rubric> {
    if (!this.index) {
      let raw: unknown = [];
      try {
        raw = JSON.parse(readFileSync(this.filePath, "utf8"));
      } catch {
        raw = [];
      }
      this.index = indexRubricRows(raw);
    }
    return this.index;
  }

  async getRubric(kind: string): Promise<Rubric> {
    this.source = "bundled";
    return resolveFromIndex(this.load(), kind);
  }
}

export interface HttpRubricProviderOptions {
  /** Base URL of the ReconLab instance, e.g. "https://reconlab.example". */
  baseUrl: string;
  apiKey?: string;
  /** Cache lifetime before a refetch is attempted. Default 5 minutes. */
  ttlMs?: number;
  /** Injectable fetch (for tests). Defaults to the global fetch. */
  fetchImpl?: typeof fetch;
  /** Fallback provider for when the platform has never been reachable. */
  fallback?: RubricProvider;
  /** Injectable clock (for tests). */
  now?: () => number;
}

/**
 * HTTP-backed provider. Resolution order per getRubric: live fetch (when the
 * cache is stale) -> last good in-memory cache -> bundled default. A fetch
 * failure never propagates: we keep serving the last good cache, else the
 * bundle, so a verification is never crashed by an unreachable platform.
 */
export class HttpRubricProvider implements RubricProvider {
  source: RubricSource = "bundled";
  private cache: Map<string, Rubric> | null = null;
  private cachedAt = 0;
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly ttlMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly fallback: RubricProvider;
  private readonly now: () => number;

  constructor(options: HttpRubricProviderOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/u, "");
    this.apiKey = options.apiKey;
    this.ttlMs = options.ttlMs ?? 5 * 60 * 1000;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.fallback = options.fallback ?? new BundledRubricProvider();
    this.now = options.now ?? Date.now;
  }

  /** Force a refetch on the next getRubric. */
  invalidate(): void {
    this.cache = null;
    this.cachedAt = 0;
  }

  private async fetchAll(): Promise<Map<string, Rubric>> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.apiKey) headers.authorization = "Bearer " + this.apiKey;
    const response = await this.fetchImpl(this.baseUrl + "/api/rubrics", { headers });
    if (!response.ok) {
      throw new Error("rubric fetch failed: HTTP " + response.status);
    }
    const body: unknown = await response.json();
    const index = indexRubricRows(body);
    if (index.size === 0) {
      throw new Error("rubric fetch returned no rows");
    }
    return index;
  }

  private async ensureFresh(): Promise<void> {
    if (this.cache && this.now() - this.cachedAt < this.ttlMs) {
      this.source = "cache";
      return;
    }
    try {
      this.cache = await this.fetchAll();
      this.cachedAt = this.now();
      this.source = "live";
    } catch {
      // Live fetch failed: keep the last good cache if we have one.
      this.source = this.cache ? "cache" : "bundled";
    }
  }

  async getRubric(kind: string): Promise<Rubric> {
    await this.ensureFresh();
    if (this.cache) {
      return resolveFromIndex(this.cache, kind);
    }
    // Never reached the platform and no cache yet: fall back to the bundle.
    const row = await this.fallback.getRubric(kind);
    this.source = "bundled";
    return row;
  }
}

/**
 * Default provider used when no live ReconLab instance is configured (the
 * current offline state). Mirrors the createDefaultVerifierRegistry() convention.
 */
export function createDefaultRubricProvider(): RubricProvider {
  return new BundledRubricProvider();
}
