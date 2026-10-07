import { createHash, randomUUID } from "node:crypto";
import { Buffer } from "node:buffer";

import { HttpRubricProvider, type RubricProvider } from "../../verifiers/rubric-provider.ts";

/**
 * ReconLab v2 contract HTTP client (PhantomVeil side).
 *
 * Thin, typed, one method per contract endpoint. Everything is injectable so the
 * whole thing unit-tests offline: `fetchImpl` (transport), `sleep` + `now`
 * (backoff), `uuid` (Idempotency-Key). Non-2xx responses throw a typed
 * ReconLabError whose `.code` is the stable contract error code (branch on code,
 * never on message). Built-in bounded 429 handling honors Retry-After.
 *
 * Source of truth is openapi.yaml; see the adapter README notes for the two
 * places this client deviates from the step-3 brief to stay faithful to the spec.
 */

export type FetchLike = (url: string, init: unknown) => Promise<unknown>;

export interface ReconLabClientOptions {
  baseUrl: string;
  apiKey: string;
  fetchImpl?: FetchLike;
  /** Injectable sleep for backoff (tests pass a recorder; default real timer). */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable clock in ms (reserved for future jittered backoff). */
  now?: () => number;
  /** Idempotency-Key generator; default randomUUID. */
  uuid?: () => string;
  /** Max 429 retries before giving up. Default 3. */
  maxRateLimitRetries?: number;
  /** Default backoff when a 429 omits Retry-After. Default 1 (second). */
  defaultRetryAfterSeconds?: number;
  contractVersion?: number;
}

export class ReconLabError extends Error {
  readonly status: number;
  readonly code: string;
  readonly data?: Record<string, unknown>;
  readonly retryAfter?: number;

  constructor(args: {
    status: number;
    code: string;
    message: string;
    data?: Record<string, unknown>;
    retryAfter?: number;
  }) {
    super(args.message);
    this.name = "ReconLabError";
    this.status = args.status;
    this.code = args.code;
    this.data = args.data;
    this.retryAfter = args.retryAfter;
  }
}

export interface EvidenceRef {
  id: string;
  sha256: string;
}

export interface QueueItem {
  id: string;
  kind: string;
  state: string;
  title?: string;
  target?: string;
  scope_id?: string;
  endpoint?: string;
  location?: string;
  parameter?: string;
  confidence?: number;
  evidence?: EvidenceRef[];
  reproduction_steps?: string[];
  verdict_note?: string;
  checks?: Array<{ id?: string; state?: string; note?: string }>;
  rev?: number;
  etag?: string;
  lease?: { active?: boolean; holder?: string; expires_at?: string | null };
  created?: string;
  updated?: string;
  [key: string]: unknown;
}

export interface VerdictInput {
  state: string;
  verdict_note?: string;
  reason_code?: string;
  confidence?: number;
  reproduction_steps?: string[];
  evidence?: EvidenceRef[];
  lease_token?: string;
  checks?: Array<{ id?: string; state?: string }>;
  parameter?: string;
  location?: string;
  severity?: string;
  [key: string]: unknown;
}

export interface ClaimResult {
  lease_token: string;
  lease_expires_at?: string;
  lease_seconds?: number;
  item?: QueueItem;
}

interface RawResponse {
  status: number;
  ok: boolean;
  headers: unknown;
  body: unknown;
}

function headerGet(headers: unknown, name: string): string | undefined {
  if (!headers) return undefined;
  const h = headers as { get?: (n: string) => string | null };
  if (typeof h.get === "function") {
    const v = h.get(name);
    return v === null || v === undefined ? undefined : v;
  }
  const obj = headers as Record<string, unknown>;
  const lower = name.toLowerCase();
  for (const key of Object.keys(obj)) {
    if (key.toLowerCase() === lower) {
      const v = obj[key];
      return v === undefined || v === null ? undefined : String(v);
    }
  }
  return undefined;
}

async function readBody(res: unknown): Promise<unknown> {
  const r = res as { text?: () => Promise<string>; json?: () => Promise<unknown> };
  if (typeof r.text === "function") {
    const t = await r.text();
    if (!t) return undefined;
    try {
      return JSON.parse(t);
    } catch {
      return t;
    }
  }
  if (typeof r.json === "function") {
    try {
      return await r.json();
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : undefined;
}

function toBuffer(bytes: Uint8Array | ArrayBuffer | Buffer | string): Buffer {
  if (Buffer.isBuffer(bytes)) return bytes;
  if (typeof bytes === "string") return Buffer.from(bytes, "utf8");
  if (bytes instanceof ArrayBuffer) return Buffer.from(new Uint8Array(bytes));
  return Buffer.from(bytes as Uint8Array);
}

export class ReconLabClient {
  readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly fetchImpl: FetchLike;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly uuid: () => string;
  private readonly maxRateLimitRetries: number;
  private readonly defaultRetryAfterSeconds: number;
  private readonly contractVersion: number;

  constructor(options: ReconLabClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/u, "");
    this.apiKey = options.apiKey;
    this.fetchImpl =
      options.fetchImpl ?? ((url, init) => (fetch as unknown as FetchLike)(url, init));
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.now = options.now ?? Date.now;
    this.uuid = options.uuid ?? randomUUID;
    this.maxRateLimitRetries = options.maxRateLimitRetries ?? 3;
    this.defaultRetryAfterSeconds = options.defaultRetryAfterSeconds ?? 1;
    this.contractVersion = options.contractVersion ?? 2;
  }

  /** Build an HttpRubricProvider that shares this client transport + key. */
  createRubricProvider(ttlMs?: number): RubricProvider {
    return new HttpRubricProvider({
      baseUrl: this.baseUrl,
      apiKey: this.apiKey,
      fetchImpl: this.fetchImpl as unknown as typeof fetch,
      now: this.now,
      ...(ttlMs !== undefined ? { ttlMs } : {}),
    });
  }

  private retryAfterSeconds(res: RawResponse): number {
    const header = headerGet(res.headers, "Retry-After");
    if (header) {
      const parsed = Number.parseInt(header, 10);
      if (Number.isFinite(parsed) && parsed >= 0) return parsed;
    }
    const data = asRecord(asRecord(res.body)?.data);
    const fromData = data?.retry_after;
    if (typeof fromData === "number" && fromData >= 0) return fromData;
    return this.defaultRetryAfterSeconds;
  }

  private makeError(res: RawResponse): ReconLabError {
    const body = asRecord(res.body);
    const code = typeof body?.code === "string" ? body.code : `HTTP_${res.status}`;
    const message = typeof body?.message === "string" ? body.message : `ReconLab HTTP ${res.status}`;
    const data = asRecord(body?.data);
    const retryAfter = res.status === 429 ? this.retryAfterSeconds(res) : undefined;
    return new ReconLabError({ status: res.status, code, message, data, retryAfter });
  }

  private async request(
    method: string,
    path: string,
    opts: {
      query?: Record<string, unknown>;
      headers?: Record<string, string>;
      body?: unknown;
      /** Non-2xx statuses to return instead of throwing (e.g. 304 for conditional GET). */
      acceptStatuses?: number[];
    } = {},
  ): Promise<RawResponse> {
    let url = this.baseUrl + path;
    if (opts.query) {
      const search = new URLSearchParams();
      for (const [key, value] of Object.entries(opts.query)) {
        if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
      }
      const qs = search.toString();
      if (qs) url += `?${qs}`;
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      "X-Contract-Version": String(this.contractVersion),
      Accept: "application/json",
      ...(opts.headers ?? {}),
    };
    const init: Record<string, unknown> = { method, headers };
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }

    for (let attempt = 0; ; attempt += 1) {
      const raw = (await this.fetchImpl(url, init)) as {
        status: number;
        ok?: boolean;
        headers: unknown;
      };
      const body = await readBody(raw);
      const status = raw.status;
      const ok = raw.ok ?? (status >= 200 && status < 300);
      const res: RawResponse = { status, ok, headers: raw.headers, body };

      if (status === 429 && attempt < this.maxRateLimitRetries) {
        await this.sleep(this.retryAfterSeconds(res) * 1000);
        continue;
      }
      const accepted = ok || (opts.acceptStatuses?.includes(status) ?? false);
      if (!accepted) throw this.makeError(res);
      return res;
    }
  }

  // --- verification queue -------------------------------------------------

  async listQueue(params: {
    state?: string;
    kind?: string;
    target?: string;
    scope_id?: string;
    severity?: string;
    since?: string;
    limit?: number;
    cursor?: string;
    sort?: string;
  } = {}): Promise<{
    items: QueueItem[];
    count: number;
    next_cursor: string | null;
    rate_limit?: unknown;
  }> {
    const res = await this.request("GET", "/api/verification/queue", { query: params });
    const body = asRecord(res.body) ?? {};
    return {
      items: (body.items as QueueItem[]) ?? [],
      count: (body.count as number) ?? 0,
      next_cursor: (body.next_cursor as string | null) ?? null,
      rate_limit: body.rate_limit,
    };
  }

  /**
   * Clean read-only preflight for a single queue item (contract v2 addition).
   *
   * Does not require or touch the lease: never advances rev / changes etag. The
   * returned etag is same-source as PATCH's If-Match (read it, write it), taken
   * from the ETag response header with item.etag as fallback. item.lease tells
   * us in one call whether the lease is still ours. With ifNoneMatch set, a 304
   * returns { notModified: true } and an empty body (cheap polling). A superseded
   * record is returned normally (check item.superseded_by), not a 409.
   */
  async getQueueItem(
    id: string,
    opts: { ifNoneMatch?: string } = {},
  ): Promise<{ item?: QueueItem; etag?: string; notModified: boolean }> {
    const res = await this.request("GET", `/api/verification/queue/${encodeURIComponent(id)}`, {
      ...(opts.ifNoneMatch ? { headers: { "If-None-Match": opts.ifNoneMatch } } : {}),
      acceptStatuses: [304],
    });
    if (res.status === 304) {
      return { notModified: true };
    }
    const body = asRecord(res.body) ?? {};
    const item = body.item as QueueItem | undefined;
    const headerEtag = headerGet(res.headers, "ETag");
    const etag = headerEtag ?? (item?.etag as string | undefined);
    return { item, etag, notModified: false };
  }

  async claim(
    id: string,
    args: { worker_id: string; lease_seconds?: number },
  ): Promise<ClaimResult> {
    const res = await this.request("POST", `/api/verification/queue/${encodeURIComponent(id)}/claim`, {
      body: { worker_id: args.worker_id, ...(args.lease_seconds ? { lease_seconds: args.lease_seconds } : {}) },
    });
    const body = asRecord(res.body) ?? {};
    return {
      lease_token: body.lease_token as string,
      lease_expires_at: body.lease_expires_at as string | undefined,
      lease_seconds: body.lease_seconds as number | undefined,
      item: body.item as QueueItem | undefined,
    };
  }

  async heartbeat(
    id: string,
    args: { lease_token: string; lease_seconds?: number },
  ): Promise<unknown> {
    const res = await this.request("POST", `/api/verification/queue/${encodeURIComponent(id)}/heartbeat`, {
      body: { lease_token: args.lease_token, ...(args.lease_seconds ? { lease_seconds: args.lease_seconds } : {}) },
    });
    return res.body;
  }

  async release(id: string, args: { lease_token: string; reason?: string }): Promise<unknown> {
    const res = await this.request("POST", `/api/verification/queue/${encodeURIComponent(id)}/release`, {
      body: { lease_token: args.lease_token, ...(args.reason ? { reason: args.reason } : {}) },
    });
    return res.body;
  }

  async patchVerdict(
    id: string,
    etag: string,
    verdict: VerdictInput,
  ): Promise<{ item?: QueueItem; rubric_warnings?: unknown[]; rubric?: unknown }> {
    const res = await this.request("PATCH", `/api/verification/queue/${encodeURIComponent(id)}`, {
      headers: { "If-Match": etag },
      body: verdict,
    });
    const body = asRecord(res.body) ?? {};
    return {
      item: body.item as QueueItem | undefined,
      rubric_warnings: body.rubric_warnings as unknown[] | undefined,
      rubric: body.rubric,
    };
  }

  async report(
    finding: Record<string, unknown>,
    opts: { idempotencyKey?: string } = {},
  ): Promise<{
    idempotencyKey: string;
    status: number;
    replay: boolean;
    deduplicated: boolean;
    item?: QueueItem;
    rubric_warnings?: unknown[];
  }> {
    const idempotencyKey = opts.idempotencyKey ?? this.uuid();
    const res = await this.request("POST", "/api/verification/queue", {
      headers: { "Idempotency-Key": idempotencyKey },
      body: finding,
    });
    const body = asRecord(res.body) ?? {};
    const replay = (headerGet(res.headers, "Idempotent-Replay") ?? "").toLowerCase() === "true";
    return {
      idempotencyKey,
      status: res.status,
      replay,
      deduplicated: body.deduplicated === true,
      item: body.item as QueueItem | undefined,
      rubric_warnings: body.rubric_warnings as unknown[] | undefined,
    };
  }

  // --- evidence -----------------------------------------------------------

  async uploadEvidence(
    bytes: Uint8Array | ArrayBuffer | Buffer | string,
    opts: { kind?: string; note?: string; content_type?: string; filename?: string } = {},
  ): Promise<{
    id: string;
    sha256: string;
    digest_verified: boolean;
    deduplicated: boolean;
    evidence?: unknown;
  }> {
    const buf = toBuffer(bytes);
    const digest = createHash("sha256").update(buf).digest();
    const hex = digest.toString("hex");
    const base64Digest = digest.toString("base64");
    const res = await this.request("POST", "/api/evidence", {
      headers: {
        "Content-Digest": `sha-256=:${base64Digest}:`,
        "X-Content-SHA256": hex,
      },
      body: {
        content_base64: buf.toString("base64"),
        content_type: opts.content_type ?? "application/octet-stream",
        ...(opts.kind ? { kind: opts.kind } : {}),
        ...(opts.note ? { note: opts.note } : {}),
        ...(opts.filename ? { filename: opts.filename } : {}),
        sha256: hex,
      },
    });
    const body = asRecord(res.body) ?? {};
    const evidence = asRecord(body.evidence) ?? {};
    const digestVerified = body.digest_verified !== false && evidence.digest_verified !== false;
    if (body.digest_verified === false || evidence.digest_verified === false) {
      // Server read-back disagreed with our digest; surface it loudly.
      // eslint-disable-next-line no-console
      console.warn(`ReconLab evidence ${String(evidence.id)} reported digest_verified=false`);
    }
    return {
      id: (evidence.id as string) ?? (body.id as string),
      sha256: (evidence.sha256 as string) ?? hex,
      digest_verified: digestVerified,
      deduplicated: body.deduplicated === true,
      evidence: body.evidence,
    };
  }

  async getEvidence(id: string): Promise<unknown> {
    const res = await this.request("GET", `/api/evidence/${encodeURIComponent(id)}`);
    return res.body;
  }

  async getEvidenceRaw(id: string): Promise<unknown> {
    const res = await this.request("GET", `/api/evidence/${encodeURIComponent(id)}/raw`);
    return res.body;
  }

  // --- scopes -------------------------------------------------------------

  async listScopes(params: { status?: string; limit?: number; cursor?: string } = {}): Promise<unknown> {
    const res = await this.request("GET", "/api/scopes", { query: params });
    return res.body;
  }

  async getScope(id: string): Promise<unknown> {
    const res = await this.request("GET", `/api/scopes/${encodeURIComponent(id)}`);
    return res.body;
  }

  async checkScope(args: {
    url?: string;
    urls?: string[];
    target?: string;
    scope_id?: string;
  }): Promise<{ in_scope: boolean; hop_count?: number; results?: unknown[] }> {
    const res = await this.request("POST", "/api/scope/check", { body: args });
    const body = asRecord(res.body) ?? {};
    return {
      in_scope: body.in_scope !== false,
      hop_count: body.hop_count as number | undefined,
      results: body.results as unknown[] | undefined,
    };
  }

  // --- rubrics / meta -----------------------------------------------------

  async getRubrics(): Promise<unknown> {
    const res = await this.request("GET", "/api/rubrics");
    return res.body;
  }

  async getRubric(kind: string): Promise<unknown> {
    const res = await this.request("GET", `/api/rubrics/${encodeURIComponent(kind)}`);
    return res.body;
  }

  async getContractMeta(): Promise<unknown> {
    const res = await this.request("GET", "/api/contract/meta");
    return res.body;
  }
}
