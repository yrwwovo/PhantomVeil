import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { ReconLabClient, ReconLabError } from "../src/adapters/reconlab/reconlab-client.ts";

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return { status, ok: status >= 200 && status < 300, headers, json: async () => body } as unknown;
}

function makeClient(fetchImpl: (url: string, init: any) => Promise<unknown>, extra: Record<string, unknown> = {}) {
  return new ReconLabClient({
    baseUrl: "https://reconlab.example",
    apiKey: "rlk_test",
    fetchImpl: fetchImpl as never,
    sleep: async () => {},
    uuid: () => "fixed-uuid-0001",
    ...extra,
  });
}

test("every non-2xx maps to its stable ReconLabError.code and status", async () => {
  const cases: Array<[number, string]> = [
    [401, "UNAUTHORIZED"],
    [403, "OUT_OF_SCOPE"],
    [409, "ALREADY_CLAIMED"],
    [409, "LEASE_EXPIRED"],
    [412, "PRECONDITION_FAILED"],
    [428, "PRECONDITION_REQUIRED"],
    [422, "RUBRIC_VIOLATION"],
    [400, "DIGEST_MISMATCH"],
  ];
  for (const [status, code] of cases) {
    const client = makeClient(async () => jsonResponse(status, { contract_version: 2, status, code, message: "x" }));
    await assert.rejects(
      () => client.listQueue(),
      (error: unknown) => {
        assert.ok(error instanceof ReconLabError);
        assert.equal(error.code, code);
        assert.equal(error.status, status);
        return true;
      },
    );
  }
});

test("error data passthrough exposes current_etag on a 412", async () => {
  const client = makeClient(async () =>
    jsonResponse(412, { status: 412, code: "PRECONDITION_FAILED", message: "stale", data: { current_etag: "e9" } }),
  );
  await assert.rejects(
    () => client.patchVerdict("Q1", "e1", { state: "confirmed" }),
    (error: unknown) => {
      assert.ok(error instanceof ReconLabError);
      assert.equal(error.data?.current_etag, "e9");
      return true;
    },
  );
});

test("429 waits per Retry-After then retries and succeeds", async () => {
  const sleeps: number[] = [];
  let calls = 0;
  const client = new ReconLabClient({
    baseUrl: "https://reconlab.example",
    apiKey: "rlk_test",
    sleep: async (ms: number) => {
      sleeps.push(ms);
    },
    fetchImpl: (async () => {
      calls += 1;
      if (calls <= 2) {
        return jsonResponse(429, { status: 429, code: "RATE_LIMITED", message: "slow down" }, { "Retry-After": "3" });
      }
      return jsonResponse(200, { contract_version: 2, items: [], count: 0, next_cursor: null });
    }) as never,
  });
  const result = await client.listQueue();
  assert.equal(result.count, 0);
  assert.equal(calls, 3);
  assert.deepEqual(sleeps, [3000, 3000]);
});

test("429 beyond the retry cap throws RATE_LIMITED with retryAfter", async () => {
  let calls = 0;
  const client = new ReconLabClient({
    baseUrl: "https://reconlab.example",
    apiKey: "rlk_test",
    maxRateLimitRetries: 2,
    sleep: async () => {},
    fetchImpl: (async () => {
      calls += 1;
      return jsonResponse(429, { status: 429, code: "RATE_LIMITED", message: "nope" }, { "Retry-After": "5" });
    }) as never,
  });
  await assert.rejects(
    () => client.listQueue(),
    (error: unknown) => {
      assert.ok(error instanceof ReconLabError);
      assert.equal(error.code, "RATE_LIMITED");
      assert.equal(error.retryAfter, 5);
      return true;
    },
  );
  assert.equal(calls, 3); // initial + 2 retries
});

test("uploadEvidence computes the sha-256 digest and sends Content-Digest", async () => {
  const payload = "control response body";
  const digest = createHash("sha256").update(payload).digest();
  const hex = digest.toString("hex");
  const b64 = digest.toString("base64");
  let seen: any;
  const client = makeClient(async (_url, init) => {
    seen = init;
    return jsonResponse(201, {
      contract_version: 2,
      evidence: { id: "EV-1", sha256: hex },
      digest_verified: true,
      deduplicated: false,
    });
  });
  const up = await client.uploadEvidence(payload, { kind: "http_exchange", note: "control", filename: "c.txt" });
  assert.equal(up.id, "EV-1");
  assert.equal(up.sha256, hex);
  assert.equal(up.digest_verified, true);
  assert.equal(seen.headers["Content-Digest"], `sha-256=:${b64}:`);
  assert.equal(seen.headers["X-Content-SHA256"], hex);
  const body = JSON.parse(seen.body);
  assert.equal(body.sha256, hex);
  assert.equal(body.content_base64, Buffer.from(payload, "utf8").toString("base64"));
  assert.equal(body.kind, "http_exchange");
});

test("uploadEvidence surfaces digest_verified:false from the server", async () => {
  const client = makeClient(async () =>
    jsonResponse(201, {
      contract_version: 2,
      evidence: { id: "EV-2", sha256: "deadbeef" },
      digest_verified: false,
      deduplicated: false,
    }),
  );
  const up = await client.uploadEvidence(Buffer.from("x"), { kind: "http_exchange" });
  assert.equal(up.digest_verified, false);
  assert.equal(up.id, "EV-2");
});

test("report reuses the same Idempotency-Key across a 429 retry", async () => {
  const keys: string[] = [];
  let calls = 0;
  const client = new ReconLabClient({
    baseUrl: "https://reconlab.example",
    apiKey: "rlk_test",
    uuid: () => "stable-key-abc",
    sleep: async () => {},
    fetchImpl: (async (_url: string, init: any) => {
      keys.push(init.headers["Idempotency-Key"]);
      calls += 1;
      if (calls === 1) return jsonResponse(429, { status: 429, code: "RATE_LIMITED", message: "slow" }, { "Retry-After": "1" });
      return jsonResponse(201, { contract_version: 2, item: { id: "Q9" }, deduplicated: false });
    }) as never,
  });
  const rep = await client.report({ kind: "open_redirect", endpoint: "https://demo.test/go" });
  assert.equal(rep.status, 201);
  assert.equal(rep.idempotencyKey, "stable-key-abc");
  assert.deepEqual(keys, ["stable-key-abc", "stable-key-abc"]);
});

test("report honors an explicit Idempotency-Key", async () => {
  let seenKey: string | undefined;
  const client = makeClient(async (_url, init) => {
    seenKey = init.headers["Idempotency-Key"];
    return jsonResponse(201, { contract_version: 2, item: { id: "Q1" } });
  });
  const rep = await client.report({ kind: "open_redirect", endpoint: "https://demo.test/go" }, { idempotencyKey: "my-key-77" });
  assert.equal(seenKey, "my-key-77");
  assert.equal(rep.idempotencyKey, "my-key-77");
});

test("all requests carry Authorization and X-Contract-Version: 2", async () => {
  let seen: any;
  const client = makeClient(async (_url, init) => {
    seen = init;
    return jsonResponse(200, { contract_version: 2, items: [], count: 0, next_cursor: null });
  });
  await client.listQueue({ state: "suspected", kind: "open_redirect", limit: 5 });
  assert.equal(seen.headers.Authorization, "Bearer rlk_test");
  assert.equal(seen.headers["X-Contract-Version"], "2");
});

test("checkScope returns in_scope false mapping and throws 403 as OUT_OF_SCOPE", async () => {
  const okClient = makeClient(async () =>
    jsonResponse(200, { contract_version: 2, in_scope: true, hop_count: 2, results: [] }),
  );
  const ok = await okClient.checkScope({ urls: ["https://a.test", "https://b.test"] });
  assert.equal(ok.in_scope, true);

  const badClient = makeClient(async () =>
    jsonResponse(403, { status: 403, code: "OUT_OF_SCOPE", message: "hop out" }),
  );
  await assert.rejects(
    () => badClient.checkScope({ urls: ["https://evil.test"] }),
    (error: unknown) => error instanceof ReconLabError && error.code === "OUT_OF_SCOPE",
  );
});
