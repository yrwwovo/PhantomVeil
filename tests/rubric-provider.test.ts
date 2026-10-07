import assert from "node:assert/strict";
import test from "node:test";

import {
  BundledRubricProvider,
  HttpRubricProvider,
  createDefaultRubricProvider,
  type Rubric,
} from "../src/verifiers/rubric-provider.ts";

function jsonResponse(rows: unknown) {
  return { ok: true, status: 200, json: async () => rows } as unknown as Response;
}

const liveRows = [
  {
    rule_id: "reflected_xss",
    title: "x",
    category: "c",
    enforce: true,
    min_confidence: 99,
    confirm_checks: ["reproduce"],
    confirm_evidence_kinds: [],
    reject_reasons: [],
    inconclusive_triggers: [],
    note: "",
  },
  {
    rule_id: "default",
    title: "d",
    category: "c",
    enforce: false,
    min_confidence: 50,
    confirm_checks: ["reproduce"],
    confirm_evidence_kinds: [],
    reject_reasons: [],
    inconclusive_triggers: [],
    note: "",
  },
];

test("bundled provider: known kind returns its own row", async () => {
  const provider = createDefaultRubricProvider();
  const r = await provider.getRubric("reflected_xss");
  assert.equal(r.kind, "reflected_xss");
  assert.equal(r.enforce, true);
  assert.equal(r.min_confidence, 60);
  assert.deepEqual(r.confirm_checks, ["reproduce", "control"]);
  assert.deepEqual(r.confirm_evidence_kinds, ["http_exchange"]);
  assert.equal(provider.source, "bundled");
});

test("bundled provider: unknown kind falls back to the default row", async () => {
  const provider = new BundledRubricProvider();
  const r = await provider.getRubric("does_not_exist");
  assert.equal(r.kind, "default");
  assert.equal(r.enforce, false);
  assert.equal(r.min_confidence, 50);
});

test("http provider: serves live rows and caches (no second fetch)", async () => {
  let fetchCount = 0;
  const provider = new HttpRubricProvider({
    baseUrl: "https://reconlab.example/",
    apiKey: "secret-key",
    fetchImpl: async () => {
      fetchCount += 1;
      return jsonResponse(liveRows);
    },
  });
  const r1 = await provider.getRubric("reflected_xss");
  assert.equal(r1.min_confidence, 99);
  assert.equal(provider.source, "live");

  const r2 = await provider.getRubric("default");
  assert.equal(fetchCount, 1); // the cache avoided a second fetch
  assert.equal(provider.source, "cache");
  assert.equal(r2.kind, "default");
});

test("http provider: falls back to the bundled default when the fetch fails", async () => {
  const provider = new HttpRubricProvider({
    baseUrl: "https://reconlab.example",
    fetchImpl: async () => {
      throw new Error("network down");
    },
  });
  const r = await provider.getRubric("reflected_xss");
  assert.equal(r.kind, "reflected_xss");
  assert.equal(r.min_confidence, 60); // from the committed bundle, not a crash
  assert.equal(provider.source, "bundled");
});

test("http provider: keeps serving the last good cache after a later failure", async () => {
  let mode: "ok" | "fail" = "ok";
  const provider = new HttpRubricProvider({
    baseUrl: "https://reconlab.example",
    ttlMs: 0, // force a refetch attempt on every call
    fetchImpl: async () => {
      if (mode === "fail") throw new Error("down");
      return jsonResponse(liveRows);
    },
  });
  const first = await provider.getRubric("reflected_xss");
  assert.equal(first.min_confidence, 99);
  assert.equal(provider.source, "live");

  mode = "fail";
  const second = await provider.getRubric("reflected_xss");
  assert.equal(second.min_confidence, 99); // served from the last good cache
  assert.equal(provider.source, "cache");
});

test("http provider: reads Authorization from the api key", async () => {
  let seenAuth: string | undefined;
  const provider = new HttpRubricProvider({
    baseUrl: "https://reconlab.example",
    apiKey: "abc123",
    fetchImpl: async (_url: unknown, init: unknown) => {
      const headers = (init as { headers?: Record<string, string> }).headers ?? {};
      seenAuth = headers.authorization;
      return jsonResponse(liveRows);
    },
  });
  const r: Rubric = await provider.getRubric("reflected_xss");
  assert.equal(r.min_confidence, 99);
  assert.equal(seenAuth, "Bearer abc123");
});
