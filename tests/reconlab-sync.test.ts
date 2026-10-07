import assert from "node:assert/strict";
import test from "node:test";

import { ReconLabClient } from "../src/adapters/reconlab/reconlab-client.ts";
import { verifyFromReconLab } from "../src/adapters/reconlab/reconlab-sync.ts";

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return { status, ok: status >= 200 && status < 300, headers, json: async () => body } as unknown;
}
function errResponse(status: number, code: string, data?: Record<string, unknown>) {
  return jsonResponse(status, { contract_version: 2, status, code, message: code, ...(data ? { data } : {}) });
}
function makeClient(fetchImpl: (url: string, init: any) => Promise<unknown>) {
  return new ReconLabClient({
    baseUrl: "https://reconlab.example",
    apiKey: "rlk_test",
    fetchImpl: fetchImpl as never,
    sleep: async () => {},
    uuid: () => "idem-key",
  });
}

function verifiedStage(outcome: string, judgment: Record<string, unknown> = {}): any {
  return {
    ok: true,
    code: "VERIFIED",
    plugin_id: "stub",
    vulnerability: "Stub",
    outcome,
    judgment: {
      outcome,
      rationale: "verdict rationale",
      reproduction_steps: outcome === "confirmed" ? ["reproduced in isolation"] : [],
      limitations: [],
      evidence_ids: [],
      confidence: 90,
      checks: ["reproduce", "control"],
      ...judgment,
    },
    rubric_source: "live",
    rubric_kind: outcome,
    rubric_exact_match: true,
    warnings: [],
    transitions_applied: [],
    hypothesis: {},
  };
}

const QUEUE = "/api/verification/queue";
const item = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  kind: "open_redirect",
  endpoint: "https://demo.test/go",
  state: "suspected",
  etag: "e1",
  ...extra,
});

test("happy path: suspected -> claim -> verify -> evidence -> fresh etag -> PATCH confirmed", async () => {
  let claimCalls = 0;
  let patchCalls = 0;
  let patchHeaders: any;
  let patchBody: any;
  let evidenceUploaded = false;
  let heartbeatCalled = false;

  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "GET" && url.includes(QUEUE)) {
      return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    }
    if (m === "POST" && url.includes("/Q1/claim")) {
      claimCalls += 1;
      return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { etag: claimCalls >= 2 ? "e2" : "e1" }) });
    }
    if (m === "POST" && url.includes("/Q1/heartbeat")) {
      heartbeatCalled = true;
      return jsonResponse(200, { contract_version: 2 });
    }
    if (m === "POST" && url.includes("/api/evidence")) {
      evidenceUploaded = true;
      return jsonResponse(201, { contract_version: 2, evidence: { id: "EV1", sha256: "sha-ev1" }, digest_verified: true });
    }
    if (m === "PATCH" && url.includes("/Q1")) {
      patchCalls += 1;
      patchHeaders = init.headers;
      patchBody = JSON.parse(init.body);
      return jsonResponse(200, { contract_version: 2, item: { id: "Q1", state: "confirmed" } });
    }
    return errResponse(500, "NO_ROUTE");
  });

  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
    gatherEvidence: async () => [{ content: "control exchange", kind: "http_exchange", filename: "c.txt" }],
  });

  assert.equal(summary.processed, 1);
  const r = summary.results[0];
  assert.equal(r.outcome, "confirmed");
  assert.equal(r.state_written, "confirmed");
  assert.deepEqual(r.evidence_ids, ["EV1"]);
  assert.equal(patchCalls, 1);
  assert.equal(patchHeaders["If-Match"], "e2"); // freshest etag from the re-claim
  assert.equal(patchBody.state, "confirmed");
  assert.equal(patchBody.lease_token, "L1");
  assert.ok(patchBody.evidence.some((e: any) => e.id === "EV1"));
  assert.ok(patchBody.reproduction_steps.length >= 1);
  assert.ok(evidenceUploaded);
  assert.ok(heartbeatCalled);
});

test("412 then success: re-GET new etag, merge, retry PATCH", async () => {
  let claimCalls = 0;
  let patchCalls = 0;
  let finalIfMatch: string | undefined;

  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "GET" && url.includes(QUEUE)) {
      return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    }
    if (m === "POST" && url.includes("/Q1/claim")) {
      claimCalls += 1;
      const etag = claimCalls >= 3 ? "e2" : "e1";
      return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { etag }) });
    }
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH" && url.includes("/Q1")) {
      patchCalls += 1;
      finalIfMatch = init.headers["If-Match"];
      if (finalIfMatch === "e1") return errResponse(412, "PRECONDITION_FAILED", { current_etag: "e2" });
      return jsonResponse(200, { contract_version: 2, item: { id: "Q1", state: "confirmed" } });
    }
    return errResponse(500, "NO_ROUTE");
  });

  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
  });
  const r = summary.results[0];
  assert.equal(r.outcome, "confirmed");
  assert.equal(r.attempts, 2);
  assert.equal(patchCalls, 2);
  assert.equal(finalIfMatch, "e2");
  assert.equal(claimCalls, 3); // initial + pre-write refresh + post-412 refresh
});

test("412 then LEASE_EXPIRED on re-check -> item abandoned, never written", async () => {
  let patchCalls = 0;
  let claimCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "GET" && url.includes(QUEUE)) {
      return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    }
    if (m === "POST" && url.includes("/Q1/claim")) {
      claimCalls += 1;
      return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { etag: "e1" }) });
    }
    if (m === "POST" && url.includes("/Q1/heartbeat")) return errResponse(409, "LEASE_EXPIRED");
    if (m === "PATCH" && url.includes("/Q1")) {
      patchCalls += 1;
      return errResponse(412, "PRECONDITION_FAILED", { current_etag: "e2" });
    }
    return errResponse(500, "NO_ROUTE");
  });

  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
    heartbeatBeforeWrite: false, // isolate the 412 re-check heartbeat
  });
  const r = summary.results[0];
  assert.equal(r.outcome, "lease_lost");
  assert.equal(patchCalls, 1);
  assert.equal(claimCalls, 2); // initial + pre-write refresh, no post-412 refresh
});

test("claim 409 ALREADY_CLAIMED -> item skipped, no write", async () => {
  let patchCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "GET" && url.includes(QUEUE)) {
      return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    }
    if (m === "POST" && url.includes("/Q1/claim")) return errResponse(409, "ALREADY_CLAIMED");
    if (m === "PATCH") {
      patchCalls += 1;
      return jsonResponse(200, { contract_version: 2 });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
  });
  assert.equal(summary.results[0].outcome, "skipped_claimed");
  assert.equal(patchCalls, 0);
});

test("403 SCOPE_EXPIRED mid-flight -> item marked scope_void", async () => {
  let patchCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "GET" && url.includes(QUEUE)) {
      return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    }
    if (m === "POST" && url.includes("/Q1/claim")) {
      return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1") });
    }
    if (m === "POST" && url.includes("/Q1/heartbeat")) return errResponse(403, "SCOPE_EXPIRED");
    if (m === "PATCH") {
      patchCalls += 1;
      return jsonResponse(200, { contract_version: 2 });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
  });
  assert.equal(summary.results[0].outcome, "scope_void");
  assert.equal(patchCalls, 0);
});

test("412 storm beyond the retry cap -> bounded error, loop continues to next item", async () => {
  let q1Patches = 0;
  let q2Confirmed = false;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "GET" && url.includes(QUEUE)) {
      return jsonResponse(200, { contract_version: 2, items: [item("Q1"), item("Q2")], count: 2, next_cursor: null });
    }
    if (m === "POST" && url.includes("/claim")) {
      const id = url.includes("/Q1/") ? "Q1" : "Q2";
      return jsonResponse(200, { contract_version: 2, lease_token: "L", item: item(id, { etag: "e1" }) });
    }
    if (m === "POST" && url.includes("/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "POST" && url.includes("/release")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH" && url.includes("/Q1")) {
      q1Patches += 1;
      return errResponse(412, "PRECONDITION_FAILED", { current_etag: "e1" });
    }
    if (m === "PATCH" && url.includes("/Q2")) {
      q2Confirmed = true;
      return jsonResponse(200, { contract_version: 2, item: { id: "Q2", state: "confirmed" } });
    }
    return errResponse(500, "NO_ROUTE");
  });

  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
    maxPreconditionRetries: 2,
  });
  assert.equal(summary.processed, 2);
  const q1 = summary.results.find((r) => r.id === "Q1")!;
  const q2 = summary.results.find((r) => r.id === "Q2")!;
  assert.equal(q1.outcome, "error");
  assert.equal(q1.detail, "precondition_exhausted");
  assert.equal(q1.attempts, 2);
  assert.equal(q2.outcome, "confirmed");
  assert.ok(q2Confirmed);
  assert.equal(q1Patches, 2);
});

test("rejected verdict writes reason_code and no evidence", async () => {
  let patchBody: any;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "GET" && url.includes(QUEUE)) {
      return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    }
    if (m === "POST" && url.includes("/Q1/claim")) {
      return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1") });
    }
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH" && url.includes("/Q1")) {
      patchBody = JSON.parse(init.body);
      return jsonResponse(200, { contract_version: 2, item: { id: "Q1", state: "rejected" } });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("rejected", { reason_code: "encoded", confidence: 20, checks: ["reproduce"] }),
  });
  const r = summary.results[0];
  assert.equal(r.outcome, "rejected");
  assert.equal(patchBody.state, "rejected");
  assert.equal(patchBody.reason_code, "encoded");
  assert.equal(patchBody.confidence, 20);
  assert.deepEqual(patchBody.evidence, []);
});

test("local RUBRIC_VIOLATION from the stage -> rubric_violation, released, not written", async () => {
  let patchCalls = 0;
  let released = false;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "GET" && url.includes(QUEUE)) {
      return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    }
    if (m === "POST" && url.includes("/Q1/claim")) {
      return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1") });
    }
    if (m === "POST" && url.includes("/Q1/release")) {
      released = true;
      return jsonResponse(200, { contract_version: 2 });
    }
    if (m === "PATCH") {
      patchCalls += 1;
      return jsonResponse(200, { contract_version: 2 });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => ({
      ok: false,
      code: "RUBRIC_VIOLATION",
      reason: "blocked",
      plugin_id: "stub",
      vulnerability: "Stub",
      outcome: "confirmed",
      judgment: {},
      errors: [{ code: "confidence_below_min", rule: "reflected_xss", message: "too low" }],
      rubric_source: "live",
      rubric_kind: "reflected_xss",
      rubric_exact_match: true,
      transitions_applied: [],
      hypothesis: {},
    } as any),
  });
  const r = summary.results[0];
  assert.equal(r.outcome, "rubric_violation");
  assert.ok((r.detail ?? "").includes("confidence_below_min"));
  assert.equal(patchCalls, 0);
  assert.ok(released);
});

test("redirect hop out of scope -> scope_void before verification write", async () => {
  let patchCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "GET" && url.includes(QUEUE)) {
      return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    }
    if (m === "POST" && url.includes("/Q1/claim")) {
      return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1") });
    }
    if (m === "POST" && url.includes("/Q1/release")) return jsonResponse(200, { contract_version: 2 });
    if (m === "POST" && url.includes("/api/scope/check")) return errResponse(403, "OUT_OF_SCOPE");
    if (m === "PATCH") {
      patchCalls += 1;
      return jsonResponse(200, { contract_version: 2 });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
    redirectHops: () => ["https://demo.test/go", "https://evil.test/"],
  });
  assert.equal(summary.results[0].outcome, "scope_void");
  assert.equal(patchCalls, 0);
});
