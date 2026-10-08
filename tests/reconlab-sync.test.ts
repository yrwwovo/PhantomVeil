import assert from "node:assert/strict";
import test from "node:test";

import { ReconLabClient } from "../src/adapters/reconlab/reconlab-client.ts";
import { verifyFromReconLab } from "../src/adapters/reconlab/reconlab-sync.ts";

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return { status, ok: status >= 200 && status < 300, headers, json: async () => body } as unknown;
}
function errResponse(status: number, code: string, data?: Record<string, unknown>, headers: Record<string, string> = {}) {
  return jsonResponse(status, { contract_version: 2, status, code, message: code, ...(data ? { data } : {}) }, headers);
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
// Single-item GET response (ETag header + item.lease) for the pre-write read / chase.
const single = (id: string, etag: string, lease: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
  jsonResponse(200, { contract_version: 2, item: { ...item(id, extra), etag, lease } }, { ETag: etag });
const ours = { active: true, holder: "w1" };

const isGet = (u: string, i: any, id: string) => i.method === "GET" && u.endsWith(`/queue/${id}`);
const isList = (u: string, i: any) => i.method === "GET" && u.includes(QUEUE) && !/\/queue\/[^/?]+$/.test(u) && !/\/queue\/[^/]+\//.test(u);

test("happy path: claim -> verify -> evidence -> clean GET for fresh etag -> PATCH confirmed", async () => {
  let claimCalls = 0;
  let getCalls = 0;
  let patchCalls = 0;
  let patchHeaders: any;
  let patchBody: any;

  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) { getCalls += 1; return single("Q1", "e2", ours); }
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) {
      claimCalls += 1;
      return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { etag: "e1", lease: ours }) });
    }
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "POST" && url.includes("/api/evidence")) return jsonResponse(201, { contract_version: 2, evidence: { id: "EV1", sha256: "sha-ev1" }, digest_verified: true });
    if (m === "PATCH" && url.endsWith("/queue/Q1")) {
      patchCalls += 1; patchHeaders = init.headers; patchBody = JSON.parse(init.body);
      return jsonResponse(200, { contract_version: 2, item: { id: "Q1", state: "confirmed" } });
    }
    return errResponse(500, "NO_ROUTE");
  });

  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
    gatherEvidence: async () => [{ content: "control exchange", kind: "http_exchange", filename: "c.txt" }],
  });

  const r = summary.results[0];
  assert.equal(r.outcome, "confirmed");
  assert.equal(r.state_written, "confirmed");
  assert.deepEqual(r.evidence_ids, ["EV1"]);
  assert.equal(patchCalls, 1);
  assert.equal(patchHeaders["If-Match"], "e2");
  assert.equal(getCalls, 1);
  assert.equal(claimCalls, 1);
  assert.ok(patchBody.evidence.some((e: any) => e.id === "EV1"));
});

test("412 then success: retry uses the 412 response etag directly, NO extra GET", async () => {
  let getCalls = 0;
  let patchCalls = 0;
  let finalIfMatch: string | undefined;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) { getCalls += 1; return single("Q1", "e1", ours); }
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH" && url.endsWith("/queue/Q1")) {
      patchCalls += 1; finalIfMatch = init.headers["If-Match"];
      if (finalIfMatch === "e1") return errResponse(412, "PRECONDITION_FAILED", { current_etag: "e2" }, { ETag: "e2" });
      return jsonResponse(200, { contract_version: 2, item: { id: "Q1", state: "confirmed" } });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  const r = summary.results[0];
  assert.equal(r.outcome, "confirmed");
  assert.equal(r.attempts, 2);
  assert.equal(patchCalls, 2);
  assert.equal(finalIfMatch, "e2");
  assert.equal(getCalls, 1); // ONLY the pre-write read; the 412 branch does not GET
});

test("repeat 412 (second conflict) -> abandoned back to the queue, lease released", async () => {
  let patchCalls = 0;
  let getCalls = 0;
  let released = false;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) { getCalls += 1; return single("Q1", "e1", ours); }
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "POST" && url.includes("/Q1/release")) { released = true; return jsonResponse(200, { contract_version: 2 }); }
    if (m === "PATCH" && url.endsWith("/queue/Q1")) {
      patchCalls += 1;
      return errResponse(412, "PRECONDITION_FAILED", { current_etag: `e${patchCalls + 1}` }, { ETag: `e${patchCalls + 1}` });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  const r = summary.results[0];
  assert.equal(r.outcome, "abandoned");
  assert.equal(r.detail, "precondition_conflict");
  assert.equal(patchCalls, 2); // original + exactly one retry (spec default)
  assert.equal(getCalls, 1); // no GET inside the 412 branch
  assert.ok(released);
});

test("412 retry then 409 LEASE_EXPIRED on the PATCH -> lease_lost, not written", async () => {
  let patchCalls = 0;
  let getCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) { getCalls += 1; return single("Q1", "e1", ours); }
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH" && url.endsWith("/queue/Q1")) {
      patchCalls += 1;
      if (patchCalls === 1) return errResponse(412, "PRECONDITION_FAILED", { current_etag: "e2" }, { ETag: "e2" });
      return errResponse(409, "LEASE_EXPIRED");
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  const r = summary.results[0];
  assert.equal(r.outcome, "lease_lost");
  assert.equal(r.detail, "LEASE_EXPIRED");
  assert.equal(patchCalls, 2);
  assert.equal(getCalls, 1);
});

test("412 retry then 409 ALREADY_SUPERSEDED on the PATCH -> superseded, not written", async () => {
  let patchCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) return single("Q1", "e1", ours);
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH" && url.endsWith("/queue/Q1")) {
      patchCalls += 1;
      if (patchCalls === 1) return errResponse(412, "PRECONDITION_FAILED", { current_etag: "e2" }, { ETag: "e2" });
      return errResponse(409, "ALREADY_SUPERSEDED");
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  const r = summary.results[0];
  assert.equal(r.outcome, "superseded");
  assert.equal(r.detail, "ALREADY_SUPERSEDED");
  assert.equal(patchCalls, 2);
});

test("superseded_by -> chase successor that is terminal/dead -> abandon as superseded, never PATCH", async () => {
  let patchCalls = 0;
  let q2GetCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) return single("Q1", "e1", ours, { superseded_by: "Q2" });
    if (isGet(url, init, "Q2")) { q2GetCalls += 1; return single("Q2", "eQ2", ours, { state: "confirmed" }); }
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH") { patchCalls += 1; return jsonResponse(200, { contract_version: 2 }); }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  const r = summary.results[0];
  assert.equal(r.outcome, "superseded");
  assert.equal(r.detail, "superseded_by:Q2");
  assert.equal(q2GetCalls, 1); // chased the successor
  assert.equal(patchCalls, 0); // never wrote onto the retired record OR the terminal successor
});

test("superseded_by -> successor alive and lease ours -> retarget PATCH onto the successor", async () => {
  let patchUrl: string | undefined;
  let patchIfMatch: string | undefined;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) return single("Q1", "e1", ours, { superseded_by: "Q2" });
    if (isGet(url, init, "Q2")) return single("Q2", "eQ2", ours, { state: "suspected" });
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH") {
      patchUrl = url; patchIfMatch = init.headers["If-Match"];
      return jsonResponse(200, { contract_version: 2, item: { id: "Q2", state: "confirmed" } });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  const r = summary.results[0];
  assert.equal(r.id, "Q1"); // result still keyed by the processed item
  assert.equal(r.outcome, "confirmed");
  assert.ok(patchUrl?.endsWith("/queue/Q2")); // write retargeted onto the live successor
  assert.equal(patchIfMatch, "eQ2");
});

test("superseded_by -> successor GET unavailable -> abandon as superseded (successor_unavailable)", async () => {
  let patchCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) return single("Q1", "e1", ours, { superseded_by: "Q2" });
    if (isGet(url, init, "Q2")) return errResponse(404, "NOT_FOUND");
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH") { patchCalls += 1; return jsonResponse(200, { contract_version: 2 }); }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  const r = summary.results[0];
  assert.equal(r.outcome, "superseded");
  assert.equal(r.detail, "superseded_by:Q2:successor_unavailable");
  assert.equal(patchCalls, 0);
});

test("pre-write clean read shows lease held by another worker -> lease_lost, never written", async () => {
  let patchCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) return single("Q1", "e2", { active: true, holder: "someone-else" });
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH") { patchCalls += 1; return jsonResponse(200, { contract_version: 2 }); }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  assert.equal(summary.results[0].outcome, "lease_lost");
  assert.equal(patchCalls, 0);
});

test("claim 409 ALREADY_CLAIMED -> item skipped, no write", async () => {
  let patchCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return errResponse(409, "ALREADY_CLAIMED");
    if (m === "PATCH") { patchCalls += 1; return jsonResponse(200, { contract_version: 2 }); }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  assert.equal(summary.results[0].outcome, "skipped_claimed");
  assert.equal(patchCalls, 0);
});

test("claim 409 ALREADY_SUPERSEDED / TERMINAL_IMMUTABLE -> superseded at claim, never verified or PATCHed", async () => {
  for (const code of ["ALREADY_SUPERSEDED", "TERMINAL_IMMUTABLE"]) {
    let patchCalls = 0;
    let verifyCalls = 0;
    const client = makeClient(async (url, init) => {
      const m = init.method;
      if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
      if (m === "POST" && url.includes("/Q1/claim")) return errResponse(409, code, { superseded_by: "Q2" });
      if (m === "PATCH") { patchCalls += 1; return jsonResponse(200, { contract_version: 2 }); }
      return errResponse(500, "NO_ROUTE");
    });
    const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
      runVerification: async () => { verifyCalls += 1; return verifiedStage("confirmed"); },
    });
    const r = summary.results[0];
    assert.equal(r.outcome, "superseded", code);
    assert.equal(r.detail, code);
    assert.equal(patchCalls, 0, code); // claim failure terminates the item: no PATCH, no successor write
    assert.equal(verifyCalls, 0, code);
  }
});

test("403 SCOPE_EXPIRED mid-flight (pre-write heartbeat) -> scope_void", async () => {
  let patchCalls = 0;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return errResponse(403, "SCOPE_EXPIRED");
    if (m === "PATCH") { patchCalls += 1; return jsonResponse(200, { contract_version: 2 }); }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
  assert.equal(summary.results[0].outcome, "scope_void");
  assert.equal(patchCalls, 0);
});

test("no cross-item state leak: Q1 abandons, Q2 writes with only its own etag + evidence", async () => {
  let evSeq = 0;
  const q2Patch: { ifMatch?: string; body?: any } = {};
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) return single("Q1", "eA", ours);
    if (isGet(url, init, "Q2")) return single("Q2", "eB", ours);
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1"), item("Q2")], count: 2, next_cursor: null });
    if (m === "POST" && url.includes("/claim")) {
      const id = url.includes("/Q1/") ? "Q1" : "Q2";
      return jsonResponse(200, { contract_version: 2, lease_token: `L-${id}`, item: item(id, { lease: ours }) });
    }
    if (m === "POST" && url.includes("/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "POST" && url.includes("/release")) return jsonResponse(200, { contract_version: 2 });
    if (m === "POST" && url.includes("/api/evidence")) { evSeq += 1; return jsonResponse(201, { contract_version: 2, evidence: { id: `EV${evSeq}`, sha256: `sha${evSeq}` }, digest_verified: true }); }
    if (m === "PATCH" && url.endsWith("/queue/Q1")) {
      // Q1 always conflicts -> abandoned after one retry.
      return errResponse(412, "PRECONDITION_FAILED", { current_etag: "eA2" }, { ETag: "eA2" });
    }
    if (m === "PATCH" && url.endsWith("/queue/Q2")) {
      q2Patch.ifMatch = init.headers["If-Match"];
      q2Patch.body = JSON.parse(init.body);
      return jsonResponse(200, { contract_version: 2, item: { id: "Q2", state: "confirmed" } });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
    gatherEvidence: async (it) => [{ content: `proof-${it.id}`, kind: "http_exchange", filename: `${it.id}.txt` }],
  });
  const q1 = summary.results.find((r) => r.id === "Q1")!;
  const q2 = summary.results.find((r) => r.id === "Q2")!;
  assert.equal(q1.outcome, "abandoned");
  assert.equal(q2.outcome, "confirmed");
  // Q2 wrote with its OWN etag + lease token, and ONLY its own evidence id.
  assert.equal(q2Patch.ifMatch, "eB");
  assert.equal(q2Patch.body.lease_token, "L-Q2");
  const ids = (q2Patch.body.evidence as any[]).map((e) => e.id);
  assert.deepEqual(ids, ["EV2"]); // EV1 belonged to Q1 and must not leak in
  assert.deepEqual(q2.evidence_ids, ["EV2"]);
});

test("rejected verdict writes reason_code and no evidence", async () => {
  let patchBody: any;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (isGet(url, init, "Q1")) return single("Q1", "e1", ours);
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH" && url.endsWith("/queue/Q1")) { patchBody = JSON.parse(init.body); return jsonResponse(200, { contract_version: 2, item: { id: "Q1", state: "rejected" } }); }
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
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/release")) { released = true; return jsonResponse(200, { contract_version: 2 }); }
    if (m === "PATCH") { patchCalls += 1; return jsonResponse(200, { contract_version: 2 }); }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => ({
      ok: false, code: "RUBRIC_VIOLATION", reason: "blocked", plugin_id: "stub", vulnerability: "Stub", outcome: "confirmed",
      judgment: {}, errors: [{ code: "confidence_below_min", rule: "reflected_xss", message: "too low" }],
      rubric_source: "live", rubric_kind: "reflected_xss", rubric_exact_match: true, transitions_applied: [], hypothesis: {},
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
    if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
    if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
    if (m === "POST" && url.includes("/Q1/release")) return jsonResponse(200, { contract_version: 2 });
    if (m === "POST" && url.includes("/api/scope/check")) return errResponse(403, "OUT_OF_SCOPE");
    if (m === "PATCH") { patchCalls += 1; return jsonResponse(200, { contract_version: 2 }); }
    return errResponse(500, "NO_ROUTE");
  });
  const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, {
    runVerification: async () => verifiedStage("confirmed"),
    redirectHops: () => ["https://demo.test/go", "https://evil.test/"],
  });
  assert.equal(summary.results[0].outcome, "scope_void");
  assert.equal(patchCalls, 0);
});

test("409 on the first PATCH (supersede check precedes If-Match) -> superseded, no successor write", async () => {
  for (const code of ["ALREADY_SUPERSEDED", "TERMINAL_IMMUTABLE", "ALREADY_FINAL"]) {
    let patchCalls = 0;
    const patchedPaths: string[] = [];
    const client = makeClient(async (url, init) => {
      const m = init.method;
      // pre-write GET: clean record, lease ours, NO superseded_by.
      if (isGet(url, init, "Q1")) return single("Q1", "e1", ours);
      if (isList(url, init)) return jsonResponse(200, { contract_version: 2, items: [item("Q1")], count: 1, next_cursor: null });
      if (m === "POST" && url.includes("/Q1/claim")) return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: item("Q1", { lease: ours }) });
      if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
      if (m === "PATCH") { patchCalls += 1; patchedPaths.push(url); return errResponse(409, code); }
      return errResponse(500, "NO_ROUTE");
    });
    const summary = await verifyFromReconLab(client, "/tmp", { workerId: "w1" }, { runVerification: async () => verifiedStage("confirmed") });
    const r = summary.results[0];
    assert.equal(r.outcome, "superseded", code);
    assert.equal(r.detail, code);
    assert.equal(patchCalls, 1, code); // direct 409 on the FIRST PATCH; no 412 dance
    assert.ok(patchedPaths.every((p) => p.endsWith("/queue/Q1")), code); // never PATCHed a successor / superseded_by
  }
});
